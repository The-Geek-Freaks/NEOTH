//! Crash recovery for request-bound updater leaf audits.
//!
//! The live authority writes a durable `UpdaterLeafIntent` before polling an
//! effect and a matching `UpdaterLeafResult` after it completes. A process or
//! runtime crash can strand the intent between those acknowledgements. This
//! module scans the canonical instance WAL, rejects ambiguous live histories,
//! and appends one synthetic `interrupted` result for every unpaired intent.
//!
//! Recovery never infers success from external or local state. Stage
//! publication has its own two-phase contract, so an intent without a terminal
//! result is interrupted just like HTTP and process leaves.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::Path;

use anyhow::{Context, Result};
use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use super::authority::{
    RecoveredUpdaterLeafIdentity, RecoveredUpdaterLeafIntent, RecoveredUpdaterLeafResult,
    decode_and_validate_updater_leaf_intent, decode_and_validate_updater_leaf_result,
    synthetic_interrupted_result_payload,
};
use crate::wal::events::{EVENT_TYPE_EXTENDED, ExtendedSubtype};
#[cfg(test)]
use crate::wal::scan::for_each_frame_at_home;
use crate::wal::scan::{
    HomeWalFrontier, HomeWalScanLimits, for_each_frame_in_home_segment_chain_from,
    load_home_hmac_keys,
};
use crate::wal::writer::WalWriterHandle;
use crate::wal::{EventFlags, HeaderBuilder};

const MAX_LIVE_UPDATER_IDENTITIES: usize = 256;
const MAX_UPDATER_AUDIT_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_OPEN_UPDATER_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_CHECKPOINT_BYTES: usize = 3 * 1024 * 1024;
const CHECKPOINT_NAME: &str = "updater-reconcile.frontier";
const CHECKPOINT_SCHEMA_VERSION: u8 = 1;
const CHECKPOINT_HMAC_DOMAIN: &[u8] = b"neoth/updater-reconcile-checkpoint/v1\0";

/// Runtime boundary that requested reconciliation.
#[allow(dead_code)] // Wired by the daemon startup/shutdown slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UpdaterReconcilePhase {
    Startup,
    Shutdown,
}

impl UpdaterReconcilePhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Shutdown => "shutdown",
        }
    }
}

/// Bounded reconciliation result for operator logs and tests.
#[allow(dead_code)] // Wired by the daemon startup/shutdown slice.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct UpdaterReconcileSummary {
    pub scanned_intents: usize,
    pub already_terminal: usize,
    pub interrupted: usize,
}

/// Pair updater leaf intent/result frames across the active canonical segment
/// chain and append one durable synthetic interruption for each orphan.
///
/// The caller must own the daemon's single-instance lock and pass the same
/// direct-child base segment bound to `writer`. Rotations of that namespace are
/// included; unrelated standalone/snapshot WAL namespaces are ignored. A
/// second reconciler could otherwise race between scan and append.
#[allow(dead_code)] // Wired by the daemon startup/shutdown slice.
pub(crate) async fn reconcile_unfinished_updater_leaves(
    neoth_home: &Path,
    segment_path: &Path,
    writer: &WalWriterHandle,
    phase: UpdaterReconcilePhase,
) -> Result<UpdaterReconcileSummary> {
    reconcile_unfinished_updater_leaves_inner(neoth_home, segment_path, writer, phase, true).await
}

async fn reconcile_unfinished_updater_leaves_inner(
    neoth_home: &Path,
    segment_path: &Path,
    writer: &WalWriterHandle,
    phase: UpdaterReconcilePhase,
    append_synthetic_terminals: bool,
) -> Result<UpdaterReconcileSummary> {
    let home = neoth_home.to_path_buf();
    let scan_segment_path = segment_path.to_path_buf();
    let (mut state, mut frontier) = tokio::task::spawn_blocking(move || {
        load_and_scan_updater_checkpoint(&home, &scan_segment_path, MAX_LIVE_UPDATER_IDENTITIES)
    })
    .await
    .context("join updater leaf reconciliation WAL scan")??;

    let mut summary = UpdaterReconcileSummary {
        scanned_intents: state.scanned_intents,
        already_terminal: state.already_terminal,
        interrupted: 0,
    };
    persist_checkpoint_async(neoth_home, segment_path, &frontier, &state)
        .await
        .context("durably checkpoint updater reconciliation before synthetic terminals")?;
    if !append_synthetic_terminals {
        return Ok(summary);
    }

    let unfinished = state.unfinished_intents();
    for intent in unfinished {
        append_interrupted_result(writer, &intent).await?;
        summary.interrupted = summary
            .interrupted
            .checked_add(1)
            .context("updater interruption count overflow")?;
    }
    if summary.interrupted > 0 {
        let home = neoth_home.to_path_buf();
        let scan_segment_path = segment_path.to_path_buf();
        let prior_frontier = frontier.clone();
        let mut moved_state = state;
        (state, frontier) = tokio::task::spawn_blocking(move || {
            let frontier = scan_updater_tail(
                &home,
                &scan_segment_path,
                &mut moved_state,
                Some(&prior_frontier),
                reconciliation_scan_limits(),
            )?;
            Ok::<_, anyhow::Error>((moved_state, frontier))
        })
        .await
        .context("join updater synthetic-terminal acknowledgement scan")??;
        persist_checkpoint_async(neoth_home, segment_path, &frontier, &state)
            .await
            .context("advance updater reconciliation checkpoint after terminal acknowledgement")?;
    }

    tracing::info!(
        phase = phase.as_str(),
        scanned_intents = summary.scanned_intents,
        already_terminal = summary.already_terminal,
        interrupted = summary.interrupted,
        "updater leaf WAL reconciliation complete"
    );
    Ok(summary)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReconcileCheckpointEnvelope {
    schema_version: u8,
    body: ReconcileCheckpointBody,
    hmac_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReconcileCheckpointBody {
    schema_version: u8,
    chain_base_name: String,
    frontier: HomeWalFrontier,
    next_order: u64,
    scanned_intents: u64,
    already_terminal: u64,
    open_intents: Vec<CheckpointOpenIntent>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CheckpointOpenIntent {
    order: u64,
    payload_hex: String,
}

struct OpenLeafAudit {
    intent: RecoveredUpdaterLeafIntent,
    order: usize,
    payload: Vec<u8>,
}

#[cfg(test)]
#[derive(Debug)]
struct ScanResult {
    scanned_intents: usize,
    already_terminal: usize,
    unfinished: Vec<RecoveredUpdaterLeafIntent>,
}

/// Streaming parser state. The bound applies to concurrently live intents,
/// not lifetime WAL cardinality: paired entries are validated and evicted
/// immediately, so years of valid one-at-a-time updates remain scanable. An
/// identity may start a later pair only after its prior exact result; while
/// live, a repeated intent is ambiguous and rejected, and any result without
/// a live intent is rejected.
struct AuditScanState {
    open: HashMap<RecoveredUpdaterLeafIdentity, OpenLeafAudit>,
    open_payload_bytes: usize,
    next_order: usize,
    scanned_intents: usize,
    already_terminal: usize,
    max_live: usize,
}

impl AuditScanState {
    fn new(max_live: usize) -> Result<Self> {
        anyhow::ensure!(max_live > 0, "updater live-identity scan limit is zero");
        Ok(Self {
            open: HashMap::new(),
            open_payload_bytes: 0,
            next_order: 0,
            scanned_intents: 0,
            already_terminal: 0,
            max_live,
        })
    }

    #[cfg(test)]
    fn consume_intent(&mut self, intent: RecoveredUpdaterLeafIntent) -> Result<()> {
        self.consume_validated_intent(intent, Vec::new())
    }

    fn consume_intent_payload(&mut self, payload: Vec<u8>) -> Result<()> {
        anyhow::ensure!(
            !payload.is_empty() && payload.len() <= MAX_UPDATER_AUDIT_PAYLOAD_BYTES,
            "updater intent violates the {}-byte per-record recovery limit",
            MAX_UPDATER_AUDIT_PAYLOAD_BYTES
        );
        let intent = decode_and_validate_updater_leaf_intent(&payload)
            .context("validate exact updater intent payload")?;
        self.consume_validated_intent(intent, payload)
    }

    fn consume_validated_intent(
        &mut self,
        intent: RecoveredUpdaterLeafIntent,
        payload: Vec<u8>,
    ) -> Result<()> {
        anyhow::ensure!(
            payload.len() <= MAX_UPDATER_AUDIT_PAYLOAD_BYTES,
            "updater intent exceeds the {}-byte per-record recovery limit",
            MAX_UPDATER_AUDIT_PAYLOAD_BYTES
        );
        let identity = intent.identity();
        anyhow::ensure!(
            !self.open.contains_key(&identity),
            "duplicate or conflicting live updater intent for operation {:?}, request {:?}",
            identity.operation_id,
            identity.request_id
        );
        anyhow::ensure!(
            self.open.len() < self.max_live,
            "updater WAL scan exceeds the {}-live-identity limit",
            self.max_live
        );
        let open_payload_bytes = self
            .open_payload_bytes
            .checked_add(payload.len())
            .context("updater open-payload byte counter overflow")?;
        anyhow::ensure!(
            open_payload_bytes <= MAX_OPEN_UPDATER_PAYLOAD_BYTES,
            "updater WAL scan exceeds the {}-byte aggregate open-intent limit",
            MAX_OPEN_UPDATER_PAYLOAD_BYTES
        );
        let order = self.next_order;
        self.next_order = self
            .next_order
            .checked_add(1)
            .context("updater WAL intent-order overflow")?;
        self.scanned_intents = self
            .scanned_intents
            .checked_add(1)
            .context("updater WAL intent count overflow")?;
        self.open_payload_bytes = open_payload_bytes;
        self.open.insert(
            identity,
            OpenLeafAudit {
                intent,
                order,
                payload,
            },
        );
        Ok(())
    }

    fn consume_result(&mut self, result: RecoveredUpdaterLeafResult) -> Result<()> {
        let identity = result.identity();
        let open = self.open.remove(&identity).with_context(|| {
            format!(
                "updater result has no prior intent for live operation {:?}, request {:?}",
                identity.operation_id, identity.request_id
            )
        })?;
        result.validate_matches(&open.intent).with_context(|| {
            format!(
                "updater result conflicts with its intent for operation {:?}, request {:?}",
                identity.operation_id, identity.request_id
            )
        })?;
        self.open_payload_bytes = self
            .open_payload_bytes
            .checked_sub(open.payload.len())
            .context("updater open-payload byte counter underflow")?;
        self.already_terminal = self
            .already_terminal
            .checked_add(1)
            .context("updater WAL terminal count overflow")?;
        Ok(())
    }

    fn unfinished_intents(&self) -> Vec<RecoveredUpdaterLeafIntent> {
        let mut intents = self
            .open
            .values()
            .map(|open| (open.order, open.intent.clone()))
            .collect::<Vec<_>>();
        intents.sort_unstable_by_key(|(order, _)| *order);
        intents.into_iter().map(|(_, intent)| intent).collect()
    }

    fn checkpoint_open_intents(&self) -> Result<Vec<CheckpointOpenIntent>> {
        let mut intents = self
            .open
            .values()
            .map(|open| {
                Ok(CheckpointOpenIntent {
                    order: u64::try_from(open.order)
                        .context("updater intent order exceeds checkpoint u64")?,
                    payload_hex: hex::encode(&open.payload),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        intents.sort_unstable_by_key(|intent| intent.order);
        Ok(intents)
    }

    fn from_checkpoint(body: &ReconcileCheckpointBody, max_live: usize) -> Result<Self> {
        anyhow::ensure!(
            body.open_intents.len() <= max_live,
            "updater checkpoint exceeds the {max_live}-live-identity limit"
        );
        let next_order =
            usize::try_from(body.next_order).context("updater checkpoint order exceeds usize")?;
        let scanned_intents = usize::try_from(body.scanned_intents)
            .context("updater checkpoint intent count exceeds usize")?;
        let already_terminal = usize::try_from(body.already_terminal)
            .context("updater checkpoint terminal count exceeds usize")?;
        anyhow::ensure!(
            next_order == scanned_intents,
            "updater checkpoint order/count invariant is invalid"
        );
        anyhow::ensure!(
            already_terminal
                .checked_add(body.open_intents.len())
                .is_some_and(|count| count == scanned_intents),
            "updater checkpoint open/terminal/count invariant is invalid"
        );

        let mut state = Self::new(max_live)?;
        state.next_order = next_order;
        state.scanned_intents = scanned_intents;
        state.already_terminal = already_terminal;
        let mut prior_order = None;
        for encoded in &body.open_intents {
            let order =
                usize::try_from(encoded.order).context("checkpoint intent order exceeds usize")?;
            anyhow::ensure!(
                order < next_order && prior_order.is_none_or(|prior| order > prior),
                "updater checkpoint intent order is invalid"
            );
            let payload = hex::decode(&encoded.payload_hex)
                .context("decode exact updater checkpoint intent payload")?;
            anyhow::ensure!(
                !payload.is_empty() && payload.len() <= MAX_UPDATER_AUDIT_PAYLOAD_BYTES,
                "updater checkpoint intent payload violates its per-record bound"
            );
            let open_payload_bytes = state
                .open_payload_bytes
                .checked_add(payload.len())
                .context("updater checkpoint open-payload byte counter overflow")?;
            anyhow::ensure!(
                open_payload_bytes <= MAX_OPEN_UPDATER_PAYLOAD_BYTES,
                "updater checkpoint exceeds the aggregate open-intent byte limit"
            );
            let intent = decode_and_validate_updater_leaf_intent(&payload)
                .context("validate exact updater checkpoint intent payload")?;
            let identity = intent.identity();
            anyhow::ensure!(
                !state.open.contains_key(&identity),
                "updater checkpoint contains a duplicate live identity"
            );
            state.open.insert(
                identity,
                OpenLeafAudit {
                    intent,
                    order,
                    payload,
                },
            );
            state.open_payload_bytes = open_payload_bytes;
            prior_order = Some(order);
        }
        Ok(state)
    }

    #[cfg(test)]
    fn finish(self) -> ScanResult {
        let mut unfinished = self
            .open
            .into_values()
            .map(|open| (open.order, open.intent))
            .collect::<Vec<_>>();
        unfinished.sort_unstable_by_key(|(order, _)| *order);
        ScanResult {
            scanned_intents: self.scanned_intents,
            already_terminal: self.already_terminal,
            unfinished: unfinished.into_iter().map(|(_, intent)| intent).collect(),
        }
    }
}

#[cfg(test)]
fn scan_unfinished_updater_leaves_with_limit(
    neoth_home: &Path,
    segment_path: &Path,
    max_live: usize,
) -> Result<ScanResult> {
    let mut state = AuditScanState::new(max_live)?;
    scan_updater_tail(
        neoth_home,
        segment_path,
        &mut state,
        None,
        reconciliation_scan_limits(),
    )
    .context("scan canonical WAL for updater leaf audit pairs")?;
    Ok(state.finish())
}

fn load_and_scan_updater_checkpoint(
    neoth_home: &Path,
    segment_path: &Path,
    max_live: usize,
) -> Result<(AuditScanState, HomeWalFrontier)> {
    load_and_scan_updater_checkpoint_with_limits(
        neoth_home,
        segment_path,
        max_live,
        reconciliation_scan_limits(),
    )
}

fn load_and_scan_updater_checkpoint_with_limits(
    neoth_home: &Path,
    segment_path: &Path,
    max_live: usize,
    limits: HomeWalScanLimits,
) -> Result<(AuditScanState, HomeWalFrontier)> {
    match load_checkpoint(neoth_home, segment_path)? {
        Some(body) => {
            let mut state = AuditScanState::from_checkpoint(&body, max_live)?;
            let frontier = scan_updater_tail(
                neoth_home,
                segment_path,
                &mut state,
                Some(&body.frontier),
                limits,
            )
            .context("resume updater recovery from authenticated WAL frontier")?;
            Ok((state, frontier))
        }
        None => {
            let mut state = AuditScanState::new(max_live)?;
            let frontier = scan_updater_tail(neoth_home, segment_path, &mut state, None, limits)
                .context("bootstrap updater recovery from the complete valid WAL quota")?;
            Ok((state, frontier))
        }
    }
}

fn reconciliation_scan_limits() -> HomeWalScanLimits {
    crate::wal::scan::supported_home_scan_limits()
}

#[cfg(test)]
fn reconciliation_scan_limits_for_quota(quota_bytes: u64) -> HomeWalScanLimits {
    crate::wal::scan::home_scan_limits_for_quota(quota_bytes)
}

fn scan_updater_tail(
    neoth_home: &Path,
    segment_path: &Path,
    state: &mut AuditScanState,
    frontier: Option<&HomeWalFrontier>,
    limits: HomeWalScanLimits,
) -> Result<HomeWalFrontier> {
    for_each_frame_in_home_segment_chain_from(
        neoth_home,
        segment_path,
        limits,
        frontier,
        |location, frame| consume_updater_frame(state, location, frame),
    )
    .context("scan selected WAL tail for updater leaf audit pairs")
}

fn consume_updater_frame(
    state: &mut AuditScanState,
    location: &crate::wal::scan::HomeWalFrameLocation,
    frame: &crate::wal::frame::DecodedFrame<'_>,
) -> Result<()> {
    if frame.header.event_type != EVENT_TYPE_EXTENDED {
        return Ok(());
    }
    match ExtendedSubtype::from_u8(frame.header.event_subtype) {
        Some(ExtendedSubtype::UpdaterLeafIntent) => {
            anyhow::ensure!(
                frame.header.flags.is_empty(),
                "updater intent carries forbidden WAL flags {:?}",
                frame.header.flags
            );
            anyhow::ensure!(
                frame.payload.len() <= MAX_UPDATER_AUDIT_PAYLOAD_BYTES,
                "updater intent in WAL segment {:?} exceeds the {}-byte recovery payload limit",
                location.segment_name,
                MAX_UPDATER_AUDIT_PAYLOAD_BYTES
            );
            state
                .consume_intent_payload(frame.payload.to_vec())
                .with_context(|| {
                    format!(
                        "consume updater intent in WAL segment {:?}",
                        location.segment_name
                    )
                })?;
        }
        Some(ExtendedSubtype::UpdaterLeafResult) => {
            anyhow::ensure!(
                frame.payload.len() <= MAX_UPDATER_AUDIT_PAYLOAD_BYTES,
                "updater result in WAL segment {:?} exceeds the {}-byte recovery payload limit",
                location.segment_name,
                MAX_UPDATER_AUDIT_PAYLOAD_BYTES
            );
            let result =
                decode_and_validate_updater_leaf_result(frame.payload).with_context(|| {
                    format!(
                        "validate updater result in WAL segment {:?}",
                        location.segment_name
                    )
                })?;
            if frame.header.flags.is_empty() {
                anyhow::ensure!(
                    !result.is_interrupted_failure(),
                    "interrupted updater result omitted the synthetic WAL flag"
                );
            } else if frame.header.flags == EventFlags::SYNTHETIC {
                anyhow::ensure!(
                    result.is_canonical_interrupted_failure(),
                    "synthetic updater result is not the canonical interrupted terminal"
                );
            } else {
                anyhow::bail!(
                    "updater result carries forbidden WAL flags {:?}",
                    frame.header.flags
                );
            }
            state.consume_result(result).with_context(|| {
                format!(
                    "consume updater result in WAL segment {:?}",
                    location.segment_name
                )
            })?;
        }
        _ => {}
    }
    Ok(())
}

fn load_checkpoint(
    neoth_home: &Path,
    segment_path: &Path,
) -> Result<Option<ReconcileCheckpointBody>> {
    let expected_base_name = segment_path
        .file_name()
        .and_then(OsStr::to_str)
        .context("updater WAL chain base has no UTF-8 file name")?;
    let wal_path = neoth_home.join("wal");
    let root =
        crate::skills::store::open_bound_directory(&wal_path, false, "updater checkpoint root")?
            .with_context(|| {
                format!("updater checkpoint root is missing: {}", wal_path.display())
            })?;
    let name = OsStr::new(CHECKPOINT_NAME);
    match root.dir.symlink_metadata(name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "inspect capability-bound updater checkpoint {}",
                    root.display_path.join(name).display()
                )
            });
        }
        Ok(_) => {}
    }
    let display = root.display_path.join(name);
    let bytes = crate::skills::store::read_regular_file_bounded(
        &root.dir,
        name,
        &display,
        MAX_CHECKPOINT_BYTES,
    )
    .with_context(|| {
        format!(
            "read capability-bound updater checkpoint {}",
            display.display()
        )
    })?;
    let envelope: ReconcileCheckpointEnvelope =
        serde_json::from_slice(&bytes).context("decode updater reconciliation checkpoint")?;
    anyhow::ensure!(
        envelope.schema_version == CHECKPOINT_SCHEMA_VERSION
            && envelope.body.schema_version == CHECKPOINT_SCHEMA_VERSION,
        "unsupported updater reconciliation checkpoint schema"
    );
    anyhow::ensure!(
        envelope.body.chain_base_name == expected_base_name,
        "updater reconciliation checkpoint belongs to a different WAL namespace"
    );
    let tag = decode_checkpoint_tag(&envelope.hmac_sha256)?;
    let body_bytes =
        serde_json::to_vec(&envelope.body).context("canonicalize updater checkpoint body")?;
    let keys = load_home_hmac_keys(neoth_home)
        .context("load active updater checkpoint authentication key")?;
    let active_key = keys.first().context(
        "updater reconciliation checkpoint cannot be authenticated without an active WAL HMAC key",
    )?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(active_key).expect("HMAC-SHA256 accepts any key length");
    mac.update(CHECKPOINT_HMAC_DOMAIN);
    mac.update(&body_bytes);
    anyhow::ensure!(
        mac.verify_slice(&tag).is_ok(),
        "updater reconciliation checkpoint HMAC authentication failed under the active WAL key"
    );
    Ok(Some(envelope.body))
}

async fn persist_checkpoint_async(
    neoth_home: &Path,
    segment_path: &Path,
    frontier: &HomeWalFrontier,
    state: &AuditScanState,
) -> Result<()> {
    let home = neoth_home.to_path_buf();
    let chain_base_name = segment_path
        .file_name()
        .and_then(OsStr::to_str)
        .context("updater WAL chain base has no UTF-8 file name")?
        .to_string();
    let body = ReconcileCheckpointBody {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        chain_base_name,
        frontier: frontier.clone(),
        next_order: u64::try_from(state.next_order)
            .context("updater checkpoint order exceeds u64")?,
        scanned_intents: u64::try_from(state.scanned_intents)
            .context("updater checkpoint intent count exceeds u64")?,
        already_terminal: u64::try_from(state.already_terminal)
            .context("updater checkpoint terminal count exceeds u64")?,
        open_intents: state.checkpoint_open_intents()?,
    };
    tokio::task::spawn_blocking(move || persist_checkpoint_body(&home, body))
        .await
        .context("join updater checkpoint persistence")?
}

fn persist_checkpoint_body(neoth_home: &Path, body: ReconcileCheckpointBody) -> Result<()> {
    let body_bytes = serde_json::to_vec(&body).context("serialize updater checkpoint body")?;
    let keys = load_home_hmac_keys(neoth_home)
        .context("load active updater checkpoint authentication key")?;
    let active_key = keys
        .first()
        .context("updater checkpoint cannot be signed without an active WAL HMAC key")?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(active_key).expect("HMAC-SHA256 accepts any key length");
    mac.update(CHECKPOINT_HMAC_DOMAIN);
    mac.update(&body_bytes);
    let envelope = ReconcileCheckpointEnvelope {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        body,
        hmac_sha256: hex::encode(mac.finalize().into_bytes()),
    };
    let bytes =
        serde_json::to_vec(&envelope).context("serialize updater reconciliation checkpoint")?;
    anyhow::ensure!(
        bytes.len() <= MAX_CHECKPOINT_BYTES,
        "updater reconciliation checkpoint exceeds the {}-byte persistence limit",
        MAX_CHECKPOINT_BYTES
    );

    let wal_path = neoth_home.join("wal");
    let root =
        crate::skills::store::open_bound_directory(&wal_path, false, "updater checkpoint root")?
            .with_context(|| {
                format!("updater checkpoint root is missing: {}", wal_path.display())
            })?;
    let name = OsStr::new(CHECKPOINT_NAME);
    let display = root.display_path.join(name);
    crate::skills::store::atomic_write_private_child(&root.dir, name, &display, &bytes)
        .with_context(|| {
            format!(
                "atomically persist updater checkpoint {}",
                display.display()
            )
        })
}

fn decode_checkpoint_tag(tag: &str) -> Result<[u8; 32]> {
    anyhow::ensure!(
        tag.len() == 64
            && tag
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "updater reconciliation checkpoint has an invalid HMAC encoding"
    );
    let bytes = hex::decode(tag).context("decode updater checkpoint HMAC")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("updater checkpoint HMAC is not 32 bytes"))
}

async fn append_interrupted_result(
    writer: &WalWriterHandle,
    intent: &RecoveredUpdaterLeafIntent,
) -> Result<()> {
    let payload = synthetic_interrupted_result_payload(intent, crate::time::now_unix_secs())?;
    let header = HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
        .event_subtype(ExtendedSubtype::UpdaterLeafResult as u8)
        .flags(EventFlags::SYNTHETIC)
        .build();
    writer
        .append(header, payload)
        .await
        .context("append recovered updater leaf result")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::updater::authority::{
        UpdaterAuthorityComponent, UpdaterAuthorityLane, UpdaterAuthorityTask, UpdaterHttpMethod,
        UpdaterLeafAuthorizer, UpdaterLeafEffect, UpdaterLeafOutcomeCode, UpdaterLeafRequest,
        UpdaterLeafSuccess, UpdaterProgram, serialize_updater_leaf_intent_payload,
    };
    use serde_json::{Value, json};
    use sha2::Digest as _;

    fn http_request(operation: &str, request: &str, path: &str) -> UpdaterLeafRequest {
        UpdaterLeafRequest::http(
            operation,
            request,
            7,
            UpdaterAuthorityTask::NeothSelf,
            UpdaterAuthorityLane::NeothSelfProbe,
            UpdaterAuthorityComponent::Neoth,
            UpdaterLeafEffect::ReleaseMetadataFetch,
            UpdaterHttpMethod::Get,
            &format!("https://api.example.test{path}"),
            &[],
            None,
            128 * 1024,
        )
        .unwrap()
    }

    fn process_request(operation: &str, request: &str) -> UpdaterLeafRequest {
        UpdaterLeafRequest::process(
            operation,
            request,
            7,
            UpdaterAuthorityTask::CliVersions,
            UpdaterAuthorityLane::CliVersionProbe,
            UpdaterAuthorityComponent::ClaudeCli,
            UpdaterLeafEffect::CliInstalledVersionProbe,
            UpdaterProgram::ManagedCli,
            &["--version".to_string()],
            &[],
            64 * 1024,
        )
        .unwrap()
    }

    fn stage_request(operation: &str, request: &str) -> UpdaterLeafRequest {
        let home = std::env::temp_dir().join("neoth-reconcile-authority");
        UpdaterLeafRequest::verified_stage(
            operation,
            request,
            7,
            UpdaterAuthorityTask::NeothSelf,
            UpdaterAuthorityLane::SelfStage,
            UpdaterAuthorityComponent::Neoth,
            UpdaterLeafEffect::VerifiedStageWrite,
            &home,
            &home.join("updates").join("stage"),
            &"33".repeat(32),
            4096,
        )
        .unwrap()
    }

    fn intent_payload(request: &UpdaterLeafRequest) -> Vec<u8> {
        serialize_updater_leaf_intent_payload(request, 1_700_000_000).unwrap()
    }

    fn interrupted_payload(intent_payload: &[u8]) -> Vec<u8> {
        let intent = decode_and_validate_updater_leaf_intent(intent_payload).unwrap();
        synthetic_interrupted_result_payload(&intent, 1_700_000_001).unwrap()
    }

    async fn append_payload(writer: &WalWriterHandle, subtype: ExtendedSubtype, payload: Vec<u8>) {
        append_payload_with_flags(writer, subtype, payload, EventFlags::empty()).await;
    }

    async fn append_payload_with_flags(
        writer: &WalWriterHandle,
        subtype: ExtendedSubtype,
        payload: Vec<u8>,
        flags: EventFlags,
    ) {
        let header = HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
            .event_subtype(subtype as u8)
            .flags(flags)
            .build();
        writer.append(header, payload).await.unwrap();
    }

    fn read_updater_results(home: &Path) -> Vec<Value> {
        let mut results = Vec::new();
        for_each_frame_at_home(home, HomeWalScanLimits::default(), |_, frame| {
            if frame.header.event_type == EVENT_TYPE_EXTENDED
                && frame.header.event_subtype == ExtendedSubtype::UpdaterLeafResult as u8
            {
                results.push(serde_json::from_slice(frame.payload)?);
            }
            Ok(())
        })
        .unwrap();
        results
    }

    fn writer_for_home(
        home: &Path,
    ) -> (
        WalWriterHandle,
        tokio::task::JoinHandle<()>,
        std::path::PathBuf,
    ) {
        let wal = home.join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let segment = wal.join("000001.wal");
        let (writer, join) =
            crate::wal::writer::spawn_for_home(segment.clone(), home.to_path_buf()).unwrap();
        (writer, join, segment)
    }

    async fn rotating_writer_for_home(
        home: &Path,
    ) -> (
        WalWriterHandle,
        tokio::task::JoinHandle<Result<(), String>>,
        std::path::PathBuf,
    ) {
        let wal = home.join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let segment = wal.join("000001.wal");
        let (writer, join, ready) = crate::wal::writer::spawn_for_home_with_policy_ready(
            segment.clone(),
            home.to_path_buf(),
            crate::wal::writer::RotationPolicy {
                max_bytes: 100,
                max_age_ns: crate::wal::writer::RotationPolicy::DEFAULT_MAX_AGE_NS,
            },
        )
        .unwrap();
        ready.wait().await.unwrap();
        (writer, join, segment)
    }

    async fn restart_writer_for_home(
        home: &Path,
        base_segment: &Path,
    ) -> (WalWriterHandle, tokio::task::JoinHandle<Result<(), String>>) {
        let segment = crate::wal::scan::latest_home_segment_in_chain(
            home,
            base_segment,
            HomeWalScanLimits::default(),
        )
        .unwrap();
        let (writer, join, ready) =
            crate::wal::writer::spawn_for_home_ready(segment, home.to_path_buf()).unwrap();
        ready.wait().await.unwrap();
        (writer, join)
    }

    #[tokio::test]
    async fn real_wal_recovery_interrupts_every_target_once() {
        let home = tempfile::tempdir().unwrap();
        let (writer, join, segment) = writer_for_home(home.path());
        for request in [
            http_request("op-http", "req-http", "/releases/latest"),
            process_request("op-process", "req-process"),
            stage_request("op-stage", "req-stage"),
        ] {
            append_payload(
                &writer,
                ExtendedSubtype::UpdaterLeafIntent,
                intent_payload(&request),
            )
            .await;
        }

        let first = reconcile_unfinished_updater_leaves(
            home.path(),
            &segment,
            &writer,
            UpdaterReconcilePhase::Startup,
        )
        .await
        .unwrap();
        assert_eq!(
            first,
            UpdaterReconcileSummary {
                scanned_intents: 3,
                already_terminal: 0,
                interrupted: 3,
            }
        );

        let second = reconcile_unfinished_updater_leaves(
            home.path(),
            &segment,
            &writer,
            UpdaterReconcilePhase::Shutdown,
        )
        .await
        .unwrap();
        assert_eq!(
            second,
            UpdaterReconcileSummary {
                scanned_intents: 3,
                already_terminal: 3,
                interrupted: 0,
            }
        );

        let results = read_updater_results(home.path());
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|result| {
            result["status"] == "failure"
                && result["error_kind"] == "interrupted"
                && result["outcome"].is_null()
        }));

        drop(writer);
        join.await.unwrap();
    }

    #[tokio::test]
    async fn authority_produced_frames_decode_across_the_recovery_boundary() {
        let home = tempfile::tempdir().unwrap();
        let (writer, join, segment) = writer_for_home(home.path());
        let authorizer = UpdaterLeafAuthorizer::for_reconciliation_test(writer.clone(), 7);
        let url = "https://api.example.test/authority-produced";
        authorizer
            .execute_http(
                http_request(
                    "op-authority-produced",
                    "req-authority-produced",
                    "/authority-produced",
                ),
                UpdaterLeafEffect::ReleaseMetadataFetch,
                UpdaterHttpMethod::Get,
                url,
                &[],
                None,
                128 * 1024,
                || async {
                    UpdaterLeafSuccess::new((), UpdaterLeafOutcomeCode::Completed)
                        .with_observed_artifact(&hex::encode(sha2::Sha256::digest([])), 0)
                        .map_err(|error| {
                            crate::updater::authority::UpdaterLeafFailure::new(
                                crate::updater::authority::UpdaterLeafFailureKind::Protocol,
                                error,
                            )
                        })
                },
            )
            .await
            .unwrap();

        let summary = reconcile_unfinished_updater_leaves(
            home.path(),
            &segment,
            &writer,
            UpdaterReconcilePhase::Startup,
        )
        .await
        .unwrap();
        assert_eq!(
            summary,
            UpdaterReconcileSummary {
                scanned_intents: 1,
                already_terminal: 1,
                interrupted: 0,
            }
        );

        drop(authorizer);
        drop(writer);
        join.await.unwrap();
    }

    #[tokio::test]
    async fn exact_segment_recovery_ignores_noncanonical_snapshot_wal_files() {
        let home = tempfile::tempdir().unwrap();
        let (writer, join, segment) = writer_for_home(home.path());
        append_payload(
            &writer,
            ExtendedSubtype::UpdaterLeafIntent,
            intent_payload(&http_request(
                "op-exact-segment",
                "req-exact-segment",
                "/exact-segment",
            )),
        )
        .await;
        std::fs::write(
            home.path().join("wal").join("init-snapshot-0000000001.wal"),
            b"not a canonical runtime WAL segment",
        )
        .unwrap();

        let summary = reconcile_unfinished_updater_leaves(
            home.path(),
            &segment,
            &writer,
            UpdaterReconcilePhase::Startup,
        )
        .await
        .unwrap();
        assert_eq!(
            summary,
            UpdaterReconcileSummary {
                scanned_intents: 1,
                already_terminal: 0,
                interrupted: 1,
            }
        );

        drop(writer);
        join.await.unwrap();
    }

    #[tokio::test]
    async fn rotated_chain_restart_pairs_cross_segment_result_and_recovers_orphan_once() {
        let home = tempfile::tempdir().unwrap();
        let (writer, join, segment) = rotating_writer_for_home(home.path()).await;
        let authorizer = UpdaterLeafAuthorizer::for_reconciliation_test(writer.clone(), 7);
        let url = "https://api.example.test/cross-rotation";
        authorizer
            .execute_http(
                http_request("op-cross-rotation", "req-cross-rotation", "/cross-rotation"),
                UpdaterLeafEffect::ReleaseMetadataFetch,
                UpdaterHttpMethod::Get,
                url,
                &[],
                None,
                128 * 1024,
                || async {
                    UpdaterLeafSuccess::new((), UpdaterLeafOutcomeCode::Completed)
                        .with_observed_artifact(&hex::encode(sha2::Sha256::digest([])), 0)
                        .map_err(|error| {
                            crate::updater::authority::UpdaterLeafFailure::new(
                                crate::updater::authority::UpdaterLeafFailureKind::Protocol,
                                error,
                            )
                        })
                },
            )
            .await
            .unwrap();
        append_payload(
            &writer,
            ExtendedSubtype::UpdaterLeafIntent,
            intent_payload(&http_request(
                "op-rotated-orphan",
                "req-rotated-orphan",
                "/rotated-orphan",
            )),
        )
        .await;
        assert!(home.path().join("wal").join("000002.wal").is_file());
        assert!(home.path().join("wal").join("000003.wal").is_file());
        drop(authorizer);
        drop(writer);
        join.await.unwrap().unwrap();

        let (writer, join) = restart_writer_for_home(home.path(), &segment).await;
        let summary = reconcile_unfinished_updater_leaves(
            home.path(),
            &segment,
            &writer,
            UpdaterReconcilePhase::Startup,
        )
        .await
        .unwrap();
        assert_eq!(
            summary,
            UpdaterReconcileSummary {
                scanned_intents: 2,
                already_terminal: 1,
                interrupted: 1,
            }
        );
        drop(writer);
        join.await.unwrap().unwrap();

        let (writer, join) = restart_writer_for_home(home.path(), &segment).await;
        let second = reconcile_unfinished_updater_leaves(
            home.path(),
            &segment,
            &writer,
            UpdaterReconcilePhase::Startup,
        )
        .await
        .unwrap();
        assert_eq!(
            second,
            UpdaterReconcileSummary {
                scanned_intents: 2,
                already_terminal: 2,
                interrupted: 0,
            }
        );
        drop(writer);
        join.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn marker_covered_updater_tamper_fails_before_checkpoint_or_recovery_append() {
        let home = tempfile::tempdir().unwrap();
        let (writer, join, base_segment) = rotating_writer_for_home(home.path()).await;
        append_payload(
            &writer,
            ExtendedSubtype::UpdaterLeafIntent,
            intent_payload(&http_request(
                "op-marker-tamper",
                "req-marker-tamper",
                "/marker-tamper",
            )),
        )
        .await;
        writer
            .append(
                HeaderBuilder::new(0x01, b"force-rotation").build(),
                b"force-rotation".to_vec(),
            )
            .await
            .unwrap();
        assert!(home.path().join("wal/000002.wal").is_file());
        drop(writer);
        join.await.unwrap().unwrap();

        let (writer, join) = restart_writer_for_home(home.path(), &base_segment).await;
        let predecessor_path = home.path().join("wal/000001.wal");
        let mut predecessor = std::fs::read(&predecessor_path).unwrap();
        let header_len = crate::wal::segment_header::parse_segment_header(&predecessor)
            .unwrap()
            .header_len();
        let mut cursor = header_len;
        let (frame_start, frame_len, reserved_len) = loop {
            let frame = crate::wal::frame::decode_frame(&predecessor[cursor..]).unwrap();
            let frame_len = frame.header.total_len as usize;
            if frame.header.event_type == EVENT_TYPE_EXTENDED
                && frame.header.event_subtype == ExtendedSubtype::UpdaterLeafIntent as u8
            {
                break (cursor, frame_len, frame.header.reserved_len as usize);
            }
            cursor += frame_len;
        };
        let payload_offset = frame_start + 4 + 96 + reserved_len;
        predecessor[payload_offset] ^= 0x01;
        let crc_offset = frame_start + frame_len - 4;
        let crc = crc32c::crc32c(&predecessor[frame_start..crc_offset]);
        predecessor[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());
        crate::wal::frame::decode_frame(&predecessor[frame_start..])
            .expect("tampered updater frame must retain a valid public CRC");
        std::fs::write(&predecessor_path, predecessor).unwrap();

        let error = reconcile_unfinished_updater_leaves(
            home.path(),
            &base_segment,
            &writer,
            UpdaterReconcilePhase::Startup,
        )
        .await
        .expect_err("stale compaction-marker HMAC must stop reconciliation");
        assert!(format!("{error:#}").contains("did not verify"), "{error:#}");
        assert!(
            !home.path().join("wal").join(CHECKPOINT_NAME).exists(),
            "a tampered predecessor must fail before checkpoint publication"
        );

        let mut updater_results = 0usize;
        for entry in std::fs::read_dir(home.path().join("wal")).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(OsStr::to_str) != Some("wal") {
                continue;
            }
            crate::wal::scan::for_each_frame(&std::fs::read(path).unwrap(), |_, frame| {
                if frame.header.event_type == EVENT_TYPE_EXTENDED
                    && frame.header.event_subtype == ExtendedSubtype::UpdaterLeafResult as u8
                {
                    updater_results += 1;
                }
                Ok(())
            })
            .unwrap();
        }
        assert_eq!(
            updater_results, 0,
            "a tampered predecessor must fail before synthetic recovery append"
        );

        drop(writer);
        join.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn crash_after_open_checkpoint_before_synthetic_append_is_idempotent() {
        let home = tempfile::tempdir().unwrap();
        let (writer, join, segment) = writer_for_home(home.path());
        append_payload(
            &writer,
            ExtendedSubtype::UpdaterLeafIntent,
            intent_payload(&http_request(
                "op-checkpoint-crash",
                "req-checkpoint-crash",
                "/checkpoint-crash",
            )),
        )
        .await;

        let before_crash = reconcile_unfinished_updater_leaves_inner(
            home.path(),
            &segment,
            &writer,
            UpdaterReconcilePhase::Startup,
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            before_crash,
            UpdaterReconcileSummary {
                scanned_intents: 1,
                already_terminal: 0,
                interrupted: 0,
            }
        );
        assert!(home.path().join("wal").join(CHECKPOINT_NAME).is_file());
        assert!(read_updater_results(home.path()).is_empty());

        let recovered = reconcile_unfinished_updater_leaves(
            home.path(),
            &segment,
            &writer,
            UpdaterReconcilePhase::Startup,
        )
        .await
        .unwrap();
        assert_eq!(
            recovered,
            UpdaterReconcileSummary {
                scanned_intents: 1,
                already_terminal: 0,
                interrupted: 1,
            }
        );
        let repeated = reconcile_unfinished_updater_leaves(
            home.path(),
            &segment,
            &writer,
            UpdaterReconcilePhase::Shutdown,
        )
        .await
        .unwrap();
        assert_eq!(
            repeated,
            UpdaterReconcileSummary {
                scanned_intents: 1,
                already_terminal: 1,
                interrupted: 0,
            }
        );
        assert_eq!(read_updater_results(home.path()).len(), 1);

        drop(writer);
        join.await.unwrap();
    }

    #[tokio::test]
    async fn crash_after_subset_of_synthetic_results_appends_only_the_missing_terminal() {
        let home = tempfile::tempdir().unwrap();
        let (writer, join, segment) = writer_for_home(home.path());
        let intent_a = intent_payload(&http_request("op-subset-a", "req-subset-a", "/subset-a"));
        let intent_b = intent_payload(&http_request("op-subset-b", "req-subset-b", "/subset-b"));
        for payload in [&intent_a, &intent_b] {
            append_payload(&writer, ExtendedSubtype::UpdaterLeafIntent, payload.clone()).await;
        }
        reconcile_unfinished_updater_leaves_inner(
            home.path(),
            &segment,
            &writer,
            UpdaterReconcilePhase::Startup,
            false,
        )
        .await
        .unwrap();

        append_payload_with_flags(
            &writer,
            ExtendedSubtype::UpdaterLeafResult,
            interrupted_payload(&intent_a),
            EventFlags::SYNTHETIC,
        )
        .await;
        drop(writer);
        join.await.unwrap();

        let (writer, join) = restart_writer_for_home(home.path(), &segment).await;
        let recovered = reconcile_unfinished_updater_leaves(
            home.path(),
            &segment,
            &writer,
            UpdaterReconcilePhase::Startup,
        )
        .await
        .unwrap();
        assert_eq!(
            recovered,
            UpdaterReconcileSummary {
                scanned_intents: 2,
                already_terminal: 1,
                interrupted: 1,
            }
        );
        assert_eq!(read_updater_results(home.path()).len(), 2);
        let repeated = reconcile_unfinished_updater_leaves(
            home.path(),
            &segment,
            &writer,
            UpdaterReconcilePhase::Shutdown,
        )
        .await
        .unwrap();
        assert_eq!(
            repeated,
            UpdaterReconcileSummary {
                scanned_intents: 2,
                already_terminal: 2,
                interrupted: 0,
            }
        );
        assert_eq!(read_updater_results(home.path()).len(), 2);
        drop(writer);
        join.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn authenticated_checkpoint_tail_uses_the_full_quota_bound() {
        assert_eq!(
            reconciliation_scan_limits().max_total_physical_bytes,
            crate::daemon::quota::DEFAULT_CEILING_BYTES
        );
        let home = tempfile::tempdir().unwrap();
        let (writer, join, segment) = writer_for_home(home.path());
        append_payload(
            &writer,
            ExtendedSubtype::UpdaterLeafIntent,
            intent_payload(&http_request(
                "op-quota-tail",
                "req-quota-tail",
                "/quota-tail",
            )),
        )
        .await;
        reconcile_unfinished_updater_leaves_inner(
            home.path(),
            &segment,
            &writer,
            UpdaterReconcilePhase::Startup,
            false,
        )
        .await
        .unwrap();

        for index in 0..8u8 {
            let payload = vec![index; 4096];
            let header = HeaderBuilder::new(0x01, &payload).build();
            writer.append(header, payload).await.unwrap();
        }
        let physical = std::fs::metadata(&segment).unwrap().len();
        let too_small = reconciliation_scan_limits_for_quota(physical - 1);
        let error = load_and_scan_updater_checkpoint_with_limits(
            home.path(),
            &segment,
            MAX_LIVE_UPDATER_IDENTITIES,
            too_small,
        )
        .err()
        .expect("a checkpoint tail above the supplied quota must fail");
        assert!(format!("{error:#}").contains("aggregate physical limit"));

        let quota_valid = reconciliation_scan_limits_for_quota(physical + 1024);
        let (_, frontier) = load_and_scan_updater_checkpoint_with_limits(
            home.path(),
            &segment,
            MAX_LIVE_UPDATER_IDENTITIES,
            quota_valid,
        )
        .expect("checkpoint tail below the effective quota must resume");
        assert_eq!(frontier.segment_name, "000001.wal");

        drop(writer);
        join.await.unwrap();
    }

    #[tokio::test]
    async fn tampered_checkpoint_body_or_mac_fails_closed_before_append() {
        for tamper_mac in [false, true] {
            let home = tempfile::tempdir().unwrap();
            let (writer, join, segment) = writer_for_home(home.path());
            append_payload(
                &writer,
                ExtendedSubtype::UpdaterLeafIntent,
                intent_payload(&http_request(
                    "op-checkpoint-tamper",
                    "req-checkpoint-tamper",
                    "/checkpoint-tamper",
                )),
            )
            .await;
            reconcile_unfinished_updater_leaves_inner(
                home.path(),
                &segment,
                &writer,
                UpdaterReconcilePhase::Startup,
                false,
            )
            .await
            .unwrap();

            let checkpoint_path = home.path().join("wal").join(CHECKPOINT_NAME);
            let mut checkpoint: Value =
                serde_json::from_slice(&std::fs::read(&checkpoint_path).unwrap()).unwrap();
            if tamper_mac {
                checkpoint["hmac_sha256"] = json!("00".repeat(32));
            } else {
                checkpoint["body"]["scanned_intents"] = json!(9);
            }
            std::fs::write(&checkpoint_path, serde_json::to_vec(&checkpoint).unwrap()).unwrap();

            let error = reconcile_unfinished_updater_leaves(
                home.path(),
                &segment,
                &writer,
                UpdaterReconcilePhase::Startup,
            )
            .await
            .unwrap_err();
            assert!(
                format!("{error:#}").contains("checkpoint HMAC authentication failed"),
                "{error:#}"
            );
            assert!(read_updater_results(home.path()).is_empty());
            drop(writer);
            join.await.unwrap();
        }
    }

    #[test]
    fn rotated_archive_key_cannot_authenticate_a_recovery_checkpoint() {
        let home = tempfile::tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        std::fs::write(wal.join("hmac.key"), [0x11u8; 32]).unwrap();
        let body = ReconcileCheckpointBody {
            schema_version: CHECKPOINT_SCHEMA_VERSION,
            chain_base_name: "000001.wal".to_string(),
            frontier: HomeWalFrontier {
                segment_name: "000001.wal".to_string(),
                segment_generation: 0,
                segment_seq: 1,
                segment_start_ts_ns: 1,
                segment_node_id: [0u8; 16],
                next_logical_offset: crate::wal::segment_header::SEGMENT_HEADER_LEN as u64,
            },
            next_order: 0,
            scanned_intents: 0,
            already_terminal: 0,
            open_intents: Vec::new(),
        };
        persist_checkpoint_body(home.path(), body).unwrap();

        std::fs::rename(
            wal.join("hmac.key"),
            wal.join("hmac.key.1700000000.archive"),
        )
        .unwrap();
        std::fs::write(wal.join("hmac.key"), [0x22u8; 32]).unwrap();

        let error = load_checkpoint(home.path(), &wal.join("000001.wal"))
            .expect_err("an archived key must not authorize the active recovery frontier");
        assert!(
            format!("{error:#}").contains("failed under the active WAL key"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn conflicting_live_intent_identity_fails_closed() {
        let home = tempfile::tempdir().unwrap();
        let (writer, join, segment) = writer_for_home(home.path());
        for request in [
            http_request("op-conflict", "req-conflict", "/first"),
            http_request("op-conflict", "req-conflict", "/different"),
        ] {
            append_payload(
                &writer,
                ExtendedSubtype::UpdaterLeafIntent,
                intent_payload(&request),
            )
            .await;
        }

        let error = reconcile_unfinished_updater_leaves(
            home.path(),
            &segment,
            &writer,
            UpdaterReconcilePhase::Startup,
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("duplicate or conflicting live updater intent"));
        assert!(read_updater_results(home.path()).is_empty());

        drop(writer);
        join.await.unwrap();
    }

    #[tokio::test]
    async fn result_without_intent_fails_closed() {
        let home = tempfile::tempdir().unwrap();
        let (writer, join, segment) = writer_for_home(home.path());
        let payload = intent_payload(&http_request(
            "op-result-only",
            "req-result-only",
            "/result-only",
        ));
        append_payload_with_flags(
            &writer,
            ExtendedSubtype::UpdaterLeafResult,
            interrupted_payload(&payload),
            EventFlags::SYNTHETIC,
        )
        .await;

        let error = reconcile_unfinished_updater_leaves(
            home.path(),
            &segment,
            &writer,
            UpdaterReconcilePhase::Startup,
        )
        .await
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("has no prior intent"),
            "{error:#}"
        );

        drop(writer);
        join.await.unwrap();
    }

    #[tokio::test]
    async fn synthetic_flag_is_exactly_bound_to_canonical_interruption() {
        let home = tempfile::tempdir().unwrap();
        let (writer, join, segment) = writer_for_home(home.path());
        let nonsynthetic_intent_payload = intent_payload(&http_request(
            "op-nonsynthetic-interrupted",
            "req-nonsynthetic-interrupted",
            "/nonsynthetic-interrupted",
        ));
        append_payload(
            &writer,
            ExtendedSubtype::UpdaterLeafIntent,
            nonsynthetic_intent_payload.clone(),
        )
        .await;
        append_payload(
            &writer,
            ExtendedSubtype::UpdaterLeafResult,
            interrupted_payload(&nonsynthetic_intent_payload),
        )
        .await;
        let error = reconcile_unfinished_updater_leaves(
            home.path(),
            &segment,
            &writer,
            UpdaterReconcilePhase::Startup,
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("omitted the synthetic WAL flag"));
        drop(writer);
        join.await.unwrap();

        let home = tempfile::tempdir().unwrap();
        let (writer, join, segment) = writer_for_home(home.path());
        let success_intent_payload = intent_payload(&http_request(
            "op-synthetic-success",
            "req-synthetic-success",
            "/synthetic-success",
        ));
        append_payload(
            &writer,
            ExtendedSubtype::UpdaterLeafIntent,
            success_intent_payload.clone(),
        )
        .await;
        let mut success: Value =
            serde_json::from_slice(&interrupted_payload(&success_intent_payload)).unwrap();
        success["status"] = json!("success");
        success["outcome"] = json!("completed");
        success["observed_sha256"] = json!(hex::encode(sha2::Sha256::digest([])));
        success["observed_size_bytes"] = json!(0);
        success["error_kind"] = Value::Null;
        success["error_sha256"] = Value::Null;
        append_payload_with_flags(
            &writer,
            ExtendedSubtype::UpdaterLeafResult,
            serde_json::to_vec(&success).unwrap(),
            EventFlags::SYNTHETIC,
        )
        .await;
        let error = reconcile_unfinished_updater_leaves(
            home.path(),
            &segment,
            &writer,
            UpdaterReconcilePhase::Startup,
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("not the canonical interrupted terminal"));
        drop(writer);
        join.await.unwrap();

        let home = tempfile::tempdir().unwrap();
        let (writer, join, segment) = writer_for_home(home.path());
        let intent_payload = intent_payload(&http_request(
            "op-synthetic-ordinary",
            "req-synthetic-ordinary",
            "/synthetic-ordinary",
        ));
        append_payload(
            &writer,
            ExtendedSubtype::UpdaterLeafIntent,
            intent_payload.clone(),
        )
        .await;
        let mut ordinary: Value =
            serde_json::from_slice(&interrupted_payload(&intent_payload)).unwrap();
        ordinary["error_kind"] = json!("transport");
        append_payload_with_flags(
            &writer,
            ExtendedSubtype::UpdaterLeafResult,
            serde_json::to_vec(&ordinary).unwrap(),
            EventFlags::SYNTHETIC,
        )
        .await;
        let error = reconcile_unfinished_updater_leaves(
            home.path(),
            &segment,
            &writer,
            UpdaterReconcilePhase::Startup,
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("not the canonical interrupted terminal"));
        drop(writer);
        join.await.unwrap();
    }

    #[tokio::test]
    async fn updater_intent_rejects_synthetic_flag() {
        let home = tempfile::tempdir().unwrap();
        let (writer, join, segment) = writer_for_home(home.path());
        append_payload_with_flags(
            &writer,
            ExtendedSubtype::UpdaterLeafIntent,
            intent_payload(&http_request(
                "op-synthetic-intent",
                "req-synthetic-intent",
                "/synthetic-intent",
            )),
            EventFlags::SYNTHETIC,
        )
        .await;
        let error = reconcile_unfinished_updater_leaves(
            home.path(),
            &segment,
            &writer,
            UpdaterReconcilePhase::Startup,
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("intent carries forbidden WAL flags"));
        drop(writer);
        join.await.unwrap();
    }

    #[tokio::test]
    async fn invalid_request_binding_fails_before_recovery_append() {
        let home = tempfile::tempdir().unwrap();
        let (writer, join, segment) = writer_for_home(home.path());
        let mut payload: Value = serde_json::from_slice(&intent_payload(&stage_request(
            "op-invalid-binding",
            "req-invalid-binding",
        )))
        .unwrap();
        payload["request_binding_sha256"] = json!("ff".repeat(32));
        append_payload(
            &writer,
            ExtendedSubtype::UpdaterLeafIntent,
            serde_json::to_vec(&payload).unwrap(),
        )
        .await;

        let error = reconcile_unfinished_updater_leaves(
            home.path(),
            &segment,
            &writer,
            UpdaterReconcilePhase::Startup,
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("request binding does not match"));
        assert!(read_updater_results(home.path()).is_empty());

        drop(writer);
        join.await.unwrap();
    }

    #[tokio::test]
    async fn explicit_live_identity_limit_is_fail_closed() {
        let home = tempfile::tempdir().unwrap();
        let (writer, join, segment) = writer_for_home(home.path());
        for request in [
            http_request("op-limit-1", "req-limit-1", "/one"),
            http_request("op-limit-2", "req-limit-2", "/two"),
        ] {
            append_payload(
                &writer,
                ExtendedSubtype::UpdaterLeafIntent,
                intent_payload(&request),
            )
            .await;
        }

        let error =
            scan_unfinished_updater_leaves_with_limit(home.path(), &segment, 1).unwrap_err();
        assert!(format!("{error:#}").contains("1-live-identity limit"));

        drop(writer);
        join.await.unwrap();
    }

    #[test]
    fn paired_history_beyond_live_limit_stays_bounded() {
        let intent_payload = intent_payload(&http_request("op-history", "req-history", "/history"));
        let result_payload = interrupted_payload(&intent_payload);
        let intent = decode_and_validate_updater_leaf_intent(&intent_payload).unwrap();
        let result = decode_and_validate_updater_leaf_result(&result_payload).unwrap();
        let mut state = AuditScanState::new(1).unwrap();

        for _ in 0..=MAX_LIVE_UPDATER_IDENTITIES {
            state.consume_intent(intent.clone()).unwrap();
            state.consume_result(result.clone()).unwrap();
            assert!(state.open.is_empty());
        }

        let scan = state.finish();
        assert_eq!(scan.scanned_intents, MAX_LIVE_UPDATER_IDENTITIES + 1);
        assert_eq!(scan.already_terminal, MAX_LIVE_UPDATER_IDENTITIES + 1);
        assert!(scan.unfinished.is_empty());
    }

    #[test]
    fn exact_open_intent_payloads_have_strict_record_and_aggregate_bounds() {
        let mut state = AuditScanState::new(MAX_LIVE_UPDATER_IDENTITIES).unwrap();
        let mut oversized =
            intent_payload(&http_request("op-oversized", "req-oversized", "/oversized"));
        oversized.resize(MAX_UPDATER_AUDIT_PAYLOAD_BYTES + 1, b' ');
        let error = state.consume_intent_payload(oversized).unwrap_err();
        assert!(format!("{error:#}").contains("per-record recovery limit"));

        let records_before_overflow =
            MAX_OPEN_UPDATER_PAYLOAD_BYTES / MAX_UPDATER_AUDIT_PAYLOAD_BYTES;
        for index in 0..records_before_overflow {
            let mut payload = intent_payload(&http_request(
                &format!("op-aggregate-{index}"),
                &format!("req-aggregate-{index}"),
                "/aggregate",
            ));
            payload.resize(MAX_UPDATER_AUDIT_PAYLOAD_BYTES, b' ');
            state.consume_intent_payload(payload).unwrap();
        }
        let mut overflow = intent_payload(&http_request(
            "op-aggregate-overflow",
            "req-aggregate-overflow",
            "/aggregate",
        ));
        overflow.resize(MAX_UPDATER_AUDIT_PAYLOAD_BYTES, b' ');
        let error = state.consume_intent_payload(overflow).unwrap_err();
        assert!(format!("{error:#}").contains("aggregate open-intent limit"));
    }

    #[test]
    fn impossible_success_outcome_is_rejected_against_intent() {
        let intent_payload = intent_payload(&http_request("op-outcome", "req-outcome", "/outcome"));
        let mut result: Value =
            serde_json::from_slice(&interrupted_payload(&intent_payload)).unwrap();
        result["status"] = json!("success");
        result["outcome"] = json!("installed");
        result["observed_sha256"] = json!(hex::encode(sha2::Sha256::digest([])));
        result["observed_size_bytes"] = json!(0);
        result["error_kind"] = Value::Null;
        result["error_sha256"] = Value::Null;

        let intent = decode_and_validate_updater_leaf_intent(&intent_payload).unwrap();
        let result =
            decode_and_validate_updater_leaf_result(&serde_json::to_vec(&result).unwrap()).unwrap();
        let mut state = AuditScanState::new(1).unwrap();
        state.consume_intent(intent).unwrap();
        let error = state.consume_result(result).unwrap_err();
        assert!(format!("{error:#}").contains("forbids outcome installed"));
    }
}
