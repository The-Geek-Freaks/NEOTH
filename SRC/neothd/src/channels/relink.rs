//! Converted OpenClaw relink provenance, recovery receipts and traffic gates.
//! The coordinator alone writes credentials/routing and publishes readiness
//! after these receipts prove their exact durable postimages.

use std::ffi::OsStr;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::{collections::BTreeSet, fmt};

use anyhow::{Context, Result, ensure};
use neoth_openclaw_custody::{ConvertedRelinkChannel, SelectedConvertedRelinkAccount};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::registry::{ChannelAccountMode, ChannelId, ChannelRef, channel_descriptors};

pub(crate) const RELINK_INDEX_FILE: &str = "channel_relinks.json";
const RELINK_LOCK_FILE: &str = ".channel-relinks.lock";
const RELINK_SCHEMA_VERSION: u8 = 1;
const RELINK_TRANSACTION_VERSION: u8 = 1;
const MAX_INDEX_BYTES: usize = 64 * 1024;
const MAX_PENDING: usize = 16;
const IMPORT_DOMAIN: &[u8] = b"neoth-converted-relink-pending-v1\0";

static RELINK_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConvertedRelinkKind {
    IMessage,
    GoogleChat,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub(crate) struct PendingRelinkId(String);

impl PendingRelinkId {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RelinkGate {
    Unimported,
    Pending(PendingRelinkId),
    Prepared(PendingRelinkId),
    Ready(PendingRelinkId),
}

/// Capture the exact relink generation a runtime instance is allowed to use.
/// None is reserved for the historical no-index path.  A newly imported target
/// therefore differs from an adapter that was started before import; callers
/// can require a restart/reload instead of allowing that stale adapter to
/// inherit the new authority.
pub(crate) fn traffic_binding_at(home: &Path, destination: &ChannelRef) -> Result<Option<String>> {
    match gate_for_at(home, destination)? {
        RelinkGate::Unimported => Ok(None),
        RelinkGate::Pending(id) | RelinkGate::Prepared(id) => anyhow::bail!(
            "converted {} target is pending relink ({})",
            destination.channel_id.as_str(),
            id.as_str()
        ),
        RelinkGate::Ready(_) => {
            let home_directory = crate::skills::store::open_bound_directory(
                home,
                false,
                "converted relink traffic binding home",
            )?
            .context("converted relink traffic binding home absent")?;
            let path = home_directory.physical_display_path.join(RELINK_INDEX_FILE);
            let (_, index) = read_index(&home_directory.dir, &path)?;
            let entry = index
                .pending
                .iter()
                .find(|entry| &entry.destination == destination)
                .context("ready converted relink disappeared while capturing traffic binding")?;
            ensure!(
                matches!(entry.state, PersistedRelinkState::Ready),
                "converted relink changed while capturing traffic binding"
            );
            Ok(Some(entry.bound_material_sha256.clone().context(
                "ready converted relink has no material binding",
            )?))
        }
    }
}

/// Redacted durable provenance. It intentionally stores neither the OpenClaw
/// account label nor source-file paths, credentials, endpoints, or targets.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingConvertedRelink {
    id: PendingRelinkId,
    kind: ConvertedRelinkKind,
    destination: ChannelRef,
    source_set_sha256: String,
    audited_openclaw_schema_commit: String,
    known_channel_inventory_sha256: String,
    source_account_label_commitment: String,
    #[serde(default)]
    state: PersistedRelinkState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bound_material_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completion_request_material_sha256: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PersistedRelinkState {
    #[default]
    Pending,
    Prepared,
    Ready,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RelinkTransactionPhase {
    Prepared,
    PairCommitted,
    RoutingCommitted,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RelinkTransaction {
    version: u8,
    pending_id: PendingRelinkId,
    destination: ChannelRef,
    target_sha256: String,
    request_material_sha256: String,
    pair_before_sha256: String,
    routing_before_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pair_after_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    routing_after_sha256: Option<String>,
    phase: RelinkTransactionPhase,
}

#[derive(Clone, Debug)]
pub(crate) struct RelinkCompletionToken {
    pending_id: PendingRelinkId,
    destination: ChannelRef,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelinkCompletionStage {
    Prepared,
    PairCommitted,
    RoutingCommitted,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RelinkIndex {
    schema_version: u8,
    pending: Vec<PendingConvertedRelink>,
}

/// Opaque result of the only admitted mutation. No public save/Ready operation
/// exists: later probe/publication code must use a separate transaction API.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BeginPendingOutcome {
    Created(PendingRelinkId),
    AlreadyPending(PendingRelinkId),
}

pub(crate) fn begin_pending_at(
    home: &Path,
    selected: &SelectedConvertedRelinkAccount,
    destination: ChannelRef,
) -> Result<BeginPendingOutcome> {
    let _local = RELINK_MUTEX
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| anyhow::anyhow!("converted relink mutex is poisoned"))?;
    let home_directory =
        crate::skills::store::open_bound_directory(home, false, "converted relink home")?
            .context("converted relink home absent")?;
    let lock_path = home_directory.physical_display_path.join(RELINK_LOCK_FILE);
    let (lock, lock_binding) = crate::skills::store::open_or_create_bound_lockfile(
        &home_directory.dir,
        OsStr::new(RELINK_LOCK_FILE),
        &lock_path,
    )?;
    lock.try_lock()
        .map_err(|error| anyhow::anyhow!("lock converted relink index: {error}"))?;

    let path = home_directory.physical_display_path.join(RELINK_INDEX_FILE);
    let (raw, mut index) = read_index(&home_directory.dir, &path)?;
    let record = pending_from_selected(selected, destination)?;
    if let Some(existing) = index
        .pending
        .iter()
        .find(|entry| entry.destination == record.destination)
    {
        // A retry after the durable coordinator advanced Pending -> Prepared
        // still names the same immutable custody generation. State and the
        // eventual material binding are coordinator-owned, so they are not
        // part of request identity.
        if existing.id == record.id {
            return Ok(BeginPendingOutcome::AlreadyPending(existing.id.clone()));
        }
        anyhow::bail!("converted relink target already has a different live source import");
    }
    ensure!(
        index.pending.len() < MAX_PENDING,
        "converted relink pending index is full"
    );
    index.pending.push(record.clone());
    validate_index(&index)?;
    ensure!(
        lock_binding.matches_regular_file_child_readonly(
            &home_directory.dir,
            OsStr::new(RELINK_LOCK_FILE),
            &lock_path
        )?,
        "converted relink lock changed before commit"
    );
    let (observed_raw, _) = read_index(&home_directory.dir, &path)?;
    ensure!(
        observed_raw == raw,
        "converted relink index changed before CAS commit"
    );
    write_index(&home_directory.dir, &path, &index)?;
    Ok(BeginPendingOutcome::Created(record.id))
}

/// Freeze the semantic candidate before a credential backend can perform an
/// effect (notably a keychain replacement). The index is private provenance;
/// it stores only a digest and never the candidate or service-account bytes.
pub(crate) fn reserve_request_at(
    home: &Path,
    destination: &ChannelRef,
    pending_id: &str,
    request_material: &str,
) -> Result<()> {
    validate_hex(request_material, "converted relink request material")?;
    let _local = RELINK_MUTEX
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| anyhow::anyhow!("converted relink mutex is poisoned"))?;
    let bound = crate::skills::store::open_bound_directory(home, false, "converted relink home")?
        .context("converted relink home absent")?;
    let lock_path = bound.physical_display_path.join(RELINK_LOCK_FILE);
    let (lock, binding) = crate::skills::store::open_or_create_bound_lockfile(
        &bound.dir,
        OsStr::new(RELINK_LOCK_FILE),
        &lock_path,
    )?;
    lock.try_lock()
        .map_err(|error| anyhow::anyhow!("lock converted relink index: {error}"))?;
    let path = bound.physical_display_path.join(RELINK_INDEX_FILE);
    let (raw, mut index) = read_index(&bound.dir, &path)?;
    let entry = index
        .pending
        .iter_mut()
        .find(|entry| &entry.destination == destination)
        .context("converted relink target is not imported")?;
    ensure!(
        entry.id.as_str() == pending_id,
        "converted relink request has a different pending identity"
    );
    match entry.completion_request_material_sha256.as_deref() {
        Some(existing) => ensure!(
            existing == request_material,
            "converted relink request material differs from the reserved candidate"
        ),
        None => entry.completion_request_material_sha256 = Some(request_material.to_owned()),
    }
    validate_index(&index)?;
    ensure!(
        binding.matches_regular_file_child_readonly(
            &bound.dir,
            OsStr::new(RELINK_LOCK_FILE),
            &lock_path
        )?,
        "converted relink lock changed before request reservation"
    );
    let (observed, _) = read_index(&bound.dir, &path)?;
    ensure!(
        observed == raw,
        "converted relink index changed before request reservation CAS"
    );
    write_index(&bound.dir, &path, &index)
}

/// Read-only runtime policy. A missing index leaves legacy scalar channels alone.
pub(crate) fn gate_for_at(home: &Path, destination: &ChannelRef) -> Result<RelinkGate> {
    let Some(home_directory) =
        crate::skills::store::open_bound_directory(home, false, "converted relink read home")?
    else {
        return Ok(RelinkGate::Unimported);
    };
    let path = home_directory.physical_display_path.join(RELINK_INDEX_FILE);
    let (_, index) = read_index(&home_directory.dir, &path)?;
    let Some(entry) = index
        .pending
        .iter()
        .find(|entry| &entry.destination == destination)
    else {
        return Ok(RelinkGate::Unimported);
    };
    match entry.state {
        PersistedRelinkState::Pending => Ok(RelinkGate::Pending(entry.id.clone())),
        PersistedRelinkState::Prepared => Ok(RelinkGate::Prepared(entry.id.clone())),
        PersistedRelinkState::Ready => {
            let expected = entry
                .bound_material_sha256
                .as_deref()
                .context("ready converted relink has no material binding")?;
            ensure!(
                expected == bound_material_commitment(home, destination)?,
                "ready converted relink no longer matches current bound material"
            );
            Ok(RelinkGate::Ready(entry.id.clone()))
        }
    }
}

fn pending_from_selected(
    selected: &SelectedConvertedRelinkAccount,
    destination: ChannelRef,
) -> Result<PendingConvertedRelink> {
    let kind = match selected.channel() {
        ConvertedRelinkChannel::IMessage => ConvertedRelinkKind::IMessage,
        ConvertedRelinkChannel::GoogleChat => ConvertedRelinkKind::GoogleChat,
    };
    let expected = match kind {
        ConvertedRelinkKind::IMessage => ChannelId::IMessageBlueBubbles,
        ConvertedRelinkKind::GoogleChat => ChannelId::GoogleChat,
    };
    ensure!(
        destination.channel_id == expected && destination.account_id.is_default(),
        "converted relink requires the canonical LegacyDefaultOnly destination"
    );
    let descriptor = channel_descriptors()
        .iter()
        .find(|row| row.id == expected)
        .context("converted relink destination absent from registry")?;
    ensure!(
        descriptor.account_mode == ChannelAccountMode::LegacyDefaultOnly,
        "converted relink destination is not LegacyDefaultOnly"
    );
    let source = selected.source_set();
    validate_hex(&source.source_set_sha256, "source set digest")?;
    validate_hex(
        &source.known_channel_inventory_sha256,
        "source inventory digest",
    )?;
    ensure!(
        source.audited_openclaw_schema_commit
            == neoth_openclaw_custody::AUDITED_OPENCLAW_SCHEMA_COMMIT,
        "converted relink source schema pin does not match custody contract"
    );
    ensure!(
        source.known_channel_inventory_sha256
            == neoth_openclaw_custody::canonical_known_channel_inventory_sha256(),
        "converted relink source inventory pin does not match custody contract"
    );
    let label = commitment(
        kind,
        destination.clone(),
        &source.source_set_sha256,
        source.audited_openclaw_schema_commit,
        &source.known_channel_inventory_sha256,
        selected.source_account_label(),
    );
    let id = PendingRelinkId(commitment(
        kind,
        destination.clone(),
        &source.source_set_sha256,
        source.audited_openclaw_schema_commit,
        &source.known_channel_inventory_sha256,
        &label,
    ));
    Ok(PendingConvertedRelink {
        id,
        kind,
        destination,
        source_set_sha256: source.source_set_sha256.clone(),
        audited_openclaw_schema_commit: source.audited_openclaw_schema_commit.to_owned(),
        known_channel_inventory_sha256: source.known_channel_inventory_sha256.clone(),
        source_account_label_commitment: label,
        state: PersistedRelinkState::Pending,
        bound_material_sha256: None,
        completion_request_material_sha256: None,
    })
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Semantic authority material for one converted destination. It deliberately
/// excludes unrelated configuration and the other converted family, so a
/// later Google Chat relink cannot revoke a still-valid iMessage generation.
pub(crate) fn candidate_material_commitment(
    credentials: &crate::config::credentials::Credentials,
    destination: &ChannelRef,
    target: &str,
) -> Result<String> {
    ensure!(
        destination.account_id.is_default() && !target.is_empty(),
        "converted relink material requires a canonical target"
    );
    let mut hash = Sha256::new();
    hash.update(b"neoth-converted-relink-material-v1\0");
    hash.update(destination.channel_id.as_str().as_bytes());
    hash.update([0]);
    hash.update(target.as_bytes());
    hash.update([0]);
    match destination.channel_id {
        ChannelId::IMessageBlueBubbles => {
            for value in [
                credentials
                    .bluebubbles_url
                    .as_deref()
                    .context("iMessage relink lacks BlueBubbles URL")?,
                credentials
                    .bluebubbles_password
                    .as_ref()
                    .context("iMessage relink lacks BlueBubbles password")?
                    .expose(),
                credentials.bluebubbles_chat_guid.as_deref().unwrap_or(""),
                credentials.imessage_allowed_sender.as_deref().unwrap_or(""),
            ] {
                hash.update((value.len() as u64).to_le_bytes());
                hash.update(value.as_bytes());
            }
        }
        ChannelId::GoogleChat => {
            let key = credentials
                .gchat_service_account_json
                .as_deref()
                .context("Google Chat relink lacks service-account file")?;
            let key_path = Path::new(key);
            let parent = key_path
                .parent()
                .context("Google Chat service-account file has no parent")?;
            let name = key_path
                .file_name()
                .context("Google Chat service-account file has no name")?;
            let bound = crate::skills::store::open_bound_directory(
                parent,
                false,
                "Google Chat service-account parent",
            )?
            .context("Google Chat service-account parent absent")?;
            let bytes = crate::skills::store::read_regular_file_bounded(
                &bound.dir,
                name,
                key_path,
                1024 * 1024,
            )
            .context("read Google Chat service-account file")?;
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
            for value in [
                credentials
                    .gchat_subscription
                    .as_deref()
                    .context("Google Chat relink lacks subscription")?,
                credentials.gchat_allowed_sender.as_deref().unwrap_or(""),
            ] {
                hash.update((value.len() as u64).to_le_bytes());
                hash.update(value.as_bytes());
            }
        }
        _ => anyhow::bail!("converted relink material has unsupported destination"),
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn transaction_file_for(destination: &ChannelRef) -> Result<&'static str> {
    match destination.channel_id {
        ChannelId::IMessageBlueBubbles if destination.account_id.is_default() => {
            Ok(".channel-relink-imessage.transaction.json")
        }
        ChannelId::GoogleChat if destination.account_id.is_default() => {
            Ok(".channel-relink-google-chat.transaction.json")
        }
        _ => anyhow::bail!("converted relink transaction has a non-canonical destination"),
    }
}

fn pair_commitment_from_dir(dir: &cap_std::fs::Dir, home: &Path) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(b"neoth-converted-relink-pair-v1\0");
    for name in ["freedom.yaml", "credentials.yaml"] {
        hash.update(name.as_bytes());
        hash.update([0]);
        match dir.symlink_metadata(OsStr::new(name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => hash.update([0]),
            Err(error) => return Err(error.into()),
            Ok(_) => {
                let bytes = crate::skills::store::read_regular_file_bounded(
                    dir,
                    OsStr::new(name),
                    &home.join(name),
                    MAX_INDEX_BYTES,
                )
                .with_context(|| format!("read converted relink pair member {name}"))?;
                hash.update([1]);
                hash.update((bytes.len() as u64).to_le_bytes());
                hash.update(bytes);
            }
        }
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub(crate) fn pair_commitment_at(home: &Path) -> Result<String> {
    let bound =
        crate::skills::store::open_bound_directory(home, false, "converted relink pair home")?
            .context("converted relink pair home absent")?;
    pair_commitment_from_dir(&bound.dir, &bound.physical_display_path)
}

fn read_transaction(
    dir: &cap_std::fs::Dir,
    home: &Path,
    destination: &ChannelRef,
) -> Result<Option<RelinkTransaction>> {
    let name = transaction_file_for(destination)?;
    let path = home.join(name);
    match dir.symlink_metadata(OsStr::new(name)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
        Ok(_) => {
            let bytes = crate::skills::store::read_regular_file_bounded(
                dir,
                OsStr::new(name),
                &path,
                MAX_INDEX_BYTES,
            )?;
            let mut parser = serde_json::Deserializer::from_slice(&bytes);
            let value = NoDuplicateJsonSeed
                .deserialize(&mut parser)
                .context("decode converted relink transaction")?;
            parser
                .end()
                .context("trailing converted relink transaction bytes")?;
            let transaction: RelinkTransaction = serde_json::from_value(value)
                .context("decode converted relink transaction schema")?;
            ensure!(
                transaction.version == RELINK_TRANSACTION_VERSION,
                "unsupported converted relink transaction version"
            );
            validate_hex(&transaction.pending_id.0, "transaction pending id")?;
            validate_hex(&transaction.target_sha256, "transaction target binding")?;
            validate_hex(
                &transaction.request_material_sha256,
                "transaction request material binding",
            )?;
            validate_hex(
                &transaction.pair_before_sha256,
                "transaction pair before binding",
            )?;
            validate_hex(
                &transaction.routing_before_sha256,
                "transaction routing before binding",
            )?;
            if let Some(value) = &transaction.pair_after_sha256 {
                validate_hex(value, "transaction pair after binding")?;
            }
            if let Some(value) = &transaction.routing_after_sha256 {
                validate_hex(value, "transaction routing after binding")?;
            }
            ensure!(
                transaction.destination.account_id.is_default(),
                "transaction has a non-default destination"
            );
            match transaction.phase {
                RelinkTransactionPhase::Prepared => ensure!(
                    transaction.pair_after_sha256.is_some()
                        && transaction.routing_after_sha256.is_some(),
                    "prepared transaction lacks postimage bindings"
                ),
                RelinkTransactionPhase::PairCommitted => ensure!(
                    transaction.pair_after_sha256.is_some()
                        && transaction.routing_after_sha256.is_some(),
                    "pair-committed transaction has invalid postimage bindings"
                ),
                RelinkTransactionPhase::RoutingCommitted => ensure!(
                    transaction.pair_after_sha256.is_some()
                        && transaction.routing_after_sha256.is_some(),
                    "routing-committed transaction lacks postimage bindings"
                ),
            }
            Ok(Some(transaction))
        }
    }
}

fn write_transaction(
    dir: &cap_std::fs::Dir,
    home: &Path,
    transaction: &RelinkTransaction,
) -> Result<()> {
    let name = transaction_file_for(&transaction.destination)?;
    let bytes = serde_json::to_vec(transaction).context("encode converted relink transaction")?;
    ensure!(
        bytes.len() <= MAX_INDEX_BYTES,
        "converted relink transaction exceeds bound"
    );
    crate::skills::store::atomic_write_private_child(
        dir,
        OsStr::new(name),
        &home.join(name),
        &bytes,
    )
}

/// Freeze the exact rendered generation before pair mutation. Recovery accepts
/// only that request and the recorded raw before/after images.
pub(crate) fn prepare_completion_at(
    home: &Path,
    destination: &ChannelRef,
    pending_id: &str,
    target: &str,
    request_material_sha256: &str,
    routing_before: &[u8],
    pair_after_sha256: &str,
    routing_after_sha256: &str,
) -> Result<RelinkCompletionToken> {
    let _local = RELINK_MUTEX
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| anyhow::anyhow!("converted relink mutex is poisoned"))?;
    let bound = crate::skills::store::open_bound_directory(home, false, "converted relink home")?
        .context("converted relink home absent")?;
    let lock_path = bound.physical_display_path.join(RELINK_LOCK_FILE);
    let (lock, binding) = crate::skills::store::open_or_create_bound_lockfile(
        &bound.dir,
        OsStr::new(RELINK_LOCK_FILE),
        &lock_path,
    )?;
    lock.try_lock()
        .map_err(|error| anyhow::anyhow!("lock converted relink index: {error}"))?;
    let index_path = bound.physical_display_path.join(RELINK_INDEX_FILE);
    let (raw, mut index) = read_index(&bound.dir, &index_path)?;
    let entry = index
        .pending
        .iter_mut()
        .find(|entry| &entry.destination == destination)
        .context("converted relink target is not imported")?;
    ensure!(
        entry.id.as_str() == pending_id,
        "converted relink pending identity changed during preparation"
    );
    let target_sha256 = sha256(target.as_bytes());
    validate_hex(request_material_sha256, "request material binding")?;
    ensure!(
        entry.completion_request_material_sha256.as_deref() == Some(request_material_sha256),
        "converted relink request material was not reserved before preparation"
    );
    let routing_before_sha256 = sha256(routing_before);
    let pair_before_sha256 = pair_commitment_from_dir(&bound.dir, &bound.physical_display_path)?;
    validate_hex(pair_after_sha256, "prepared pair postimage binding")?;
    validate_hex(routing_after_sha256, "prepared routing postimage binding")?;
    if let Some(mut transaction) =
        read_transaction(&bound.dir, &bound.physical_display_path, destination)?
    {
        ensure!(
            transaction.pending_id == entry.id
                && transaction.destination == destination.clone()
                && transaction.target_sha256 == target_sha256
                && transaction.request_material_sha256 == request_material_sha256
                && transaction.routing_before_sha256 == routing_before_sha256
                && transaction.routing_after_sha256.as_deref() == Some(routing_after_sha256),
            "different converted relink request is already prepared for this destination"
        );
        let current_route = crate::channels::routing::load_for_converted_relink_at(home)?.0;
        let current_route_sha256 = sha256(&current_route);
        match transaction.phase {
            RelinkTransactionPhase::Prepared
                if transaction.pair_before_sha256 == pair_before_sha256 =>
            {
                // The pair callback may render encrypted credentials with a
                // fresh nonce. Before any pair member changed, replace only
                // that private postimage binding; target, source request and
                // frozen routing postimage stay exact.
                transaction.pair_after_sha256 = Some(pair_after_sha256.to_owned());
                write_transaction(&bound.dir, &bound.physical_display_path, &transaction)?;
            }
            RelinkTransactionPhase::Prepared
                if transaction.pair_after_sha256.as_deref()
                    == Some(pair_before_sha256.as_str()) =>
            {
                transaction.phase = RelinkTransactionPhase::PairCommitted;
                write_transaction(&bound.dir, &bound.physical_display_path, &transaction)?;
            }
            RelinkTransactionPhase::PairCommitted
                if transaction.pair_after_sha256.as_deref()
                    == Some(pair_before_sha256.as_str())
                    && sha256(&current_route) == transaction.routing_before_sha256 => {}
            RelinkTransactionPhase::PairCommitted
                if transaction.pair_after_sha256.as_deref()
                    == Some(pair_before_sha256.as_str())
                    && transaction.routing_after_sha256.as_deref()
                        == Some(current_route_sha256.as_str()) =>
            {
                transaction.phase = RelinkTransactionPhase::RoutingCommitted;
                write_transaction(&bound.dir, &bound.physical_display_path, &transaction)?;
            }
            RelinkTransactionPhase::RoutingCommitted
                if transaction.pair_after_sha256.as_deref()
                    == Some(pair_before_sha256.as_str())
                    && transaction.routing_after_sha256.as_deref()
                        == Some(current_route_sha256.as_str()) => {}
            _ => anyhow::bail!("converted relink recovery receipt does not match durable members"),
        }
        let id = entry.id.clone();
        if matches!(entry.state, PersistedRelinkState::Pending) {
            entry.state = PersistedRelinkState::Prepared;
            validate_index(&index)?;
            write_index(&bound.dir, &index_path, &index)?;
        }
        return Ok(RelinkCompletionToken {
            pending_id: id,
            destination: destination.clone(),
        });
    }
    ensure!(
        matches!(entry.state, PersistedRelinkState::Pending),
        "converted relink is not pending preparation"
    );
    let transaction = RelinkTransaction {
        version: RELINK_TRANSACTION_VERSION,
        pending_id: entry.id.clone(),
        destination: destination.clone(),
        target_sha256,
        request_material_sha256: request_material_sha256.to_owned(),
        pair_before_sha256,
        routing_before_sha256,
        pair_after_sha256: Some(pair_after_sha256.to_owned()),
        routing_after_sha256: Some(routing_after_sha256.to_owned()),
        phase: RelinkTransactionPhase::Prepared,
    };
    write_transaction(&bound.dir, &bound.physical_display_path, &transaction)?;
    entry.state = PersistedRelinkState::Prepared;
    validate_index(&index)?;
    ensure!(
        binding.matches_regular_file_child_readonly(
            &bound.dir,
            OsStr::new(RELINK_LOCK_FILE),
            &lock_path
        )?,
        "converted relink lock changed before preparation publication"
    );
    let (observed, _) = read_index(&bound.dir, &index_path)?;
    ensure!(
        observed == raw,
        "converted relink index changed before preparation CAS"
    );
    write_index(&bound.dir, &index_path, &index)?;
    Ok(RelinkCompletionToken {
        pending_id: transaction.pending_id,
        destination: transaction.destination,
    })
}

/// Reopen only a receipt whose request identity and durable members are still
/// exact. `None` means the pair remains at its frozen before-image, so the
/// caller must use the pair writer's exact-render callback before publishing.
/// A returned token is safe to continue at the recorded durable phase.
pub(crate) fn resume_completion_at(
    home: &Path,
    destination: &ChannelRef,
    pending_id: &str,
    target: &str,
    request_material: &str,
) -> Result<Option<RelinkCompletionToken>> {
    let _local = RELINK_MUTEX
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| anyhow::anyhow!("converted relink mutex is poisoned"))?;
    let bound = crate::skills::store::open_bound_directory(home, false, "converted relink home")?
        .context("converted relink home absent")?;
    let lock_path = bound.physical_display_path.join(RELINK_LOCK_FILE);
    let (lock, binding) = crate::skills::store::open_or_create_bound_lockfile(
        &bound.dir,
        OsStr::new(RELINK_LOCK_FILE),
        &lock_path,
    )?;
    lock.try_lock()
        .map_err(|error| anyhow::anyhow!("lock converted relink index: {error}"))?;
    let Some(mut transaction) =
        read_transaction(&bound.dir, &bound.physical_display_path, destination)?
    else {
        return Ok(None);
    };
    ensure!(
        transaction.destination == *destination
            && transaction.pending_id.as_str() == pending_id
            && transaction.target_sha256 == sha256(target.as_bytes())
            && transaction.request_material_sha256 == request_material,
        "converted relink receipt does not match this request"
    );
    let index_path = bound.physical_display_path.join(RELINK_INDEX_FILE);
    let (index_before, mut index) = read_index(&bound.dir, &index_path)?;
    let entry = index
        .pending
        .iter_mut()
        .find(|entry| &entry.destination == destination)
        .context("converted relink recovery target is absent")?;
    ensure!(
        entry.id == transaction.pending_id
            && entry.completion_request_material_sha256.as_deref() == Some(request_material),
        "converted relink recovery index differs from reserved receipt"
    );
    ensure!(
        !matches!(entry.state, PersistedRelinkState::Ready),
        "converted relink recovery cannot replace Ready"
    );
    entry.state = PersistedRelinkState::Prepared;
    let pair = pair_commitment_from_dir(&bound.dir, &bound.physical_display_path)?;
    let route = crate::channels::routing::load_for_converted_relink_at(home)?.0;
    let route_sha = sha256(&route);
    if matches!(transaction.phase, RelinkTransactionPhase::Prepared)
        && pair == transaction.pair_before_sha256
    {
        ensure!(
            route_sha == transaction.routing_before_sha256,
            "converted relink route changed before pair publication"
        );
        return Ok(None);
    }
    ensure!(
        transaction.pair_after_sha256.as_deref() == Some(pair.as_str()),
        "converted relink pair does not match receipt postimage"
    );
    match transaction.phase {
        RelinkTransactionPhase::Prepared => {
            transaction.phase =
                if transaction.routing_after_sha256.as_deref() == Some(route_sha.as_str()) {
                    RelinkTransactionPhase::RoutingCommitted
                } else {
                    ensure!(
                        route_sha == transaction.routing_before_sha256,
                        "converted relink route changed before pair receipt advanced"
                    );
                    RelinkTransactionPhase::PairCommitted
                };
        }
        RelinkTransactionPhase::PairCommitted
            if route_sha
                == transaction
                    .routing_after_sha256
                    .as_deref()
                    .unwrap_or_default() =>
        {
            transaction.phase = RelinkTransactionPhase::RoutingCommitted
        }
        RelinkTransactionPhase::PairCommitted if route_sha == transaction.routing_before_sha256 => {
        }
        RelinkTransactionPhase::RoutingCommitted => ensure!(
            route_sha
                == transaction
                    .routing_after_sha256
                    .as_deref()
                    .unwrap_or_default(),
            "converted relink route does not match receipt postimage"
        ),
        _ => anyhow::bail!("converted relink route does not match receipt before or after image"),
    }
    ensure!(
        binding.matches_regular_file_child_readonly(
            &bound.dir,
            OsStr::new(RELINK_LOCK_FILE),
            &lock_path
        )?,
        "converted relink lock changed during resume"
    );
    write_transaction(&bound.dir, &bound.physical_display_path, &transaction)?;
    validate_index(&index)?;
    ensure!(
        read_index(&bound.dir, &index_path)?.0 == index_before,
        "converted relink recovery index changed before CAS"
    );
    write_index(&bound.dir, &index_path, &index)?;
    Ok(Some(RelinkCompletionToken {
        pending_id: transaction.pending_id,
        destination: transaction.destination,
    }))
}

pub(crate) fn record_pair_committed_at(home: &Path, token: &RelinkCompletionToken) -> Result<()> {
    update_transaction_phase(
        home,
        token,
        RelinkTransactionPhase::Prepared,
        |transaction, dir, path| {
            let after = pair_commitment_from_dir(dir, path)?;
            ensure!(
                transaction.pair_after_sha256.as_deref() == Some(after.as_str()),
                "converted relink pair publication does not match its prepared generation"
            );
            transaction.phase = RelinkTransactionPhase::PairCommitted;
            Ok(())
        },
    )
}

pub(crate) fn completion_stage_at(
    home: &Path,
    token: &RelinkCompletionToken,
) -> Result<RelinkCompletionStage> {
    let bound = crate::skills::store::open_bound_directory(home, false, "converted relink home")?
        .context("converted relink home absent")?;
    let transaction =
        read_transaction(&bound.dir, &bound.physical_display_path, &token.destination)?
            .context("converted relink completion receipt is absent")?;
    ensure!(
        transaction.pending_id == token.pending_id,
        "converted relink completion receipt does not match pending target"
    );
    Ok(match transaction.phase {
        RelinkTransactionPhase::Prepared => RelinkCompletionStage::Prepared,
        RelinkTransactionPhase::PairCommitted => RelinkCompletionStage::PairCommitted,
        RelinkTransactionPhase::RoutingCommitted => RelinkCompletionStage::RoutingCommitted,
    })
}

pub(crate) fn record_routing_committed_at(
    home: &Path,
    token: &RelinkCompletionToken,
    routing_postimage: &[u8],
) -> Result<()> {
    update_transaction_phase(
        home,
        token,
        RelinkTransactionPhase::PairCommitted,
        |transaction, _dir, _path| {
            let observed = sha256(routing_postimage);
            ensure!(
                transaction.routing_after_sha256.as_deref() == Some(observed.as_str()),
                "converted relink route publication does not match its prepared generation"
            );
            transaction.phase = RelinkTransactionPhase::RoutingCommitted;
            Ok(())
        },
    )
}

fn update_transaction_phase(
    home: &Path,
    token: &RelinkCompletionToken,
    expected: RelinkTransactionPhase,
    action: impl FnOnce(&mut RelinkTransaction, &cap_std::fs::Dir, &Path) -> Result<()>,
) -> Result<()> {
    let _local = RELINK_MUTEX
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| anyhow::anyhow!("converted relink mutex is poisoned"))?;
    let bound = crate::skills::store::open_bound_directory(home, false, "converted relink home")?
        .context("converted relink home absent")?;
    let lock_path = bound.physical_display_path.join(RELINK_LOCK_FILE);
    let (lock, binding) = crate::skills::store::open_or_create_bound_lockfile(
        &bound.dir,
        OsStr::new(RELINK_LOCK_FILE),
        &lock_path,
    )?;
    lock.try_lock()
        .map_err(|error| anyhow::anyhow!("lock converted relink index: {error}"))?;
    let mut transaction =
        read_transaction(&bound.dir, &bound.physical_display_path, &token.destination)?
            .context("converted relink completion receipt is absent")?;
    ensure!(
        transaction.pending_id == token.pending_id
            && transaction.destination == token.destination
            && transaction.phase == expected,
        "converted relink transaction phase does not permit this transition"
    );
    action(&mut transaction, &bound.dir, &bound.physical_display_path)?;
    ensure!(
        binding.matches_regular_file_child_readonly(
            &bound.dir,
            OsStr::new(RELINK_LOCK_FILE),
            &lock_path
        )?,
        "converted relink lock changed during transaction publication"
    );
    write_transaction(&bound.dir, &bound.physical_display_path, &transaction)
}

/// Coordinator-only terminal transition. The private receipt must already
/// prove the exact pair and routing postimages; Ready is never inferred from
/// a probe, a file's presence, or a caller-supplied flag.
pub(crate) fn mark_ready_at(home: &Path, token: &RelinkCompletionToken) -> Result<PendingRelinkId> {
    let _local = RELINK_MUTEX
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| anyhow::anyhow!("converted relink mutex is poisoned"))?;
    let home_directory =
        crate::skills::store::open_bound_directory(home, false, "converted relink home")?
            .context("converted relink home absent")?;
    let lock_path = home_directory.physical_display_path.join(RELINK_LOCK_FILE);
    let (lock, lock_binding) = crate::skills::store::open_or_create_bound_lockfile(
        &home_directory.dir,
        OsStr::new(RELINK_LOCK_FILE),
        &lock_path,
    )?;
    lock.try_lock()
        .map_err(|error| anyhow::anyhow!("lock converted relink index: {error}"))?;
    let path = home_directory.physical_display_path.join(RELINK_INDEX_FILE);
    let (raw, mut index) = read_index(&home_directory.dir, &path)?;
    let transaction = read_transaction(
        &home_directory.dir,
        &home_directory.physical_display_path,
        &token.destination,
    )?
    .context("converted relink completion receipt is absent")?;
    ensure!(
        transaction.pending_id == token.pending_id && transaction.destination == token.destination,
        "converted relink completion receipt does not match pending target"
    );
    ensure!(
        matches!(transaction.phase, RelinkTransactionPhase::RoutingCommitted),
        "converted relink transaction has not committed its route"
    );
    let observed_pair =
        pair_commitment_from_dir(&home_directory.dir, &home_directory.physical_display_path)?;
    ensure!(
        transaction.pair_after_sha256.as_deref() == Some(observed_pair.as_str()),
        "converted relink pair drifted after receipt publication"
    );
    let route_raw = crate::channels::routing::load_for_converted_relink_at(home)?.0;
    let observed_route = sha256(&route_raw);
    ensure!(
        transaction.routing_after_sha256.as_deref() == Some(observed_route.as_str()),
        "converted relink route drifted after receipt publication"
    );
    let entry = index
        .pending
        .iter_mut()
        .find(|entry| &entry.destination == &token.destination)
        .context("converted relink target is not imported")?;
    ensure!(
        entry.id == token.pending_id && matches!(entry.state, PersistedRelinkState::Prepared),
        "converted relink target is not the prepared receipt generation"
    );
    let material = bound_material_commitment(home, &token.destination)?;
    ensure!(
        entry.completion_request_material_sha256.as_deref() == Some(material.as_str()),
        "converted relink material does not match its reserved request"
    );
    entry.bound_material_sha256 = Some(material);
    entry.state = PersistedRelinkState::Ready;
    let id = entry.id.clone();
    validate_index(&index)?;
    ensure!(
        lock_binding.matches_regular_file_child_readonly(
            &home_directory.dir,
            OsStr::new(RELINK_LOCK_FILE),
            &lock_path
        )?,
        "converted relink lock changed before commit"
    );
    let (observed_raw, _) = read_index(&home_directory.dir, &path)?;
    ensure!(
        observed_raw == raw,
        "converted relink index changed before CAS commit"
    );
    write_index(&home_directory.dir, &path, &index)?;
    Ok(id)
}

fn bound_material_commitment(home: &Path, destination: &ChannelRef) -> Result<String> {
    let pair = crate::config::load_runtime_config_pair_from_path(&home.join("freedom.yaml"))
        .context("load coherent converted relink material")?;
    let (_, routing) = crate::channels::routing::load_for_converted_relink_at(home)?;
    let target = routing
        .destinations
        .for_channel(destination.channel_id.as_str())
        .context("converted relink has no exact outbound route")?;
    candidate_material_commitment(&pair.credentials, destination, target)
}

fn commitment(
    kind: ConvertedRelinkKind,
    destination: ChannelRef,
    source_set: &str,
    schema: &str,
    inventory: &str,
    label: &str,
) -> String {
    let mut hash = Sha256::new();
    hash.update(IMPORT_DOMAIN);
    hash.update(format!("{kind:?}").as_bytes());
    hash.update([0]);
    hash.update(destination.channel_id.as_str().as_bytes());
    hash.update([0]);
    hash.update(destination.account_id.as_str().as_bytes());
    hash.update([0]);
    hash.update(source_set.as_bytes());
    hash.update([0]);
    hash.update(schema.as_bytes());
    hash.update([0]);
    hash.update(inventory.as_bytes());
    hash.update([0]);
    hash.update(label.as_bytes());
    format!("{:x}", hash.finalize())
}

fn read_index(parent: &cap_std::fs::Dir, path: &Path) -> Result<(Option<Vec<u8>>, RelinkIndex)> {
    let name = OsStr::new(RELINK_INDEX_FILE);
    match parent.symlink_metadata(name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((
                None,
                RelinkIndex {
                    schema_version: RELINK_SCHEMA_VERSION,
                    pending: Vec::new(),
                },
            ));
        }
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    let bytes =
        crate::skills::store::read_regular_file_bounded(parent, name, path, MAX_INDEX_BYTES)?;
    let mut parser = serde_json::Deserializer::from_slice(&bytes);
    let value = NoDuplicateJsonSeed
        .deserialize(&mut parser)
        .context("decode converted relink index")?;
    parser
        .end()
        .context("trailing converted relink index bytes")?;
    let index: RelinkIndex =
        serde_json::from_value(value).context("decode converted relink index schema")?;
    validate_index(&index)?;
    Ok((Some(bytes), index))
}

fn write_index(parent: &cap_std::fs::Dir, path: &Path, index: &RelinkIndex) -> Result<()> {
    let bytes = serde_json::to_vec(index).context("encode converted relink index")?;
    ensure!(
        bytes.len() <= MAX_INDEX_BYTES,
        "converted relink index exceeds bound"
    );
    crate::skills::store::atomic_write_private_child(
        parent,
        OsStr::new(RELINK_INDEX_FILE),
        path,
        &bytes,
    )
}

fn validate_index(index: &RelinkIndex) -> Result<()> {
    ensure!(
        index.schema_version == RELINK_SCHEMA_VERSION,
        "unsupported converted relink index schema"
    );
    ensure!(
        index.pending.len() <= MAX_PENDING,
        "converted relink index has too many pending records"
    );
    for (offset, entry) in index.pending.iter().enumerate() {
        validate_hex(entry.id.as_str(), "pending relink id")?;
        validate_hex(&entry.source_set_sha256, "source set digest")?;
        validate_hex(
            &entry.known_channel_inventory_sha256,
            "source inventory digest",
        )?;
        validate_hex(
            &entry.source_account_label_commitment,
            "source account commitment",
        )?;
        if let Some(value) = &entry.completion_request_material_sha256 {
            validate_hex(value, "completion request material")?;
        }
        ensure!(
            entry.audited_openclaw_schema_commit
                == neoth_openclaw_custody::AUDITED_OPENCLAW_SCHEMA_COMMIT,
            "pending converted relink schema pin does not match custody contract"
        );
        ensure!(
            entry.known_channel_inventory_sha256
                == neoth_openclaw_custody::canonical_known_channel_inventory_sha256(),
            "pending converted relink inventory pin does not match custody contract"
        );
        ensure!(
            entry.destination.account_id.is_default(),
            "pending converted relink has a non-default destination"
        );
        let expected = match entry.kind {
            ConvertedRelinkKind::IMessage => ChannelId::IMessageBlueBubbles,
            ConvertedRelinkKind::GoogleChat => ChannelId::GoogleChat,
        };
        ensure!(
            entry.destination.channel_id == expected,
            "pending converted relink kind/destination mismatch"
        );
        match entry.state {
            PersistedRelinkState::Pending => ensure!(
                entry.bound_material_sha256.is_none(),
                "pending converted relink has a material binding"
            ),
            PersistedRelinkState::Prepared => ensure!(
                entry.bound_material_sha256.is_none(),
                "prepared converted relink has a material binding"
            ),
            PersistedRelinkState::Ready => {
                validate_hex(
                    entry
                        .bound_material_sha256
                        .as_deref()
                        .context("ready converted relink has no material binding")?,
                    "ready material binding",
                )?;
                ensure!(
                    entry.completion_request_material_sha256.as_deref()
                        == entry.bound_material_sha256.as_deref(),
                    "ready converted relink material differs from reserved request"
                );
            }
        }
        // The opaque label commitment cannot be recomputed without the selected source label. Its ID nevertheless binds the exact stored commitment, schema and inventory.
        let expected_id = PendingRelinkId(commitment(
            entry.kind,
            entry.destination.clone(),
            &entry.source_set_sha256,
            &entry.audited_openclaw_schema_commit,
            &entry.known_channel_inventory_sha256,
            &entry.source_account_label_commitment,
        ));
        ensure!(
            entry.id == expected_id,
            "pending converted relink id does not match persisted provenance"
        );
        ensure!(
            !index.pending[..offset]
                .iter()
                .any(|prior| prior.destination == entry.destination),
            "duplicate converted relink destination"
        );
    }
    Ok(())
}

fn validate_hex(value: &str, field: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "invalid {field}"
    );
    Ok(())
}

/// `serde_json::Value` normally accepts duplicate keys last-write-wins.
/// The relink index is an authority record, so reject duplicates at every depth.
struct NoDuplicateJsonSeed;
impl<'de> DeserializeSeed<'de> for NoDuplicateJsonSeed {
    type Value = serde_json::Value;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<Self::Value, D::Error> {
        deserializer.deserialize_any(NoDuplicateJsonVisitor)
    }
}
struct NoDuplicateJsonVisitor;
impl<'de> Visitor<'de> for NoDuplicateJsonVisitor {
    type Value = serde_json::Value;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("duplicate-free JSON")
    }
    fn visit_bool<E: serde::de::Error>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(serde_json::Value::Bool(value))
    }
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(serde_json::Value::Number(value.into()))
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(serde_json::Value::Number(value.into()))
    }
    fn visit_f64<E: serde::de::Error>(self, value: f64) -> std::result::Result<Self::Value, E> {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(serde_json::Value::String(value.to_owned()))
    }
    fn visit_string<E: serde::de::Error>(
        self,
        value: String,
    ) -> std::result::Result<Self::Value, E> {
        Ok(serde_json::Value::String(value))
    }
    fn visit_none<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }
    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut rows = Vec::new();
        while let Some(row) = seq.next_element_seed(NoDuplicateJsonSeed)? {
            rows.push(row);
        }
        Ok(serde_json::Value::Array(rows))
    }
    fn visit_map<A: MapAccess<'de>>(
        self,
        mut map: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut seen = BTreeSet::new();
        let mut object = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom(
                    "duplicate converted relink JSON key",
                ));
            }
            let value = map.next_value_seed(NoDuplicateJsonSeed)?;
            object.insert(key, value);
        }
        Ok(serde_json::Value::Object(object))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn selected(root: &Path, label: &str) -> SelectedConvertedRelinkAccount {
        let source = root.join("openclaw.yaml");
        std::fs::write(&source, "channels:\n  imessage:\n    accounts:\n      personal:\n        cliPath: /usr/bin/imsg\n      work:\n        cliPath: /usr/bin/imsg\n").unwrap();
        neoth_openclaw_custody::select_converted_relink_account(
            &source,
            ConvertedRelinkChannel::IMessage,
            label,
            &neoth_openclaw_custody::canonical_known_channel_inventory_sha256(),
        )
        .unwrap()
    }
    #[test]
    fn pending_write_reopen_idempotence_conflict_and_legacy_gate() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let destination = ChannelRef::default_account(ChannelId::IMessageBlueBubbles);
        assert_eq!(
            gate_for_at(&home, &destination).unwrap(),
            RelinkGate::Unimported
        );
        let first = selected(root.path(), "personal");
        let created = begin_pending_at(&home, &first, destination.clone()).unwrap();
        assert!(matches!(created, BeginPendingOutcome::Created(_)));
        assert!(matches!(
            gate_for_at(&home, &destination).unwrap(),
            RelinkGate::Pending(_)
        ));
        let again = selected(root.path(), "personal");
        assert!(matches!(
            begin_pending_at(&home, &again, destination.clone()).unwrap(),
            BeginPendingOutcome::AlreadyPending(_)
        ));
        let conflicting = selected(root.path(), "work");
        assert!(begin_pending_at(&home, &conflicting, destination.clone()).is_err());
        assert!(matches!(
            gate_for_at(&home, &destination).unwrap(),
            RelinkGate::Pending(_)
        ));
    }
    #[test]
    fn defaultless_destination_and_corrupt_or_duplicate_index_are_refused() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let selected = selected(root.path(), "personal");
        assert!(
            begin_pending_at(
                &home,
                &selected,
                ChannelRef::new(
                    ChannelId::IMessageBlueBubbles,
                    super::super::registry::ChannelAccountId::new("work").unwrap()
                )
            )
            .is_err()
        );
        std::fs::write(
            home.join(RELINK_INDEX_FILE),
            br#"{"schema_version":1,"schema_version":1,"pending":[]}"#,
        )
        .unwrap();
        assert!(
            gate_for_at(
                &home,
                &ChannelRef::default_account(ChannelId::IMessageBlueBubbles)
            )
            .is_err()
        );
    }
    #[test]
    fn tampered_recomputed_schema_or_inventory_pin_is_refused_without_rewrite() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let destination = ChannelRef::default_account(ChannelId::IMessageBlueBubbles);
        begin_pending_at(
            &home,
            &selected(root.path(), "personal"),
            destination.clone(),
        )
        .unwrap();
        for schema in [true, false] {
            let path = home.join(RELINK_INDEX_FILE);
            let bytes = std::fs::read(&path).unwrap();
            let mut index: RelinkIndex = serde_json::from_slice(&bytes).unwrap();
            let entry = &mut index.pending[0];
            if schema {
                entry.audited_openclaw_schema_commit = "deadbeef".into();
            } else {
                entry.known_channel_inventory_sha256 = "0".repeat(64);
            }
            entry.id = PendingRelinkId(commitment(
                entry.kind,
                entry.destination.clone(),
                &entry.source_set_sha256,
                &entry.audited_openclaw_schema_commit,
                &entry.known_channel_inventory_sha256,
                &entry.source_account_label_commitment,
            ));
            let tampered = serde_json::to_vec(&index).unwrap();
            std::fs::write(&path, &tampered).unwrap();
            assert!(gate_for_at(&home, &destination).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), tampered);
            std::fs::write(&path, bytes).unwrap();
        }
    }

    #[test]
    fn prepared_pair_route_and_ready_require_the_exact_receipt_postimages() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        std::fs::create_dir(&home).unwrap();
        std::fs::write(home.join("freedom.yaml"), b"before-config").unwrap();
        std::fs::write(home.join("credentials.yaml"), b"before-credentials").unwrap();
        let destination = ChannelRef::default_account(ChannelId::IMessageBlueBubbles);
        let created = begin_pending_at(
            &home,
            &selected(root.path(), "personal"),
            destination.clone(),
        )
        .unwrap();
        let id = match created {
            BeginPendingOutcome::Created(id) => id,
            _ => panic!("expected creation"),
        };
        std::fs::write(home.join("credentials.yaml"), b"after-credentials").unwrap();
        let expected_pair = pair_commitment_from_dir(
            &crate::skills::store::open_bound_directory(&home, false, "test home")
                .unwrap()
                .unwrap()
                .dir,
            &home,
        )
        .unwrap();
        std::fs::write(home.join("credentials.yaml"), b"before-credentials").unwrap();
        let mut expected_routing = crate::channels::routing::ChannelRouting::default();
        expected_routing
            .destinations
            .set_for_channel("imessage_bluebubbles", "iMessage;-;+491".into());
        let expected_route = sha256(&serde_json::to_vec_pretty(&expected_routing).unwrap());
        let request_material = sha256(b"test-request-material");
        reserve_request_at(&home, &destination, id.as_str(), &request_material).unwrap();
        let token = prepare_completion_at(
            &home,
            &destination,
            id.as_str(),
            "iMessage;-;+491",
            &request_material,
            b"",
            &expected_pair,
            &expected_route,
        )
        .unwrap();
        assert!(matches!(
            gate_for_at(&home, &destination).unwrap(),
            RelinkGate::Prepared(_)
        ));
        std::fs::write(home.join("credentials.yaml"), b"after-credentials").unwrap();
        record_pair_committed_at(&home, &token).unwrap();
        let (_, mut routing) =
            crate::channels::routing::load_for_converted_relink_at(&home).unwrap();
        assert!(
            routing
                .destinations
                .set_for_channel("imessage_bluebubbles", "iMessage;-;+491".into())
        );
        let postimage = crate::channels::routing::save_for_converted_relink_if_raw_matches_at(
            &home, b"", &routing,
        )
        .unwrap();
        record_routing_committed_at(&home, &token, &postimage).unwrap();
        assert_eq!(
            completion_stage_at(&home, &token).unwrap(),
            RelinkCompletionStage::RoutingCommitted
        );
    }

    #[test]
    fn prepared_receipt_refuses_pair_drift_and_keeps_traffic_blocked() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        std::fs::create_dir(&home).unwrap();
        std::fs::write(home.join("freedom.yaml"), b"before-config").unwrap();
        std::fs::write(home.join("credentials.yaml"), b"before-credentials").unwrap();
        let destination = ChannelRef::default_account(ChannelId::IMessageBlueBubbles);
        let id = match begin_pending_at(
            &home,
            &selected(root.path(), "personal"),
            destination.clone(),
        )
        .unwrap()
        {
            BeginPendingOutcome::Created(id) => id,
            _ => panic!("expected creation"),
        };
        let expected_pair = pair_commitment_from_dir(
            &crate::skills::store::open_bound_directory(&home, false, "test home")
                .unwrap()
                .unwrap()
                .dir,
            &home,
        )
        .unwrap();
        let expected_route = sha256(
            &serde_json::to_vec_pretty(&crate::channels::routing::ChannelRouting::default())
                .unwrap(),
        );
        let request_material = sha256(b"test-request-material");
        reserve_request_at(&home, &destination, id.as_str(), &request_material).unwrap();
        prepare_completion_at(
            &home,
            &destination,
            id.as_str(),
            "iMessage;-;+491",
            &request_material,
            b"",
            &expected_pair,
            &expected_route,
        )
        .unwrap();
        std::fs::write(home.join("freedom.yaml"), b"unexpected-config").unwrap();
        assert!(
            prepare_completion_at(
                &home,
                &destination,
                id.as_str(),
                "iMessage;-;+491",
                &request_material,
                b"",
                &expected_pair,
                &expected_route
            )
            .is_err()
        );
        assert!(matches!(
            gate_for_at(&home, &destination).unwrap(),
            RelinkGate::Prepared(_)
        ));
    }
}
