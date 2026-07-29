//! Crash-safe WAL delivery and reconciliation for installed-Skill mutations.
//!
//! Every runtime registry load passes through this module before it may observe
//! user-installed Skills. The lifecycle is deliberately independent of the CLI:
//! daemon startup can use its already-open WAL writer, one-shot commands can use
//! the authenticated audit RPC, and an offline process owns a unique home-bound
//! WAL segment.

use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use sha2::{Digest as _, Sha256};

use super::installer::{
    self, SkillMutationAuditBinding, SkillMutationAuditReceipt, SkillMutationKind,
    SkillMutationPhase,
};
use crate::wal::writer::WalWriterHandle;

const INTENT_VISIBILITY_RETRIES: usize = 5;
const INTENT_VISIBILITY_RETRY_DELAY: Duration = Duration::from_millis(50);
const SKILL_AUDIT_HMAC_DOMAIN: &[u8] = b"neoth:skill-mutation:audit-payload:v2\0";

/// Outcome of an intent delivery attempt after scanning every bounded WAL
/// segment for the exact operation binding.
pub(crate) enum IntentDelivery {
    Durable(SkillMutationAuditReceipt),
    /// The delivery failed before any append could be in flight.
    DefinitelyNotRecorded(anyhow::Error),
    /// An append may still complete after this caller returns. The persistent
    /// `intent_submitting` journal must remain for same-operation recovery.
    Pending(anyhow::Error),
}

enum AuditDeliveryAttempt {
    Acknowledged,
    DefinitelyNotRecorded(anyhow::Error),
    Uncertain(anyhow::Error),
}

#[cfg(test)]
thread_local! {
    static TEST_SKILL_AUDIT_FAILURES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn fail_next_skill_audit_deliveries(count: usize) {
    TEST_SKILL_AUDIT_FAILURES.with(|remaining| remaining.set(count));
}

fn skill_mutation_subtype(
    kind: SkillMutationKind,
    terminal: bool,
) -> crate::wal::events::ExtendedSubtype {
    match (kind.is_install(), terminal) {
        (true, false) => crate::wal::events::ExtendedSubtype::SkillInstallIntent,
        (true, true) => crate::wal::events::ExtendedSubtype::SkillInstallResult,
        (false, false) => crate::wal::events::ExtendedSubtype::SkillRemovalIntent,
        (false, true) => crate::wal::events::ExtendedSubtype::SkillRemovalResult,
    }
}

fn receipt_sha256(receipt: &SkillMutationAuditReceipt) -> Result<String> {
    let bytes = serde_json::to_vec(receipt).context("serialize Skill mutation audit receipt")?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn unsigned_skill_mutation_audit_value(
    binding: &SkillMutationAuditBinding,
    terminal: bool,
) -> Result<serde_json::Value> {
    let audit_event_id = if terminal {
        binding.terminal_audit_event_id()
    } else {
        binding.intent_audit_event_id()
    };
    let phase = if terminal {
        binding.phase.as_str()
    } else {
        "intent"
    };
    let intent_receipt_sha256 = if terminal {
        Some(receipt_sha256(binding.intent_receipt.as_ref().context(
            "terminal Skill mutation binding lacks its authenticated intent receipt",
        )?)?)
    } else {
        None
    };
    if terminal && binding.commit_boundary_sha256.is_none() {
        anyhow::bail!("terminal Skill mutation binding lacks its durable commit boundary");
    }
    Ok(serde_json::json!({
        "schema_version": 2,
        "audit_event_id": audit_event_id,
        "operation_id": binding.operation_id,
        "mutation": binding.kind.as_str(),
        "origin": binding.origin.as_str(),
        "skill_id": binding.skill_id,
        "chain_sequence": if terminal { 2 } else { 1 },
        "intent_audit_event_id": if terminal {
            binding
                .intent_receipt
                .as_ref()
                .map(|receipt| receipt.audit_event_id.as_str())
        } else {
            None
        },
        "intent_receipt_sha256": intent_receipt_sha256,
        "commit_boundary_sha256": if terminal {
            binding.commit_boundary_sha256.as_deref()
        } else {
            None
        },
        "source_generation_sha256": binding.source_generation_sha256,
        "prior_generation_sha256": binding.prior_generation_sha256,
        "prior_object_identity_sha256": binding.prior_object_identity_sha256,
        "observed_generation_sha256": if terminal {
            binding.observed_generation_sha256.as_deref()
        } else {
            None
        },
        "status": if terminal { Some(phase) } else { None },
        "phase": phase,
        "error_sha256": if terminal {
            binding.error_sha256.as_deref()
        } else {
            None
        },
        // Compatibility fields retained for existing receipts/forensics.
        "replacing_existing": binding.kind == SkillMutationKind::Replace,
        "target_generation_sha256": binding.prior_generation_sha256,
        "prior_anchor_state": if binding.prior_generation_sha256.is_some() {
            "present"
        } else {
            "absent"
        },
        "installed_generation_sha256": if terminal && binding.kind.is_install() {
            binding.observed_generation_sha256.as_deref()
        } else {
            None
        },
        "replaced_existing": if terminal && binding.kind.is_install() {
            Some(
                binding.kind == SkillMutationKind::Replace
                    && binding.phase == SkillMutationPhase::Committed,
            )
        } else {
            None
        },
        "removed": if terminal
            && binding.kind == SkillMutationKind::Remove
            && binding.phase == SkillMutationPhase::Committed
        {
            Some(binding.prior_generation_sha256.is_some())
        } else {
            None
        },
        "removed_generation_sha256": if terminal
            && binding.kind == SkillMutationKind::Remove
            && binding.phase == SkillMutationPhase::Committed
        {
            binding.prior_generation_sha256.as_deref()
        } else {
            None
        },
        "source": binding.origin.as_str(),
        "ts_unix": binding.created_at_unix,
    }))
}

fn skill_audit_payload_hmac(
    key: &[u8],
    subtype: crate::wal::events::ExtendedSubtype,
    unsigned_payload: &[u8],
) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(SKILL_AUDIT_HMAC_DOMAIN);
    mac.update(&[subtype as u8]);
    mac.update(unsigned_payload);
    hex::encode(mac.finalize().into_bytes())
}

pub(crate) fn skill_mutation_audit_payload(
    binding: &SkillMutationAuditBinding,
    terminal: bool,
    key: &[u8],
) -> Result<Vec<u8>> {
    let subtype = skill_mutation_subtype(binding.kind, terminal);
    let mut value = unsigned_skill_mutation_audit_value(binding, terminal)?;
    let unsigned = serde_json::to_vec(&value).context("serialize unsigned Skill audit payload")?;
    let tag = skill_audit_payload_hmac(key, subtype, &unsigned);
    value
        .as_object_mut()
        .context("canonical Skill audit payload must be a JSON object")?
        .insert(
            "auth_hmac_sha256".to_string(),
            serde_json::Value::String(tag),
        );
    serde_json::to_vec(&value).context("serialize authenticated Skill mutation audit payload")
}

fn json_optional_string<'a>(
    payload: &'a serde_json::Value,
    field: &str,
) -> Result<Option<&'a str>> {
    match payload.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(Some)
            .with_context(|| format!("Skill mutation WAL field `{field}` is not a string")),
    }
}

fn validate_skill_mutation_wal_payload(
    payload: &[u8],
    binding: &SkillMutationAuditBinding,
    terminal: bool,
    key: &[u8],
    observed_subtype: crate::wal::events::ExtendedSubtype,
) -> Result<bool> {
    let mut value: serde_json::Value =
        serde_json::from_slice(payload).context("parse Skill mutation WAL payload")?;
    if json_optional_string(&value, "operation_id")? != Some(binding.operation_id.as_str()) {
        return Ok(false);
    }
    let tag = value
        .as_object_mut()
        .context("Skill mutation WAL payload is not a JSON object")?
        .remove("auth_hmac_sha256")
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .context("Skill mutation WAL payload lacks its HMAC-SHA256 authentication tag")?;
    let tag = hex::decode(&tag).context("decode Skill mutation WAL authentication tag")?;
    let unsigned =
        serde_json::to_vec(&value).context("serialize candidate unsigned Skill audit payload")?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(SKILL_AUDIT_HMAC_DOMAIN);
    mac.update(&[observed_subtype as u8]);
    mac.update(&unsigned);
    mac.verify_slice(&tag).context(
        "Skill mutation WAL payload authentication failed; CRC-only evidence is not accepted",
    )?;

    let expected: serde_json::Value =
        serde_json::from_slice(&skill_mutation_audit_payload(binding, terminal, key)?)
            .context("parse canonical Skill mutation audit payload")?;
    let actual: serde_json::Value =
        serde_json::from_slice(payload).context("reparse authenticated Skill mutation payload")?;
    if actual != expected {
        anyhow::bail!(
            "Skill mutation WAL event for operation {} conflicts with its durable journal binding",
            binding.operation_id
        );
    }
    Ok(true)
}

#[derive(Clone, Debug, Default)]
struct SkillMutationAuditScan {
    intent: Option<SkillMutationAuditReceipt>,
    terminal: Option<SkillMutationAuditReceipt>,
}

fn same_segment_terminal_is_after_intent(
    intent: &SkillMutationAuditReceipt,
    terminal: &SkillMutationAuditReceipt,
) -> bool {
    intent.segment_name != terminal.segment_name
        || intent.segment_generation != terminal.segment_generation
        || intent.segment_node_id_hex != terminal.segment_node_id_hex
        || terminal.logical_offset > intent.logical_offset
}

fn scan_skill_mutation_audit(
    home: &Path,
    binding: &SkillMutationAuditBinding,
) -> Result<SkillMutationAuditScan> {
    let keys = crate::wal::scan::load_home_hmac_keys(home)?;
    if keys.is_empty() {
        return Ok(SkillMutationAuditScan::default());
    }
    let mut observed = SkillMutationAuditScan::default();
    crate::wal::scan::for_each_frame_at_home(
        home,
        crate::wal::scan::HomeWalScanLimits::default(),
        |location, frame| {
            if frame.header.event_type != crate::wal::events::EVENT_TYPE_EXTENDED {
                return Ok(());
            }
            let Some(subtype) =
                crate::wal::events::ExtendedSubtype::from_u8(frame.header.event_subtype)
            else {
                return Ok(());
            };
            let terminal = match subtype {
                crate::wal::events::ExtendedSubtype::SkillInstallIntent
                | crate::wal::events::ExtendedSubtype::SkillRemovalIntent => false,
                crate::wal::events::ExtendedSubtype::SkillInstallResult
                | crate::wal::events::ExtendedSubtype::SkillRemovalResult => true,
                _ => return Ok(()),
            };
            let value: serde_json::Value = serde_json::from_slice(frame.payload)
                .context("parse candidate Skill mutation WAL payload")?;
            if json_optional_string(&value, "operation_id")? != Some(binding.operation_id.as_str())
            {
                return Ok(());
            }
            if frame.header.event_subtype != skill_mutation_subtype(binding.kind, terminal) as u8 {
                anyhow::bail!(
                    "Skill mutation {} has a conflicting WAL subtype 0x{:02x}",
                    binding.operation_id,
                    frame.header.event_subtype
                );
            }
            if terminal && !binding.phase.is_terminal() {
                anyhow::bail!(
                    "Skill mutation {} has an authenticated terminal before its durable journal reached a terminal phase",
                    binding.operation_id
                );
            }
            let mut authenticated = false;
            let mut last_error = None;
            for key in &keys {
                match validate_skill_mutation_wal_payload(
                    frame.payload,
                    binding,
                    terminal,
                    key,
                    subtype,
                ) {
                    Ok(true) => {
                        authenticated = true;
                        break;
                    }
                    Ok(false) => {}
                    Err(error) => last_error = Some(error),
                }
            }
            if !authenticated {
                return Err(last_error.unwrap_or_else(|| {
                    anyhow::anyhow!(
                        "Skill mutation WAL payload did not authenticate under any bounded key"
                    )
                }));
            }
            let segment_name = location
                .segment_name
                .to_str()
                .context("canonical WAL segment name is not UTF-8")?
                .to_string();
            let receipt = SkillMutationAuditReceipt {
                audit_event_id: json_optional_string(&value, "audit_event_id")?
                    .context("authenticated Skill mutation event lacks audit_event_id")?
                    .to_string(),
                payload_sha256: hex::encode(Sha256::digest(frame.payload)),
                segment_name,
                segment_generation: location.segment_generation,
                segment_seq: location.segment_seq,
                segment_start_ts_ns: location.segment_start_ts_ns,
                segment_node_id_hex: hex::encode(location.segment_node_id),
                logical_offset: location.logical_offset,
                event_id: frame.header.event_id.raw(),
                event_hlc_physical_ns: frame.header.hlc.physical_ns(),
                event_hlc_logical: frame.header.hlc.logical(),
                event_node_id_hex: hex::encode(frame.header.node_id.0),
            };
            let slot = if terminal {
                &mut observed.terminal
            } else {
                &mut observed.intent
            };
            if slot.replace(receipt).is_some() {
                anyhow::bail!(
                    "Skill mutation {} has more than one authenticated {} WAL frame",
                    binding.operation_id,
                    if terminal { "terminal" } else { "intent" }
                );
            }
            Ok(())
        },
    )?;

    if let Some(expected) = binding.intent_receipt.as_ref()
        && observed
            .intent
            .as_ref()
            .is_some_and(|actual| actual != expected)
    {
        anyhow::bail!(
            "Skill mutation {} WAL intent no longer matches its persisted authenticated receipt",
            binding.operation_id
        );
    }
    if let Some(terminal) = observed.terminal.as_ref() {
        let intent = observed.intent.as_ref().with_context(|| {
            format!(
                "Skill mutation {} has an authenticated terminal without its intent",
                binding.operation_id
            )
        })?;
        // Within one immutable segment the logical byte offset is an actual
        // physical order. Across process/restart-owned segments, wall-clock
        // HLC is not a monotone authority (snapshot restore can move it
        // backwards); the terminal's authenticated hash of this exact intent
        // receipt is the causal chain boundary instead.
        if !same_segment_terminal_is_after_intent(intent, terminal) {
            anyhow::bail!(
                "Skill mutation {} terminal is not physically ordered after its authenticated intent",
                binding.operation_id
            );
        }
    }
    Ok(observed)
}

pub(crate) fn scan_skill_mutation_audit_count(
    home: &Path,
    binding: &SkillMutationAuditBinding,
    terminal: bool,
) -> Result<usize> {
    let scan = scan_skill_mutation_audit(home, binding)?;
    Ok(usize::from(if terminal {
        scan.terminal.is_some()
    } else {
        scan.intent.is_some()
    }))
}

async fn scan_skill_mutation_audit_async(
    home: &Path,
    binding: &SkillMutationAuditBinding,
) -> Result<SkillMutationAuditScan> {
    let home = home.to_path_buf();
    let binding = binding.clone();
    tokio::task::spawn_blocking(move || scan_skill_mutation_audit(&home, &binding))
        .await
        .context("join capability-bound Skill mutation WAL scan")?
}

fn initialize_skill_mutation_audit_key(home: &Path) -> Result<Vec<u8>> {
    let wal_path = home.join("wal");
    let root = crate::skills::store::open_bound_directory(
        &wal_path,
        true,
        "Skill mutation WAL key directory",
    )?
    .context("created Skill mutation WAL key directory is unavailable")?;

    let active_name = std::ffi::OsStr::new("hmac.key");
    let master_name = std::ffi::OsStr::new("master.key");
    let mut examined_entries = 0usize;
    for entry in root
        .dir
        .entries()
        .with_context(|| format!("enumerate WAL key directory {}", wal_path.display()))?
    {
        examined_entries = examined_entries
            .checked_add(1)
            .context("WAL key initialization entry counter overflow")?;
        if examined_entries > crate::wal::scan::MAX_HOME_KEY_DIRECTORY_ENTRIES {
            anyhow::bail!(
                "WAL key initialization exceeds the {}-entry directory limit under {}",
                crate::wal::scan::MAX_HOME_KEY_DIRECTORY_ENTRIES,
                wal_path.display()
            );
        }
        let name = entry
            .with_context(|| format!("read WAL key entry under {}", wal_path.display()))?
            .file_name();
        if name != master_name {
            anyhow::bail!(
                "refusing to create a new WAL HMAC identity while `{}` already exists under {}",
                name.to_string_lossy(),
                wal_path.display()
            );
        }
    }

    let active_display = root.display_path.join(active_name);
    let mut initialized = vec![0u8; 32];
    getrandom::getrandom(&mut initialized)
        .context("OS RNG unavailable; refusing to generate a weak Skill mutation audit key")?;
    crate::wal::compaction::write_key_securely(&active_display, &initialized)
        .context("create instance-bound Skill mutation audit key")?;
    let stored = crate::skills::store::read_regular_file_bounded(
        &root.dir,
        active_name,
        &active_display,
        crate::wal::scan::MAX_HOME_KEY_BYTES,
    )
    .context("re-open created Skill mutation audit key through its bound WAL directory")?;
    let bound_active = crate::wal::compaction::decode_existing_key(&stored, &active_display)
        .context("decode created Skill mutation audit key")?;
    if bound_active != initialized {
        anyhow::bail!(
            "created WAL HMAC key changed between its atomic commit and capability-bound read"
        );
    }

    let scanner_active = crate::wal::scan::load_home_hmac_keys(home)?
        .into_iter()
        .next()
        .context("created WAL HMAC key is not visible to the bounded WAL scanner")?;
    if scanner_active != bound_active {
        anyhow::bail!("Skill mutation emitter and WAL scanner resolved different active HMAC keys");
    }
    Ok(bound_active)
}

fn load_or_init_skill_mutation_audit_key(home: &Path) -> Result<Vec<u8>> {
    match crate::wal::scan::load_home_hmac_keys(home) {
        Ok(keys) => match keys.into_iter().next() {
            Some(active) => Ok(active),
            None => initialize_skill_mutation_audit_key(home),
        },
        Err(scan_error) => initialize_skill_mutation_audit_key(home).map_err(|init_error| {
            scan_error.context(format!(
                "active WAL HMAC key was not scanner-readable and safe initialization was refused: \
                 {init_error:#}"
            ))
        }),
    }
}

async fn load_or_init_skill_mutation_audit_key_async(home: &Path) -> Result<Vec<u8>> {
    let home = home.to_path_buf();
    tokio::task::spawn_blocking(move || load_or_init_skill_mutation_audit_key(&home))
        .await
        .context("join capability-bound Skill mutation HMAC-key load")?
}

async fn daemon_singleflight_available(home: &Path) -> Result<bool> {
    let pid_path = home.join("neothd.pid");
    tokio::task::spawn_blocking(move || crate::daemon::pidfile::live_daemon_pid(&pid_path))
        .await
        .context("join daemon ownership probe")?
        .map(|pid| pid.is_some())
}

async fn emit_skill_mutation_audit(
    home: &Path,
    writer: Option<&WalWriterHandle>,
    binding: &SkillMutationAuditBinding,
    terminal: bool,
) -> AuditDeliveryAttempt {
    #[cfg(test)]
    {
        let failure = TEST_SKILL_AUDIT_FAILURES.with(|remaining| {
            let count = remaining.get();
            if count == 0 {
                None
            } else {
                remaining.set(count - 1);
                Some(anyhow::anyhow!(
                    "injected Skill mutation WAL delivery failure"
                ))
            }
        });
        if let Some(error) = failure {
            return AuditDeliveryAttempt::DefinitelyNotRecorded(error);
        }
    }

    let subtype = skill_mutation_subtype(binding.kind, terminal);
    let key = match load_or_init_skill_mutation_audit_key_async(home).await {
        Ok(key) => key,
        Err(error) => {
            return AuditDeliveryAttempt::DefinitelyNotRecorded(
                error.context("load instance-bound Skill mutation audit key"),
            );
        }
    };
    let payload = match skill_mutation_audit_payload(binding, terminal, &key) {
        Ok(payload) => payload,
        Err(error) => return AuditDeliveryAttempt::DefinitelyNotRecorded(error),
    };
    let header = crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_EXTENDED, &payload)
        .event_subtype(subtype as u8)
        .build();

    if let Some(writer) = writer {
        return match writer.append(header, payload).await {
            Ok(_) => AuditDeliveryAttempt::Acknowledged,
            Err(error) => AuditDeliveryAttempt::Uncertain(
                anyhow::Error::new(error)
                    .context("append Skill mutation audit through daemon writer"),
            ),
        };
    }

    let daemon_live = match daemon_singleflight_available(home).await {
        Ok(live) => live,
        Err(error) => {
            return AuditDeliveryAttempt::DefinitelyNotRecorded(
                error.context("inspect daemon ownership before Skill audit delivery"),
            );
        }
    };
    if daemon_live {
        return match crate::daemon::audit_rpc::try_post_skill_mutation_frame(
            home,
            crate::wal::events::EVENT_TYPE_EXTENDED,
            subtype as u8,
            &payload,
        )
        .await
        {
            Ok(()) => AuditDeliveryAttempt::Acknowledged,
            Err(crate::daemon::audit_rpc::AuditRpcClientError::Refused(503)) => {
                AuditDeliveryAttempt::DefinitelyNotRecorded(anyhow::anyhow!(
                    "daemon Skill-audit singleflight capacity is exhausted"
                ))
            }
            Err(error) => AuditDeliveryAttempt::Uncertain(
                anyhow::Error::new(error)
                    .context("daemon did not durably ACK Skill mutation audit"),
            ),
        };
    }

    let wal_dir = home.join("wal");
    if let Err(error) = std::fs::create_dir_all(&wal_dir) {
        return AuditDeliveryAttempt::DefinitelyNotRecorded(error.into());
    }
    let segment =
        crate::wal::writer::unique_standalone_segment_path(&wal_dir, "skill-mutation-audit");
    let (standalone_writer, join) =
        match crate::wal::writer::spawn_for_home(segment, home.to_path_buf()) {
            Ok(writer) => writer,
            Err(error) => {
                return AuditDeliveryAttempt::DefinitelyNotRecorded(
                    anyhow::Error::new(error)
                        .context("spawn home-bound writer for Skill mutation audit"),
                );
            }
        };
    let append = standalone_writer.append(header, payload).await;
    drop(standalone_writer);
    let joined = join.await;
    match append {
        Ok(_) => match joined {
            Ok(()) => AuditDeliveryAttempt::Acknowledged,
            Err(_) => AuditDeliveryAttempt::Acknowledged,
        },
        Err(error) => AuditDeliveryAttempt::Uncertain(
            anyhow::Error::new(error).context("append home-bound Skill mutation audit"),
        ),
    }
}

async fn scan_intent_until_visible(
    home: &Path,
    binding: &SkillMutationAuditBinding,
) -> Result<Option<SkillMutationAuditReceipt>> {
    for attempt in 0..=INTENT_VISIBILITY_RETRIES {
        let receipt = scan_skill_mutation_audit_async(home, binding).await?.intent;
        if receipt.is_some() || attempt == INTENT_VISIBILITY_RETRIES {
            return Ok(receipt);
        }
        tokio::time::sleep(INTENT_VISIBILITY_RETRY_DELAY).await;
    }
    unreachable!("bounded Skill intent scan always returns")
}

async fn scan_terminal_until_visible(
    home: &Path,
    binding: &SkillMutationAuditBinding,
) -> Result<Option<SkillMutationAuditReceipt>> {
    for attempt in 0..=INTENT_VISIBILITY_RETRIES {
        let receipt = scan_skill_mutation_audit_async(home, binding)
            .await?
            .terminal;
        if receipt.is_some() || attempt == INTENT_VISIBILITY_RETRIES {
            return Ok(receipt);
        }
        tokio::time::sleep(INTENT_VISIBILITY_RETRY_DELAY).await;
    }
    unreachable!("bounded Skill terminal scan always returns")
}

pub(crate) async fn deliver_intent(
    home: &Path,
    writer: Option<&WalWriterHandle>,
    binding: &SkillMutationAuditBinding,
) -> Result<IntentDelivery> {
    if let Some(receipt) = scan_skill_mutation_audit_async(home, binding).await?.intent {
        return Ok(IntentDelivery::Durable(receipt));
    }
    let delivery = emit_skill_mutation_audit(home, writer, binding, false).await;
    let receipt = match &delivery {
        AuditDeliveryAttempt::DefinitelyNotRecorded(_) => {
            Ok(scan_skill_mutation_audit_async(home, binding).await?.intent)
        }
        _ => scan_intent_until_visible(home, binding).await,
    }
    .with_context(|| {
        format!(
            "intent delivery for Skill mutation {} is uncertain; private journal retained",
            binding.operation_id
        )
    })?;
    if let Some(receipt) = receipt {
        return Ok(IntentDelivery::Durable(receipt));
    }
    Ok(match delivery {
        AuditDeliveryAttempt::DefinitelyNotRecorded(error) => {
            IntentDelivery::DefinitelyNotRecorded(error)
        }
        AuditDeliveryAttempt::Acknowledged => IntentDelivery::Pending(anyhow::anyhow!(
            "Skill mutation {} received an intent ACK, but no exact WAL frame is visible; \
             private journal retained",
            binding.operation_id
        )),
        AuditDeliveryAttempt::Uncertain(error) => IntentDelivery::Pending(error.context(format!(
            "Skill mutation {} intent may still be in flight; private journal retained",
            binding.operation_id
        ))),
    })
}

pub(crate) async fn deliver_terminal_once(
    home: &Path,
    writer: Option<&WalWriterHandle>,
    binding: &SkillMutationAuditBinding,
) -> Result<SkillMutationAuditReceipt> {
    if let Some(receipt) = scan_skill_mutation_audit_async(home, binding)
        .await?
        .terminal
    {
        return Ok(receipt);
    }
    let delivery = emit_skill_mutation_audit(home, writer, binding, true).await;
    let receipt = scan_skill_mutation_audit_async(home, binding)
        .await
        .map(|scan| scan.terminal)
        .with_context(|| {
            format!(
                "terminal delivery for Skill mutation {} is uncertain; outbox retained",
                binding.operation_id
            )
        })?;
    if let Some(receipt) = receipt {
        return Ok(receipt);
    }
    match delivery {
        AuditDeliveryAttempt::Acknowledged => anyhow::bail!(
            "Skill mutation {} received a terminal ACK, but no exact WAL frame is visible; \
             outbox retained",
            binding.operation_id
        ),
        AuditDeliveryAttempt::DefinitelyNotRecorded(error)
        | AuditDeliveryAttempt::Uncertain(error) => Err(error).with_context(|| {
            format!(
                "terminal audit for Skill mutation {} was not recorded; outbox retained",
                binding.operation_id
            )
        }),
    }
}

/// Reconcile the one bounded mutation journal before a runtime may load any
/// installed Skill. `writer` is supplied during daemon startup, before the
/// audit-RPC listener is online; one-shot and post-startup callers pass `None`.
pub(crate) async fn reconcile_pending(
    home: &Path,
    skills_dir: &Path,
    writer: Option<&WalWriterHandle>,
) -> Result<()> {
    let skills_dir = skills_dir.to_path_buf();
    let pending = tokio::task::spawn_blocking(move || {
        installer::open_pending_skill_mutation_reconciliation(&skills_dir)
    })
    .await
    .context("join pending Skill mutation open/recovery scan")??;
    let Some(pending) = pending else {
        return Ok(());
    };
    let prepared_binding = pending.audit_binding();
    let intent_delivery_owned = pending.intent_delivery_owned_by_current_process();
    let intent_receipt = match prepared_binding.phase {
        SkillMutationPhase::IntentSubmitting => {
            let daemon_coordinates_delivery = if writer.is_none() {
                daemon_singleflight_available(home)
                    .await
                    .context("inspect daemon ownership during Skill intent reconciliation")?
            } else {
                false
            };
            if intent_delivery_owned && !daemon_coordinates_delivery {
                // A direct daemon-writer or standalone-writer append can outlive
                // its cancelled future but has no dedup coordinator. Never
                // enqueue a second frame in the same process.
                scan_intent_until_visible(home, &prepared_binding).await?
            } else {
                match deliver_intent(home, writer, &prepared_binding).await? {
                    IntentDelivery::Durable(receipt) => Some(receipt),
                    IntentDelivery::DefinitelyNotRecorded(error) => {
                        return Err(error).context(format!(
                            "Skill mutation {} entered intent delivery; exact retry failed before \
                             durability and its journal was retained",
                            prepared_binding.operation_id
                        ));
                    }
                    IntentDelivery::Pending(error) => {
                        return Err(error).context(format!(
                            "Skill mutation {} intent delivery remains pending; journal retained",
                            prepared_binding.operation_id
                        ));
                    }
                }
            }
        }
        _ => {
            scan_skill_mutation_audit_async(home, &prepared_binding)
                .await?
                .intent
        }
    };
    let intent_seen = intent_receipt.is_some();
    let bind_intent_receipt = matches!(
        prepared_binding.phase,
        SkillMutationPhase::IntentSubmitting | SkillMutationPhase::IntentDurable
    );
    let terminal = tokio::task::spawn_blocking(move || {
        let mut pending = pending;
        if bind_intent_receipt && let Some(receipt) = intent_receipt {
            pending.mark_intent_durable_authenticated(receipt)?;
        }
        let Some(_terminal_binding) = pending.reconcile(intent_seen)? else {
            return Ok::<_, anyhow::Error>(None);
        };
        let terminal_was_owned = pending.terminal_delivery_owned_by_current_process();
        pending.mark_terminal_submitting()?;
        let terminal_binding = pending.audit_binding();
        Ok(Some((pending, terminal_was_owned, terminal_binding)))
    })
    .await
    .context("join pending Skill mutation namespace reconciliation")??;
    let Some((mut pending, terminal_was_owned, terminal_binding)) = terminal else {
        return Ok(());
    };
    let daemon_coordinates_delivery = if writer.is_none() {
        daemon_singleflight_available(home)
            .await
            .context("inspect daemon ownership during Skill terminal reconciliation")?
    } else {
        false
    };
    let terminal_receipt = if terminal_was_owned && !daemon_coordinates_delivery {
        scan_terminal_until_visible(home, &terminal_binding)
            .await?
            .with_context(|| {
                format!(
                    "Skill mutation {} terminal delivery remains in flight; outbox retained",
                    terminal_binding.operation_id
                )
            })?
    } else {
        deliver_terminal_once(home, writer, &terminal_binding).await?
    };
    tokio::task::spawn_blocking(move || {
        pending.mark_terminal_durable(terminal_receipt)?;
        pending.acknowledge_terminal()
    })
    .await
    .context("join terminal Skill mutation acknowledgement")?
}

pub(crate) async fn reconcile_for_runtime(skills_dir: &Path) -> Result<()> {
    let home = skills_dir.parent().with_context(|| {
        format!(
            "installed Skill directory {} has no instance-home parent",
            skills_dir.display()
        )
    })?;
    reconcile_pending(home, skills_dir, None).await
}

async fn apply_skill_document_mutation(
    home: &Path,
    request: installer::SkillDocumentMutationRequest,
) -> Result<installer::InstallReport> {
    let authorized_skills_dir =
        std::path::absolute(home.join("skills")).context("resolve audited Skill home")?;
    let requested_skills_dir = std::path::absolute(&request.target_skills_dir)
        .context("resolve audited Skill mutation target")?;
    if requested_skills_dir != authorized_skills_dir {
        anyhow::bail!(
            "audited generated Skill mutation target {} is not the exact skills store for home {}",
            requested_skills_dir.display(),
            home.display()
        );
    }
    let skills_dir = request.target_skills_dir.clone();
    reconcile_pending(home, &skills_dir, None)
        .await
        .context("reconcile prior installed-Skill mutation before generated write")?;
    let operation_id = uuid::Uuid::now_v7().simple().to_string();
    let mut prepared = match installer::prepare_skill_document_mutation(&request, &operation_id)? {
        installer::PreparedSkillDocumentMutation::Unchanged(report) => return Ok(report),
        installer::PreparedSkillDocumentMutation::Prepared(prepared) => prepared,
    };

    prepared
        .mark_intent_submitting()
        .context("persist generated Skill intent-delivery ownership")?;
    let binding = prepared.audit_binding();
    let intent_receipt = match deliver_intent(home, None, &binding).await? {
        IntentDelivery::Durable(receipt) => receipt,
        IntentDelivery::DefinitelyNotRecorded(audit_error) => {
            prepared.abort_without_intent().with_context(|| {
                format!(
                    "generated Skill intent was not durable and its private cleanup failed: {audit_error:#}"
                )
            })?;
            return Err(audit_error.context(
                "generated Skill intent was not durable; no public Skill package was changed",
            ));
        }
        IntentDelivery::Pending(audit_error) => {
            drop(prepared);
            return Err(audit_error.context(
                "generated Skill intent delivery may still complete; private journal retained for same-operation recovery",
            ));
        }
    };
    if let Err(error) = prepared.mark_intent_durable_authenticated(intent_receipt) {
        drop(prepared);
        let recovery = reconcile_pending(home, &skills_dir, None).await;
        return Err(match recovery {
            Ok(()) => error.context(
                "generated Skill intent was durable, but its local phase transition failed; the same operation was reconciled without publishing",
            ),
            Err(recovery_error) => error.context(format!(
                "generated Skill intent was durable, its local phase transition failed, and same-operation recovery remains pending: {recovery_error:#}"
            )),
        });
    }

    let report = match prepared.commit() {
        Ok(report) => report,
        Err(commit_error) => {
            let status = commit_error.state().as_str();
            let error = commit_error.into_inner();
            if let Err(recovery_error) = reconcile_pending(home, &skills_dir, None).await {
                return Err(error.context(format!(
                    "generated Skill package write failed with `{status}`, and its same-operation terminal reconciliation remains pending: {recovery_error:#}"
                )));
            }
            return Err(error);
        }
    };
    reconcile_pending(home, &skills_dir, None)
        .await
        .context("generated Skill package committed, but its correlated audit remains pending")?;
    Ok(report)
}

/// Run a generated/runtime Skill write from synchronous callers without
/// nesting a Tokio runtime or blocking an existing async worker. Only the
/// owned request enters the dedicated transaction thread; that thread
/// constructs the capability handles and OS mutation guard, drives its
/// current-thread runtime, commits, reconciles, and drops every bound object
/// before returning.
pub(crate) fn apply_skill_document_mutation_blocking(
    home: &Path,
    request: installer::SkillDocumentMutationRequest,
) -> Result<installer::InstallReport> {
    let home = home.to_path_buf();
    std::thread::Builder::new()
        .name("neoth-skill-mutation".to_string())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("build generated Skill mutation runtime")?;
            runtime.block_on(apply_skill_document_mutation(&home, request))
        })
        .context("spawn generated Skill mutation transaction thread")?
        .join()
        .map_err(|panic| {
            let message = panic
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("unknown panic");
            anyhow::anyhow!("generated Skill mutation transaction thread panicked: {message}")
        })?
}

pub(crate) fn reconcile_pending_blocking(home: &Path, skills_dir: &Path) -> Result<()> {
    let home = home.to_path_buf();
    let skills_dir = skills_dir.to_path_buf();
    std::thread::Builder::new()
        .name("neoth-skill-reconcile".to_string())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("build installed-Skill reconciliation runtime")?;
            runtime.block_on(reconcile_pending(&home, &skills_dir, None))
        })
        .context("spawn installed-Skill reconciliation thread")?
        .join()
        .map_err(|panic| {
            let message = panic
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("unknown panic");
            anyhow::anyhow!("installed-Skill reconciliation thread panicked: {message}")
        })?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_reconciliation_future_is_send_for_registry_hot_reload() {
        fn assert_send<T: Send>(_: T) {}
        let skills_dir = PathBuf::from("send-contract-skills");
        assert_send(reconcile_for_runtime(&skills_dir));
    }

    #[test]
    fn fresh_emitter_key_is_the_exact_bounded_scanner_key() {
        let home = tempfile::tempdir().unwrap();
        let emitter_key = load_or_init_skill_mutation_audit_key(home.path()).unwrap();
        let scanner_keys = crate::wal::scan::load_home_hmac_keys(home.path()).unwrap();
        assert_eq!(scanner_keys.first(), Some(&emitter_key));
        assert_eq!(emitter_key.len(), 32);
    }

    #[test]
    fn emitter_rejects_an_oversized_key_that_the_scanner_rejects() {
        let home = tempfile::tempdir().unwrap();
        let wal_dir = home.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        std::fs::write(
            wal_dir.join("hmac.key"),
            vec![0x5a; crate::wal::scan::MAX_HOME_KEY_BYTES + 1],
        )
        .unwrap();

        let error = load_or_init_skill_mutation_audit_key(home.path()).unwrap_err();
        assert!(format!("{error:#}").contains("maximum"));
    }

    #[cfg(unix)]
    #[test]
    fn emitter_rejects_a_linked_key_that_the_scanner_rejects() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let wal_dir = home.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        std::os::unix::fs::symlink(outside.path(), wal_dir.join("hmac.key")).unwrap();

        let error = load_or_init_skill_mutation_audit_key(home.path()).unwrap_err();
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("without following links")
                || rendered.contains("regular file")
                || rendered.contains("safe initialization was refused"),
            "linked key must fail the shared emitter/scanner contract: {rendered}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn lock_wait_does_not_starve_single_worker_runtime() {
        let home = tempfile::tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();

        let lock_path = skills_dir.clone();
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let root = crate::skills::store::open_bound_directory(
                &lock_path,
                false,
                "runtime starvation test skills root",
            )
            .unwrap()
            .unwrap();
            let guard = installer::lock_skill_mutations(&root).unwrap();
            locked_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            drop(guard);
        });
        locked_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("lock holder became ready");

        let runtime_progressed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let progressed = runtime_progressed.clone();
        let release = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(75)).await;
            progressed.store(true, std::sync::atomic::Ordering::SeqCst);
            release_tx.send(()).unwrap();
        });

        tokio::time::timeout(
            Duration::from_secs(2),
            reconcile_pending(home.path(), &skills_dir, None),
        )
        .await
        .expect("reconciliation must not block the only Tokio worker")
        .unwrap();
        release.await.unwrap();
        holder.join().unwrap();
        assert!(
            runtime_progressed.load(std::sync::atomic::Ordering::SeqCst),
            "the current-thread runtime must make progress while the OS lock is held"
        );
    }

    #[tokio::test]
    async fn crc_valid_but_unauthenticated_skill_frame_is_not_mutation_authority() {
        let home = tempfile::tempdir().unwrap();
        let source = home.path().join("incoming-forged");
        let skills_dir = home.path().join("skills");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(
            source.join("skill.yaml"),
            "id: forged_intent\n\
             description: Reject CRC-only evidence\n\
             trigger_keywords: [forged]\n\
             system_prompt: Require authenticated authority.\n",
        )
        .unwrap();
        let mut prepared = installer::prepare_install_from_local_with_expectation(
            &source,
            &skills_dir,
            false,
            None,
            "f0120000f0120000f0120000f0120000",
        )
        .unwrap();
        prepared.mark_intent_submitting().unwrap();
        let binding = prepared.audit_binding();
        drop(prepared);

        let wal_dir = home.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let (writer, join) =
            crate::wal::spawn_for_home(wal_dir.join("000001.wal"), home.path().to_path_buf())
                .unwrap();
        let forged = serde_json::to_vec(&serde_json::json!({
            "operation_id": &binding.operation_id,
            "audit_event_id": binding.intent_audit_event_id(),
            "skill_id": &binding.skill_id,
            "phase": "intent"
        }))
        .unwrap();
        let header =
            crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_EXTENDED, &forged)
                .event_subtype(crate::wal::events::ExtendedSubtype::SkillInstallIntent as u8)
                .build();
        writer.append(header, forged).await.unwrap();
        drop(writer);
        join.await.unwrap();

        let error = scan_skill_mutation_audit(home.path(), &binding).unwrap_err();
        assert!(
            format!("{error:#}").contains("lacks its HMAC-SHA256"),
            "a valid frame CRC must not substitute for authenticated provenance: {error:#}"
        );
        assert!(skills_dir.join(".neoth-skill-mutation.json").exists());
        assert!(!skills_dir.join("forged_intent").exists());
    }

    #[tokio::test]
    async fn two_authenticated_terminal_frames_fail_closed_instead_of_becoming_a_count() {
        let home = tempfile::tempdir().unwrap();
        let source = home.path().join("incoming-duplicate-terminal");
        let skills_dir = home.path().join("skills");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(
            source.join("skill.yaml"),
            "id: duplicate_terminal\n\
             description: Reject duplicate terminal authority\n\
             trigger_keywords: [duplicate]\n\
             system_prompt: Require exactly one terminal.\n",
        )
        .unwrap();
        let wal_dir = home.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let (writer, join) =
            crate::wal::spawn_for_home(wal_dir.join("000001.wal"), home.path().to_path_buf())
                .unwrap();

        let mut prepared = installer::prepare_install_from_local_with_expectation(
            &source,
            &skills_dir,
            false,
            None,
            "d0120000d0120000d0120000d0120000",
        )
        .unwrap();
        prepared.mark_intent_submitting().unwrap();
        let IntentDelivery::Durable(receipt) =
            deliver_intent(home.path(), Some(&writer), &prepared.audit_binding())
                .await
                .unwrap()
        else {
            panic!("intent must be durable");
        };
        prepared.mark_intent_durable_authenticated(receipt).unwrap();
        prepared.commit().unwrap();

        let mut pending = installer::open_pending_skill_mutation_reconciliation(&skills_dir)
            .unwrap()
            .unwrap();
        let terminal = pending.reconcile(true).unwrap().unwrap();
        drop(pending);
        let key = crate::wal::compaction::load_existing_key(&wal_dir.join("hmac.key")).unwrap();
        let payload = skill_mutation_audit_payload(&terminal, true, &key).unwrap();
        for _ in 0..2 {
            let header =
                crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_EXTENDED, &payload)
                    .event_subtype(crate::wal::events::ExtendedSubtype::SkillInstallResult as u8)
                    .build();
            writer.append(header, payload.clone()).await.unwrap();
        }

        let error = scan_skill_mutation_audit(home.path(), &terminal).unwrap_err();
        assert!(format!("{error:#}").contains("more than one authenticated terminal"));
        assert!(skills_dir.join(".neoth-skill-mutation.json").exists());

        drop(writer);
        join.await.unwrap();
    }

    #[tokio::test]
    async fn durable_intent_survives_a_bounded_hmac_key_rotation_archive() {
        let home = tempfile::tempdir().unwrap();
        let source = home.path().join("incoming-key-rotation");
        let skills_dir = home.path().join("skills");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(
            source.join("skill.yaml"),
            "id: rotated_intent\n\
             description: Preserve authenticated predecessor evidence\n\
             trigger_keywords: [rotation]\n\
             system_prompt: Recover across a key rotation.\n",
        )
        .unwrap();
        let mut prepared = installer::prepare_install_from_local_with_expectation(
            &source,
            &skills_dir,
            false,
            None,
            "a0120000a0120000a0120000a0120000",
        )
        .unwrap();
        prepared.mark_intent_submitting().unwrap();
        let binding = prepared.audit_binding();
        drop(prepared);

        let IntentDelivery::Durable(receipt) =
            deliver_intent(home.path(), None, &binding).await.unwrap()
        else {
            panic!("intent must be durable");
        };
        let active = home.path().join("wal/hmac.key");
        std::fs::copy(&active, home.path().join("wal/hmac.key.1.archive")).unwrap();
        crate::wal::compaction::rewrap_key(&active, &[9u8; 32]).unwrap();

        assert_eq!(
            scan_skill_mutation_audit_count(home.path(), &binding, false).unwrap(),
            1
        );
        assert_eq!(receipt.audit_event_id, binding.intent_audit_event_id());
    }

    #[tokio::test]
    async fn cancelled_pre_durability_delivery_keeps_journal_until_exact_frame_arrives() {
        let home = tempfile::tempdir().unwrap();
        let source = home.path().join("incoming");
        let skills_dir = home.path().join("skills");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(
            source.join("skill.yaml"),
            "id: delayed_intent\n\
             description: Delayed durability probe\n\
             trigger_keywords: [delayed]\n\
             system_prompt: Recover the exact operation.\n",
        )
        .unwrap();
        let operation_id = "cafe0000cafe0000cafe0000cafe0000";
        let mut prepared = installer::prepare_install_from_local_with_expectation(
            &source,
            &skills_dir,
            false,
            None,
            operation_id,
        )
        .unwrap();
        prepared.mark_intent_submitting().unwrap();
        let binding = prepared.audit_binding();
        drop(prepared);

        let wal_dir = home.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let (writer, writer_join) = crate::wal::spawn_for_home(
            wal_dir.join("delayed-intent-000001.wal"),
            home.path().to_path_buf(),
        )
        .unwrap();

        // Hold the single WAL task after another frame is durable. The Skill
        // request can enter the writer queue but cannot become durable yet.
        let gate = crate::wal::writer::TestAckGate::once(crate::wal::events::EVENT_TYPE_EXTENDED);
        let blocker_payload = br#"{"blocker":true}"#.to_vec();
        let blocker_header = crate::wal::HeaderBuilder::new(
            crate::wal::events::EVENT_TYPE_EXTENDED,
            &blocker_payload,
        )
        .event_subtype(crate::wal::events::ExtendedSubtype::CommunicationProfileControlled as u8)
        .build();
        let blocker_writer = writer.clone().with_test_ack_gate(gate.clone());
        let blocker =
            tokio::spawn(
                async move { blocker_writer.append(blocker_header, blocker_payload).await },
            );
        tokio::time::timeout(Duration::from_secs(2), gate.wait_until_durable())
            .await
            .expect("blocking frame must reach the deterministic pre-ACK gate");

        let delivery_home = home.path().to_path_buf();
        let delivery_writer = writer.clone();
        let delivery_binding = binding.clone();
        let delivery = tokio::spawn(async move {
            deliver_intent(&delivery_home, Some(&delivery_writer), &delivery_binding).await
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        delivery.abort();
        let _ = delivery.await;

        assert_eq!(
            scan_skill_mutation_audit_count(home.path(), &binding, false).unwrap(),
            0,
            "the blocked Skill frame must not be visible before durability"
        );
        let error = reconcile_pending(home.path(), &skills_dir, Some(&writer))
            .await
            .expect_err("same-process in-flight delivery must retain its journal");
        assert!(
            error.to_string().contains("entered intent delivery"),
            "recovery must expose the bounded pending state: {error:#}"
        );
        assert!(skills_dir.join(".neoth-skill-mutation.json").exists());

        gate.release();
        blocker.await.unwrap().unwrap();
        for _ in 0..100 {
            if scan_skill_mutation_audit_count(home.path(), &binding, false).unwrap() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            scan_skill_mutation_audit_count(home.path(), &binding, false).unwrap(),
            1,
            "the cancelled caller must not cancel its already queued append"
        );

        reconcile_pending(home.path(), &skills_dir, Some(&writer))
            .await
            .expect("later recovery must bind the exact intent and terminal result");
        assert!(!skills_dir.join(".neoth-skill-mutation.json").exists());
        assert!(!skills_dir.join("delayed_intent").exists());

        drop(writer);
        writer_join.await.ok();
    }

    #[tokio::test]
    async fn cancelled_terminal_after_fsync_is_reconciled_without_a_second_terminal() {
        let home = tempfile::tempdir().unwrap();
        let source = home.path().join("incoming-terminal");
        let skills_dir = home.path().join("skills");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(
            source.join("skill.yaml"),
            "id: terminal_cancel\n\
             description: Terminal cancellation probe\n\
             trigger_keywords: [terminal]\n\
             system_prompt: Keep exactly one result.\n",
        )
        .unwrap();
        let wal_dir = home.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let (writer, writer_join) = crate::wal::spawn_for_home(
            wal_dir.join("terminal-cancel-000001.wal"),
            home.path().to_path_buf(),
        )
        .unwrap();

        let mut prepared = installer::prepare_install_from_local_with_expectation(
            &source,
            &skills_dir,
            false,
            None,
            "face0000face0000face0000face0000",
        )
        .unwrap();
        prepared.mark_intent_submitting().unwrap();
        let IntentDelivery::Durable(intent_receipt) =
            deliver_intent(home.path(), Some(&writer), &prepared.audit_binding())
                .await
                .unwrap()
        else {
            panic!("intent must be durable");
        };
        prepared
            .mark_intent_durable_authenticated(intent_receipt)
            .unwrap();
        prepared.commit().unwrap();

        let gate = crate::wal::writer::TestAckGate::once(crate::wal::events::EVENT_TYPE_EXTENDED);
        let gated_writer = writer.clone().with_test_ack_gate(gate.clone());
        let recovery_home = home.path().to_path_buf();
        let recovery_skills = skills_dir.clone();
        let cancelled = tokio::spawn(async move {
            reconcile_pending(&recovery_home, &recovery_skills, Some(&gated_writer)).await
        });
        tokio::time::timeout(Duration::from_secs(2), gate.wait_until_durable())
            .await
            .expect("terminal frame must reach the post-fsync pre-ACK gate");
        cancelled.abort();
        let _ = cancelled.await;

        let pending = installer::open_pending_skill_mutation_reconciliation(&skills_dir)
            .unwrap()
            .unwrap();
        let terminal_binding = pending.audit_binding();
        drop(pending);
        assert_eq!(
            scan_skill_mutation_audit_count(home.path(), &terminal_binding, true).unwrap(),
            1
        );
        reconcile_pending(home.path(), &skills_dir, Some(&writer))
            .await
            .expect("same-process recovery must consume the durable terminal without retrying");
        assert_eq!(
            scan_skill_mutation_audit_count(home.path(), &terminal_binding, true).unwrap(),
            1,
            "terminal cancellation must never create a second result"
        );
        assert!(!skills_dir.join(".neoth-skill-mutation.json").exists());

        gate.release();
        drop(writer);
        writer_join.await.ok();
    }

    fn write_generated_writer_fixture(home: &Path, id: &str, manifest: &str) -> std::path::PathBuf {
        let package = home.join("skills").join(id);
        std::fs::create_dir_all(package.join("assets/nested")).unwrap();
        std::fs::write(package.join("skill.yaml"), manifest).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(
                package.join("skill.yaml"),
                std::fs::Permissions::from_mode(0o640),
            )
            .unwrap();
        }
        std::fs::write(package.join("skill.md"), "original instructions").unwrap();
        std::fs::write(package.join("assets/nested/keep.bin"), b"\0asset\0bytes").unwrap();
        package
    }

    #[tokio::test]
    async fn generated_manifest_writer_preserves_complete_package_and_audits_origin() {
        let home = tempfile::tempdir().unwrap();
        let id = "writer_assets";
        let package = write_generated_writer_fixture(
            home.path(),
            id,
            "id: writer_assets\n\
             description: Original generated writer fixture\n\
             trigger_keywords: [old]\n\
             system_prompt: Original.\n",
        );
        let prior = installer::inspect_installed_target(&home.path().join("skills"), id)
            .unwrap()
            .target_generation_sha256
            .unwrap();
        let replacement = "id: writer_assets\n\
                           description: Replacement generated writer fixture\n\
                           trigger_keywords: [new]\n\
                           system_prompt: Replacement.\n";
        let report = apply_skill_document_mutation(
            home.path(),
            installer::SkillDocumentMutationRequest {
                target_skills_dir: home.path().join("skills"),
                id: id.to_string(),
                document: installer::SkillPackageDocument::Manifest,
                replacement: replacement.as_bytes().to_vec(),
                existing: super::super::creator::ExistingSkillPolicy::Replace,
                expected_target_generation_sha256: Some(Some(prior.clone())),
                expected_document: None,
                origin: installer::SkillMutationOrigin::Teacher,
            },
        )
        .await
        .unwrap();

        assert!(report.replaced_existing);
        assert_eq!(
            report.replaced_generation_sha256.as_deref(),
            Some(prior.as_str())
        );
        assert_eq!(
            std::fs::read(package.join("skill.yaml")).unwrap(),
            replacement.as_bytes()
        );
        assert_eq!(
            std::fs::read_to_string(package.join("skill.md")).unwrap(),
            "original instructions"
        );
        assert_eq!(
            std::fs::read(package.join("assets/nested/keep.bin")).unwrap(),
            b"\0asset\0bytes"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(package.join("skill.yaml"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o640,
                "the overridden package document must retain its source permissions"
            );
        }

        let mut origins = Vec::new();
        crate::wal::scan::for_each_frame_at_home(
            home.path(),
            crate::wal::scan::HomeWalScanLimits::default(),
            |_, frame| {
                if frame.header.event_type == crate::wal::events::EVENT_TYPE_EXTENDED
                    && matches!(
                        frame.header.event_subtype,
                        subtype
                            if subtype
                                == crate::wal::events::ExtendedSubtype::SkillInstallIntent as u8
                                || subtype
                                    == crate::wal::events::ExtendedSubtype::SkillInstallResult as u8
                    )
                {
                    let payload: serde_json::Value = serde_json::from_slice(frame.payload)?;
                    origins.push(payload["origin"].as_str().unwrap_or_default().to_string());
                }
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(origins, vec!["teacher".to_string(), "teacher".to_string()]);
    }

    #[tokio::test]
    async fn keep_if_identical_generated_manifest_is_a_package_noop() {
        let home = tempfile::tempdir().unwrap();
        let manifest = "id: writer_noop\n\
                        description: Exact idempotent writer fixture\n\
                        trigger_keywords: [same]\n\
                        system_prompt: Same.\n";
        let package = write_generated_writer_fixture(home.path(), "writer_noop", manifest);
        let before =
            installer::inspect_installed_target(&home.path().join("skills"), "writer_noop")
                .unwrap()
                .target_generation_sha256
                .unwrap();
        let report = apply_skill_document_mutation(
            home.path(),
            installer::SkillDocumentMutationRequest {
                target_skills_dir: home.path().join("skills"),
                id: "writer_noop".to_string(),
                document: installer::SkillPackageDocument::Manifest,
                replacement: manifest.as_bytes().to_vec(),
                existing: super::super::creator::ExistingSkillPolicy::KeepIfIdentical,
                expected_target_generation_sha256: Some(Some(before.clone())),
                expected_document: None,
                origin: installer::SkillMutationOrigin::ProactiveCurator,
            },
        )
        .await
        .unwrap();

        assert!(!report.replaced_existing);
        assert_eq!(report.source_generation_sha256, before);
        assert!(!home.path().join("wal").exists());
        assert!(
            !home
                .path()
                .join("skills/.neoth-skill-mutation.json")
                .exists()
        );
        assert_eq!(
            std::fs::read(package.join("assets/nested/keep.bin")).unwrap(),
            b"\0asset\0bytes"
        );
    }

    #[tokio::test]
    async fn generated_writer_cannot_audit_one_home_and_mutate_another() {
        let audit_home = tempfile::tempdir().unwrap();
        let target_home = tempfile::tempdir().unwrap();
        let error = apply_skill_document_mutation(
            audit_home.path(),
            installer::SkillDocumentMutationRequest {
                target_skills_dir: target_home.path().join("skills"),
                id: "cross_home".to_string(),
                document: installer::SkillPackageDocument::Manifest,
                replacement: b"id: cross_home\n\
                               description: Must remain home-bound\n\
                               trigger_keywords: []\n\
                               system_prompt: Never publish.\n"
                    .to_vec(),
                existing: super::super::creator::ExistingSkillPolicy::Refuse,
                expected_target_generation_sha256: Some(None),
                expected_document: None,
                origin: installer::SkillMutationOrigin::Teacher,
            },
        )
        .await
        .expect_err("a WAL home must never authorize another installed-Skill store");

        assert!(format!("{error:#}").contains("exact skills store"));
        assert!(!target_home.path().join("skills").exists());
        assert!(!audit_home.path().join("wal").exists());
    }

    #[tokio::test]
    async fn cancelled_generated_writer_intent_recovers_without_publication() {
        let home = tempfile::tempdir().unwrap();
        let id = "writer_cancel";
        let original = "id: writer_cancel\n\
                        description: Cancelled writer fixture\n\
                        trigger_keywords: [old]\n\
                        system_prompt: Original.\n";
        let package = write_generated_writer_fixture(home.path(), id, original);
        let prior = installer::inspect_installed_target(&home.path().join("skills"), id)
            .unwrap()
            .target_generation_sha256
            .unwrap();
        let request = installer::SkillDocumentMutationRequest {
            target_skills_dir: home.path().join("skills"),
            id: id.to_string(),
            document: installer::SkillPackageDocument::Manifest,
            replacement: b"id: writer_cancel\n\
                           description: Must never publish after cancellation\n\
                           trigger_keywords: [new]\n\
                           system_prompt: New.\n"
                .to_vec(),
            existing: super::super::creator::ExistingSkillPolicy::Replace,
            expected_target_generation_sha256: Some(Some(prior)),
            expected_document: None,
            origin: installer::SkillMutationOrigin::ProactiveAccept,
        };
        let installer::PreparedSkillDocumentMutation::Prepared(mut prepared) =
            installer::prepare_skill_document_mutation(
                &request,
                "cafe0000cafe0000cafe0000cafe0000",
            )
            .unwrap()
        else {
            panic!("replacement must prepare a real mutation");
        };
        prepared.mark_intent_submitting().unwrap();
        let IntentDelivery::Durable(_) =
            deliver_intent(home.path(), None, &prepared.audit_binding())
                .await
                .unwrap()
        else {
            panic!("intent must become durable");
        };
        drop(prepared);

        reconcile_pending(home.path(), &home.path().join("skills"), None)
            .await
            .expect("cancelled pre-commit writer must reconcile to aborted");
        assert_eq!(
            std::fs::read(package.join("skill.yaml")).unwrap(),
            original.as_bytes()
        );
        assert_eq!(
            std::fs::read(package.join("assets/nested/keep.bin")).unwrap(),
            b"\0asset\0bytes"
        );
        assert!(
            !home
                .path()
                .join("skills/.neoth-skill-mutation.json")
                .exists()
        );
    }

    #[test]
    fn generated_writer_origins_have_distinct_stable_wire_names() {
        let origins = [
            (installer::SkillMutationOrigin::CliCreate, "cli_create"),
            (
                installer::SkillMutationOrigin::ProactiveAccept,
                "proactive_accept",
            ),
            (
                installer::SkillMutationOrigin::ProactiveCurator,
                "proactive_curator",
            ),
            (installer::SkillMutationOrigin::Teacher, "teacher"),
            (
                installer::SkillMutationOrigin::SelfImproveAccept,
                "self_improve_accept",
            ),
            (
                installer::SkillMutationOrigin::SelfImproveRollback,
                "self_improve_rollback",
            ),
        ];
        let names = origins
            .iter()
            .map(|(origin, expected)| {
                assert_eq!(origin.as_str(), *expected);
                origin.as_str()
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(names.len(), origins.len());
    }
}
