//! Crash-safe WAL delivery and reconciliation for installed-Skill mutations.
//!
//! Every runtime registry load passes through this module before it may observe
//! user-installed Skills. The lifecycle is deliberately independent of the CLI:
//! daemon startup can use its already-open WAL writer, one-shot commands can use
//! the authenticated audit RPC, and an offline process owns a unique home-bound
//! WAL segment.

use std::collections::BTreeMap;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use sha2::{Digest as _, Sha256};

use super::installer::{
    self, SkillMutationAuditBinding, SkillMutationAuditReceipt, SkillMutationKind,
    SkillMutationOrigin, SkillMutationPhase,
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

fn notify_runtime_mutation_transition(
    home: &Path,
    binding: &SkillMutationAuditBinding,
    terminal: bool,
) {
    use super::registry::RuntimeAuthorityTransitionKind;

    let kind = match (binding.kind.is_install(), terminal) {
        (true, false) => RuntimeAuthorityTransitionKind::InstallIntent,
        (true, true) => RuntimeAuthorityTransitionKind::InstallResult,
        (false, false) => RuntimeAuthorityTransitionKind::RemovalIntent,
        (false, true) => RuntimeAuthorityTransitionKind::RemovalResult,
    };
    super::registry::notify_runtime_authority_transition(home, kind);
}

pub(crate) fn receipt_sha256(receipt: &SkillMutationAuditReceipt) -> Result<String> {
    let bytes = serde_json::to_vec(receipt).context("serialize Skill mutation audit receipt")?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

/// Per-Skill mutation-chain reservation copied into the durable journal before
/// an intent can be emitted. Fields are not caller supplied: they are derived
/// from the independently authenticated WAL head while the global Skill
/// mutation lock is held.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SkillMutationIncarnationBinding {
    pub(crate) mutation_sequence: u64,
    pub(crate) previous_terminal_receipt_sha256: Option<String>,
    pub(crate) prior_install_incarnation: Option<u64>,
    pub(crate) resulting_install_incarnation: Option<u64>,
}

/// Opaque proof that one exact package generation is the latest committed
/// installation incarnation in the authenticated mutation WAL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuthenticatedSkillInstallIncarnation {
    skill_id: String,
    package_generation_sha256: String,
    install_incarnation: u64,
    terminal_receipt_sha256: String,
    origin: SkillMutationOrigin,
}

impl AuthenticatedSkillInstallIncarnation {
    pub(crate) fn skill_id(&self) -> &str {
        &self.skill_id
    }

    pub(crate) fn package_generation_sha256(&self) -> &str {
        &self.package_generation_sha256
    }

    pub(crate) fn install_incarnation(&self) -> u64 {
        self.install_incarnation
    }

    pub(crate) fn terminal_receipt_sha256(&self) -> &str {
        &self.terminal_receipt_sha256
    }

    pub(crate) fn origin(&self) -> SkillMutationOrigin {
        self.origin
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct SkillInstallIncarnationState {
    high_water_sequence: u64,
    latest_terminal_receipt_sha256: Option<String>,
    current: Option<AuthenticatedSkillInstallIncarnation>,
    pending_sequence: Option<u64>,
    indeterminate_sequence: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SkillIncarnationWalEvent {
    operation_id: String,
    kind: SkillMutationKind,
    origin: SkillMutationOrigin,
    skill_id: String,
    mutation_sequence: u64,
    previous_terminal_receipt_sha256: Option<String>,
    prior_install_incarnation: Option<u64>,
    resulting_install_incarnation: Option<u64>,
    source_generation_sha256: Option<String>,
    prior_generation_sha256: Option<String>,
    observed_generation_sha256: Option<String>,
    phase: Option<SkillMutationPhase>,
    intent_receipt_sha256: Option<String>,
    receipt: SkillMutationAuditReceipt,
    receipt_sha256: String,
}

#[derive(Clone, Debug, Default)]
struct SkillIncarnationOperation {
    intent: Option<SkillIncarnationWalEvent>,
    terminal: Option<SkillIncarnationWalEvent>,
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
    let incarnation_bound = binding.mutation_sequence.is_some();
    let mut value = serde_json::json!({
        "schema_version": if incarnation_bound { 3 } else { 2 },
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
    });
    if incarnation_bound {
        let object = value
            .as_object_mut()
            .context("canonical Skill mutation payload is not an object")?;
        object.insert(
            "mutation_sequence".to_string(),
            serde_json::to_value(binding.mutation_sequence)
                .context("serialize Skill mutation sequence")?,
        );
        object.insert(
            "previous_terminal_receipt_sha256".to_string(),
            serde_json::to_value(&binding.previous_terminal_receipt_sha256)
                .context("serialize Skill mutation predecessor receipt")?,
        );
        object.insert(
            "prior_install_incarnation".to_string(),
            serde_json::to_value(binding.prior_install_incarnation)
                .context("serialize prior Skill install incarnation")?,
        );
        object.insert(
            "resulting_install_incarnation".to_string(),
            serde_json::to_value(binding.resulting_install_incarnation)
                .context("serialize resulting Skill install incarnation")?,
        );
    }
    Ok(value)
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

fn json_required_string<'a>(payload: &'a serde_json::Value, field: &str) -> Result<&'a str> {
    json_optional_string(payload, field)?
        .with_context(|| format!("Skill mutation WAL field `{field}` is missing"))
}

fn json_optional_u64(payload: &serde_json::Value, field: &str) -> Result<Option<u64>> {
    match payload.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => value.as_u64().map(Some).with_context(|| {
            format!("Skill mutation WAL field `{field}` is not an unsigned integer")
        }),
    }
}

fn json_required_u64(payload: &serde_json::Value, field: &str) -> Result<u64> {
    json_optional_u64(payload, field)?
        .with_context(|| format!("Skill mutation WAL field `{field}` is missing"))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_mutation_kind(value: &str) -> Result<SkillMutationKind> {
    match value {
        "install" => Ok(SkillMutationKind::Install),
        "replace" => Ok(SkillMutationKind::Replace),
        "remove" => Ok(SkillMutationKind::Remove),
        _ => anyhow::bail!("unknown authenticated Skill mutation kind `{value}`"),
    }
}

fn parse_mutation_origin(value: &str) -> Result<SkillMutationOrigin> {
    match value {
        "cli_install" => Ok(SkillMutationOrigin::CliInstall),
        "cli_uninstall" => Ok(SkillMutationOrigin::CliUninstall),
        "cli_create" => Ok(SkillMutationOrigin::CliCreate),
        "proactive_accept" => Ok(SkillMutationOrigin::ProactiveAccept),
        "proactive_curator" => Ok(SkillMutationOrigin::ProactiveCurator),
        "teacher" => Ok(SkillMutationOrigin::Teacher),
        "self_improve_accept" => Ok(SkillMutationOrigin::SelfImproveAccept),
        "self_improve_rollback" => Ok(SkillMutationOrigin::SelfImproveRollback),
        _ => anyhow::bail!("unknown authenticated Skill mutation origin `{value}`"),
    }
}

fn parse_terminal_phase(value: &str) -> Result<SkillMutationPhase> {
    match value {
        "committed" => Ok(SkillMutationPhase::Committed),
        "aborted" => Ok(SkillMutationPhase::Aborted),
        "indeterminate" => Ok(SkillMutationPhase::Indeterminate),
        _ => anyhow::bail!("invalid authenticated Skill mutation terminal phase `{value}`"),
    }
}

fn authenticate_unbound_skill_mutation_payload(
    payload: &[u8],
    observed_subtype: crate::wal::events::ExtendedSubtype,
    keys: &[Vec<u8>],
) -> Result<serde_json::Value> {
    let mut value: serde_json::Value =
        serde_json::from_slice(payload).context("parse Skill mutation WAL payload")?;
    let tag = value
        .as_object_mut()
        .context("Skill mutation WAL payload is not a JSON object")?
        .remove("auth_hmac_sha256")
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .context("Skill mutation WAL payload lacks its HMAC-SHA256 authentication tag")?;
    if !valid_sha256(&tag) {
        anyhow::bail!("Skill mutation WAL authentication tag is not canonical SHA-256 hex");
    }
    let tag = hex::decode(&tag).context("decode Skill mutation WAL authentication tag")?;
    let unsigned =
        serde_json::to_vec(&value).context("serialize candidate unsigned Skill audit payload")?;
    let authenticated = keys.iter().any(|key| {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
        mac.update(SKILL_AUDIT_HMAC_DOMAIN);
        mac.update(&[observed_subtype as u8]);
        mac.update(&unsigned);
        mac.verify_slice(&tag).is_ok()
    });
    if !authenticated {
        anyhow::bail!("Skill mutation WAL payload did not authenticate under any bounded key");
    }
    Ok(value)
}

fn parse_incarnation_event(
    payload: &serde_json::Value,
    observed_subtype: crate::wal::events::ExtendedSubtype,
    terminal: bool,
    receipt: SkillMutationAuditReceipt,
) -> Result<SkillIncarnationWalEvent> {
    if json_required_u64(payload, "schema_version")? != 3 {
        anyhow::bail!("incarnation event does not use Skill mutation schema v3");
    }
    let operation_id = json_required_string(payload, "operation_id")?.to_string();
    if operation_id.len() != 32
        || !operation_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        anyhow::bail!("authenticated Skill mutation operation id is invalid");
    }
    let kind = parse_mutation_kind(json_required_string(payload, "mutation")?)?;
    if skill_mutation_subtype(kind, terminal) != observed_subtype {
        anyhow::bail!("authenticated Skill mutation subtype does not match its payload kind");
    }
    let origin = parse_mutation_origin(json_required_string(payload, "origin")?)?;
    let skill_id = json_required_string(payload, "skill_id")?.to_string();
    super::installer::validate_mutation_skill_id(&skill_id, kind)
        .context("authenticated Skill mutation id is invalid")?;
    if !valid_sha256(json_required_string(payload, "audit_event_id")?) {
        anyhow::bail!("authenticated Skill mutation audit id is invalid");
    }
    let mutation_sequence = json_required_u64(payload, "mutation_sequence")?;
    if mutation_sequence == 0 {
        anyhow::bail!("authenticated Skill mutation sequence must be non-zero");
    }
    let previous_terminal_receipt_sha256 =
        json_optional_string(payload, "previous_terminal_receipt_sha256")?.map(ToOwned::to_owned);
    if previous_terminal_receipt_sha256
        .as_deref()
        .is_some_and(|digest| !valid_sha256(digest))
    {
        anyhow::bail!("authenticated Skill mutation predecessor receipt is invalid");
    }
    match (
        mutation_sequence,
        previous_terminal_receipt_sha256.as_deref(),
    ) {
        (1, None) => {}
        (1, Some(_)) => anyhow::bail!("first Skill mutation must not name a predecessor"),
        (_, Some(_)) => {}
        (_, None) => anyhow::bail!("non-first Skill mutation requires a predecessor receipt"),
    }
    let prior_install_incarnation = json_optional_u64(payload, "prior_install_incarnation")?;
    if prior_install_incarnation
        .is_some_and(|incarnation| incarnation == 0 || incarnation >= mutation_sequence)
    {
        anyhow::bail!("authenticated prior Skill install incarnation is invalid");
    }
    let resulting_install_incarnation =
        json_optional_u64(payload, "resulting_install_incarnation")?;
    match (kind.is_install(), resulting_install_incarnation) {
        (true, Some(incarnation)) if incarnation == mutation_sequence => {}
        (false, None) => {}
        _ => anyhow::bail!(
            "authenticated resulting Skill install incarnation does not match its mutation"
        ),
    }
    let source_generation_sha256 =
        json_optional_string(payload, "source_generation_sha256")?.map(ToOwned::to_owned);
    let prior_generation_sha256 =
        json_optional_string(payload, "prior_generation_sha256")?.map(ToOwned::to_owned);
    let observed_generation_sha256 =
        json_optional_string(payload, "observed_generation_sha256")?.map(ToOwned::to_owned);
    for (label, value) in [
        ("source", source_generation_sha256.as_deref()),
        ("prior", prior_generation_sha256.as_deref()),
        ("observed", observed_generation_sha256.as_deref()),
    ] {
        if value.is_some_and(|digest| !valid_sha256(digest)) {
            anyhow::bail!("authenticated Skill mutation {label} generation is invalid");
        }
    }
    match kind {
        SkillMutationKind::Install
            if source_generation_sha256.is_some() && prior_generation_sha256.is_none() => {}
        SkillMutationKind::Replace
            if source_generation_sha256.is_some() && prior_generation_sha256.is_some() => {}
        SkillMutationKind::Remove
            if source_generation_sha256.is_none() && prior_generation_sha256.is_some() => {}
        _ => anyhow::bail!("authenticated Skill mutation generations do not match its kind"),
    }
    let (phase, intent_receipt_sha256) = if terminal {
        if json_required_u64(payload, "chain_sequence")? != 2 {
            anyhow::bail!("authenticated Skill terminal has an invalid chain sequence");
        }
        let phase = parse_terminal_phase(json_required_string(payload, "phase")?)?;
        if json_required_string(payload, "status")? != phase.as_str() {
            anyhow::bail!("authenticated Skill terminal status/phase mismatch");
        }
        let intent_receipt = json_required_string(payload, "intent_receipt_sha256")?.to_string();
        if !valid_sha256(&intent_receipt) {
            anyhow::bail!("authenticated Skill terminal intent receipt is invalid");
        }
        (Some(phase), Some(intent_receipt))
    } else {
        if json_required_u64(payload, "chain_sequence")? != 1
            || json_required_string(payload, "phase")? != "intent"
            || json_optional_string(payload, "status")?.is_some()
            || json_optional_string(payload, "intent_receipt_sha256")?.is_some()
            || observed_generation_sha256.is_some()
        {
            anyhow::bail!("authenticated Skill intent carries terminal-only state");
        }
        (None, None)
    };
    let receipt_sha256 = receipt_sha256(&receipt)?;
    Ok(SkillIncarnationWalEvent {
        operation_id,
        kind,
        origin,
        skill_id,
        mutation_sequence,
        previous_terminal_receipt_sha256,
        prior_install_incarnation,
        resulting_install_incarnation,
        source_generation_sha256,
        prior_generation_sha256,
        observed_generation_sha256,
        phase,
        intent_receipt_sha256,
        receipt,
        receipt_sha256,
    })
}

fn incarnation_bindings_match(
    intent: &SkillIncarnationWalEvent,
    terminal: &SkillIncarnationWalEvent,
) -> bool {
    intent.operation_id == terminal.operation_id
        && intent.kind == terminal.kind
        && intent.origin == terminal.origin
        && intent.skill_id == terminal.skill_id
        && intent.mutation_sequence == terminal.mutation_sequence
        && intent.previous_terminal_receipt_sha256 == terminal.previous_terminal_receipt_sha256
        && intent.prior_install_incarnation == terminal.prior_install_incarnation
        && intent.resulting_install_incarnation == terminal.resulting_install_incarnation
        && intent.source_generation_sha256 == terminal.source_generation_sha256
        && intent.prior_generation_sha256 == terminal.prior_generation_sha256
}

pub(crate) struct SkillInstallIncarnationIndex {
    states: BTreeMap<String, SkillInstallIncarnationState>,
}

impl SkillInstallIncarnationIndex {
    pub(crate) fn authenticate_current(
        &self,
        skill_id: &str,
        package_generation_sha256: &str,
    ) -> Result<AuthenticatedSkillInstallIncarnation> {
        super::creator::validate_skill_id(skill_id).context("validate Skill incarnation id")?;
        if !valid_sha256(package_generation_sha256) {
            anyhow::bail!("expected Skill package generation is not a SHA-256 digest");
        }
        let state = self.states.get(skill_id).cloned().unwrap_or_default();
        authenticate_current_from_state(state, skill_id, package_generation_sha256)
    }
}

pub(crate) fn scan_skill_install_incarnation_index(
    home: &Path,
) -> Result<SkillInstallIncarnationIndex> {
    #[cfg(test)]
    record_incarnation_index_scan_for_test(home);
    let keys = crate::wal::scan::load_home_hmac_keys(home)?;
    if keys.is_empty() {
        return Ok(SkillInstallIncarnationIndex {
            states: BTreeMap::new(),
        });
    }
    let mut operations_by_skill =
        BTreeMap::<String, BTreeMap<u64, SkillIncarnationOperation>>::new();
    crate::wal::scan::for_each_frame_at_home(
        home,
        crate::wal::scan::supported_home_scan_limits(),
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
            // Authenticate before looking at schema or skill id. Otherwise an
            // attacker could rewrite either discriminator, repair only the CRC,
            // and make the latest incarnation tail disappear from this scan.
            let value = authenticate_unbound_skill_mutation_payload(frame.payload, subtype, &keys)?;
            match json_required_u64(&value, "schema_version")? {
                2 => return Ok(()),
                3 => {}
                version => {
                    anyhow::bail!("unsupported authenticated Skill mutation schema {version}")
                }
            }
            let segment_name = location
                .segment_name
                .to_str()
                .context("canonical WAL segment name is not UTF-8")?
                .to_string();
            let receipt = SkillMutationAuditReceipt {
                audit_event_id: json_required_string(&value, "audit_event_id")?.to_string(),
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
            let event = parse_incarnation_event(&value, subtype, terminal, receipt)?;
            let skill_id = event.skill_id.clone();
            let sequence = event.mutation_sequence;
            let operation = operations_by_skill
                .entry(skill_id.clone())
                .or_default()
                .entry(sequence)
                .or_default();
            let slot = if event.phase.is_some() {
                &mut operation.terminal
            } else {
                &mut operation.intent
            };
            if slot.replace(event).is_some() {
                anyhow::bail!(
                    "Skill `{skill_id}` has duplicate authenticated mutation sequence {sequence}"
                );
            }
            Ok(())
        },
    )?;

    let mut states = BTreeMap::new();
    for (skill_id, operations) in operations_by_skill {
        states.insert(
            skill_id.clone(),
            build_skill_install_incarnation_state(&skill_id, operations)?,
        );
    }
    Ok(SkillInstallIncarnationIndex { states })
}

#[cfg(test)]
fn incarnation_index_scan_counts() -> &'static std::sync::Mutex<BTreeMap<PathBuf, usize>> {
    static COUNTS: std::sync::OnceLock<std::sync::Mutex<BTreeMap<PathBuf, usize>>> =
        std::sync::OnceLock::new();
    COUNTS.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

#[cfg(test)]
fn record_incarnation_index_scan_for_test(home: &Path) {
    let mut counts = incarnation_index_scan_counts()
        .lock()
        .expect("incarnation scan counter lock poisoned");
    *counts.entry(home.to_path_buf()).or_default() += 1;
}

#[cfg(test)]
pub(crate) fn incarnation_index_scan_count_for_test(home: &Path) -> usize {
    incarnation_index_scan_counts()
        .lock()
        .expect("incarnation scan counter lock poisoned")
        .get(home)
        .copied()
        .unwrap_or_default()
}

fn build_skill_install_incarnation_state(
    skill_id: &str,
    operations: BTreeMap<u64, SkillIncarnationOperation>,
) -> Result<SkillInstallIncarnationState> {
    let mut state = SkillInstallIncarnationState::default();
    for (sequence, operation) in operations {
        if state.pending_sequence.is_some() || state.indeterminate_sequence.is_some() {
            anyhow::bail!(
                "Skill `{skill_id}` mutation chain continues past a non-terminal operation"
            );
        }
        let expected_sequence = state
            .high_water_sequence
            .checked_add(1)
            .context("Skill mutation sequence overflow")?;
        if sequence != expected_sequence {
            anyhow::bail!(
                "Skill `{skill_id}` mutation chain skips from {} to {sequence}",
                state.high_water_sequence
            );
        }
        let intent = operation.intent.with_context(|| {
            format!("Skill `{skill_id}` mutation {sequence} has a terminal without its intent")
        })?;
        if intent.previous_terminal_receipt_sha256 != state.latest_terminal_receipt_sha256 {
            anyhow::bail!(
                "Skill `{skill_id}` mutation {sequence} does not extend the authenticated terminal head"
            );
        }
        let current_incarnation = state
            .current
            .as_ref()
            .map(AuthenticatedSkillInstallIncarnation::install_incarnation);
        if intent.prior_install_incarnation != current_incarnation {
            anyhow::bail!(
                "Skill `{skill_id}` mutation {sequence} does not consume the current install incarnation"
            );
        }
        let Some(terminal) = operation.terminal else {
            state.high_water_sequence = sequence;
            state.pending_sequence = Some(sequence);
            continue;
        };
        if !incarnation_bindings_match(&intent, &terminal)
            || terminal.intent_receipt_sha256.as_deref() != Some(intent.receipt_sha256.as_str())
        {
            anyhow::bail!(
                "Skill `{skill_id}` mutation {sequence} terminal does not bind its exact intent"
            );
        }
        if !same_segment_terminal_is_after_intent(&intent.receipt, &terminal.receipt) {
            anyhow::bail!(
                "Skill `{skill_id}` mutation {sequence} terminal is not physically after its intent"
            );
        }
        let phase = terminal
            .phase
            .context("authenticated Skill terminal unexpectedly lacks a phase")?;
        state.high_water_sequence = sequence;
        state.latest_terminal_receipt_sha256 = Some(terminal.receipt_sha256.clone());
        match phase {
            SkillMutationPhase::Committed if terminal.kind.is_install() => {
                let generation = terminal
                    .observed_generation_sha256
                    .as_deref()
                    .context("committed Skill installation lacks its observed generation")?;
                if Some(generation) != terminal.source_generation_sha256.as_deref() {
                    anyhow::bail!(
                        "committed Skill installation generation differs from its authenticated source"
                    );
                }
                state.current = Some(AuthenticatedSkillInstallIncarnation {
                    skill_id: skill_id.to_string(),
                    package_generation_sha256: generation.to_string(),
                    install_incarnation: terminal
                        .resulting_install_incarnation
                        .context("committed Skill installation lacks its incarnation")?,
                    terminal_receipt_sha256: terminal.receipt_sha256,
                    origin: terminal.origin,
                });
            }
            SkillMutationPhase::Committed if terminal.kind == SkillMutationKind::Remove => {
                if terminal.observed_generation_sha256.is_some() {
                    anyhow::bail!("committed Skill removal still observes a public generation");
                }
                state.current = None;
            }
            SkillMutationPhase::Aborted => {}
            SkillMutationPhase::Indeterminate => {
                state.indeterminate_sequence = Some(sequence);
                state.current = None;
            }
            _ => anyhow::bail!("non-terminal phase entered Skill incarnation history"),
        }
    }
    Ok(state)
}

fn scan_skill_install_incarnation_state(
    home: &Path,
    skill_id: &str,
    kind: SkillMutationKind,
) -> Result<SkillInstallIncarnationState> {
    super::installer::validate_mutation_skill_id(skill_id, kind)
        .context("validate Skill incarnation id")?;
    Ok(scan_skill_install_incarnation_index(home)?
        .states
        .get(skill_id)
        .cloned()
        .unwrap_or_default())
}

pub(crate) fn prepare_skill_mutation_incarnation(
    skills_dir: &Path,
    skill_id: &str,
    kind: SkillMutationKind,
) -> Result<SkillMutationIncarnationBinding> {
    let home = skills_dir.parent().with_context(|| {
        format!(
            "installed Skill directory {} has no instance-home parent",
            skills_dir.display()
        )
    })?;
    load_or_init_skill_mutation_audit_key(home)
        .context("initialize authenticated Skill incarnation key")?;
    let state = scan_skill_install_incarnation_state(home, skill_id, kind)?;
    if let Some(sequence) = state.pending_sequence {
        anyhow::bail!(
            "Skill `{skill_id}` mutation {sequence} is still pending; reconcile it before another mutation"
        );
    }
    if let Some(sequence) = state.indeterminate_sequence {
        anyhow::bail!(
            "Skill `{skill_id}` mutation {sequence} is indeterminate; refuse a new incarnation"
        );
    }
    let mutation_sequence = state
        .high_water_sequence
        .checked_add(1)
        .context("Skill mutation sequence overflow")?;
    Ok(SkillMutationIncarnationBinding {
        mutation_sequence,
        previous_terminal_receipt_sha256: state.latest_terminal_receipt_sha256,
        prior_install_incarnation: state
            .current
            .as_ref()
            .map(AuthenticatedSkillInstallIncarnation::install_incarnation),
        resulting_install_incarnation: kind.is_install().then_some(mutation_sequence),
    })
}

#[cfg(test)]
pub(crate) fn authenticate_current_install_incarnation(
    home: &Path,
    skill_id: &str,
    package_generation_sha256: &str,
) -> Result<AuthenticatedSkillInstallIncarnation> {
    super::creator::validate_skill_id(skill_id).context("validate Skill incarnation id")?;
    if !valid_sha256(package_generation_sha256) {
        anyhow::bail!("expected Skill package generation is not a SHA-256 digest");
    }
    let state = scan_skill_install_incarnation_state(home, skill_id, SkillMutationKind::Install)?;
    authenticate_current_from_state(state, skill_id, package_generation_sha256)
}

fn authenticate_current_from_state(
    state: SkillInstallIncarnationState,
    skill_id: &str,
    package_generation_sha256: &str,
) -> Result<AuthenticatedSkillInstallIncarnation> {
    if let Some(sequence) = state.pending_sequence {
        anyhow::bail!(
            "Skill `{skill_id}` mutation {sequence} is pending; no current authority is admissible"
        );
    }
    if let Some(sequence) = state.indeterminate_sequence {
        anyhow::bail!(
            "Skill `{skill_id}` mutation {sequence} is indeterminate; no current authority is admissible"
        );
    }
    let current = state
        .current
        .context("installed Skill has no authenticated current install incarnation")?;
    if current.skill_id != skill_id
        || current.package_generation_sha256 != package_generation_sha256
    {
        anyhow::bail!("authenticated Skill install incarnation targets a different package");
    }
    Ok(current)
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
        crate::wal::scan::supported_home_scan_limits(),
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

#[cfg(test)]
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

fn load_or_init_skill_mutation_audit_key(home: &Path) -> Result<Vec<u8>> {
    Ok(load_or_init_skill_mutation_audit_authority(home)?.active_key)
}

fn load_or_init_skill_mutation_audit_authority(
    home: &Path,
) -> Result<crate::cli::security::HmacWriterAuthority> {
    let key_path = home.join("wal").join("hmac.key");
    crate::cli::security::acquire_hmac_writer_authority(home, &key_path)
}

async fn load_or_init_skill_mutation_audit_authority_async(
    home: &Path,
) -> Result<crate::cli::security::HmacWriterAuthority> {
    let home = home.to_path_buf();
    tokio::task::spawn_blocking(move || load_or_init_skill_mutation_audit_authority(&home))
        .await
        .context("join capability-bound Skill mutation HMAC-authority load")?
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
    // Retain the shared writer authority from signing through the durable ACK.
    // This both coexists with an active daemon writer and prevents a key
    // rotation from invalidating the signed payload before it is appended.
    let hmac_authority = match load_or_init_skill_mutation_audit_authority_async(home).await {
        Ok(authority) => authority,
        Err(error) => {
            return AuditDeliveryAttempt::DefinitelyNotRecorded(
                error.context("load instance-bound Skill mutation audit key"),
            );
        }
    };
    let payload = match skill_mutation_audit_payload(binding, terminal, &hmac_authority.active_key)
    {
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
        notify_runtime_mutation_transition(home, binding, false);
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
        notify_runtime_mutation_transition(home, binding, false);
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
        notify_runtime_mutation_transition(home, binding, true);
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
        notify_runtime_mutation_transition(home, binding, true);
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
        installer::PreparedSkillDocumentMutation::Prepared(prepared) => *prepared,
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
fn test_incarnation_binding(
    home: &Path,
    skill_id: &str,
    kind: SkillMutationKind,
    origin: SkillMutationOrigin,
    source_generation_sha256: Option<String>,
) -> Result<SkillMutationAuditBinding> {
    let state = scan_skill_install_incarnation_state(home, skill_id, kind)?;
    if state.pending_sequence.is_some() || state.indeterminate_sequence.is_some() {
        anyhow::bail!("test incarnation mutation cannot extend a non-terminal head");
    }
    let mutation_sequence = state
        .high_water_sequence
        .checked_add(1)
        .context("test Skill mutation sequence overflow")?;
    let prior = state.current.as_ref();
    Ok(SkillMutationAuditBinding {
        operation_id: uuid::Uuid::now_v7().simple().to_string(),
        kind,
        origin,
        skill_id: skill_id.to_string(),
        mutation_sequence: Some(mutation_sequence),
        previous_terminal_receipt_sha256: state.latest_terminal_receipt_sha256,
        prior_install_incarnation: prior
            .map(AuthenticatedSkillInstallIncarnation::install_incarnation),
        resulting_install_incarnation: kind.is_install().then_some(mutation_sequence),
        source_generation_sha256,
        prior_generation_sha256: prior.map(|proof| proof.package_generation_sha256().to_string()),
        prior_object_identity_sha256: if kind.is_install() && prior.is_some() {
            Some("a".repeat(64))
        } else {
            None
        },
        intent_receipt: None,
        commit_boundary_sha256: None,
        phase: SkillMutationPhase::Prepared,
        observed_generation_sha256: None,
        error_sha256: None,
        created_at_unix: crate::time::now_unix_i64(),
    })
}

#[cfg(test)]
async fn append_test_incarnation_mutation(
    home: &Path,
    skill_id: &str,
    kind: SkillMutationKind,
    origin: SkillMutationOrigin,
    source_generation_sha256: Option<String>,
    phase: SkillMutationPhase,
) -> Result<()> {
    let mut binding =
        test_incarnation_binding(home, skill_id, kind, origin, source_generation_sha256)?;
    let prior_generation_sha256 = binding.prior_generation_sha256.clone();
    let IntentDelivery::Durable(intent_receipt) = deliver_intent(home, None, &binding).await?
    else {
        anyhow::bail!("test Skill mutation intent was not durable");
    };
    binding.intent_receipt = Some(intent_receipt);
    binding.commit_boundary_sha256 = Some("b".repeat(64));
    binding.phase = phase;
    binding.observed_generation_sha256 = match (phase, kind.is_install()) {
        (SkillMutationPhase::Committed, true) => binding.source_generation_sha256.clone(),
        (SkillMutationPhase::Aborted, _) => prior_generation_sha256,
        _ => None,
    };
    deliver_terminal_once(home, None, &binding).await?;
    Ok(())
}

#[cfg(test)]
async fn append_test_pending_install_incarnation(
    home: &Path,
    skill_id: &str,
    source_generation_sha256: String,
    origin: SkillMutationOrigin,
) -> Result<()> {
    let binding = test_incarnation_binding(
        home,
        skill_id,
        SkillMutationKind::Replace,
        origin,
        Some(source_generation_sha256),
    )?;
    let IntentDelivery::Durable(_) = deliver_intent(home, None, &binding).await? else {
        anyhow::bail!("test Skill mutation intent was not durable");
    };
    Ok(())
}

#[cfg(test)]
pub(crate) fn record_committed_install_incarnation_for_test(
    home: &Path,
    skill_id: &str,
    package_generation_sha256: &str,
    origin: SkillMutationOrigin,
) -> Result<()> {
    let home = home.to_path_buf();
    let skill_id = skill_id.to_string();
    let generation = package_generation_sha256.to_string();
    std::thread::Builder::new()
        .name("neoth-test-skill-incarnation".to_string())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("build test Skill incarnation runtime")?;
            let state =
                scan_skill_install_incarnation_state(&home, &skill_id, SkillMutationKind::Install)?;
            let kind = if state.current.is_some() {
                SkillMutationKind::Replace
            } else {
                SkillMutationKind::Install
            };
            runtime.block_on(append_test_incarnation_mutation(
                &home,
                &skill_id,
                kind,
                origin,
                Some(generation),
                SkillMutationPhase::Committed,
            ))
        })
        .context("spawn test Skill incarnation writer")?
        .join()
        .map_err(|_| anyhow::anyhow!("test Skill incarnation writer panicked"))?
}

#[cfg(test)]
pub(crate) fn record_committed_removal_incarnation_for_test(
    home: &Path,
    skill_id: &str,
    origin: SkillMutationOrigin,
) -> Result<()> {
    let home = home.to_path_buf();
    let skill_id = skill_id.to_string();
    std::thread::Builder::new()
        .name("neoth-test-skill-removal-incarnation".to_string())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("build test Skill removal-incarnation runtime")?;
            runtime.block_on(append_test_incarnation_mutation(
                &home,
                &skill_id,
                SkillMutationKind::Remove,
                origin,
                None,
                SkillMutationPhase::Committed,
            ))
        })
        .context("spawn test Skill removal-incarnation writer")?
        .join()
        .map_err(|_| anyhow::anyhow!("test Skill removal-incarnation writer panicked"))?
}

#[cfg(test)]
async fn recv_runtime_transition_for_test(
    subscriber: &mut super::registry::RuntimeAuthorityTransitionTestSubscriber,
    home: &Path,
) -> super::registry::RuntimeAuthorityTransitionKind {
    let expected_home = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let (observed_home, kind) = subscriber.recv().await.unwrap();
            if observed_home == expected_home {
                return kind;
            }
        }
    })
    .await
    .expect("durable Skill mutation did not emit a runtime transition")
}

#[cfg(test)]
pub(crate) fn record_pending_install_incarnation_for_test(
    home: &Path,
    skill_id: &str,
    package_generation_sha256: &str,
    origin: SkillMutationOrigin,
) -> Result<()> {
    let home = home.to_path_buf();
    let skill_id = skill_id.to_string();
    let generation = package_generation_sha256.to_string();
    std::thread::Builder::new()
        .name("neoth-test-skill-pending-incarnation".to_string())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("build test pending Skill incarnation runtime")?;
            runtime.block_on(append_test_pending_install_incarnation(
                &home, &skill_id, generation, origin,
            ))
        })
        .context("spawn test pending Skill incarnation writer")?
        .join()
        .map_err(|_| anyhow::anyhow!("test pending Skill incarnation writer panicked"))?
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

        let emitter_error = load_or_init_skill_mutation_audit_key(home.path()).unwrap_err();
        let scanner_error = crate::wal::scan::load_home_hmac_keys(home.path()).unwrap_err();
        for error in [&emitter_error, &scanner_error] {
            assert_eq!(
                error
                    .root_cause()
                    .downcast_ref::<std::io::Error>()
                    .map(std::io::Error::kind),
                Some(std::io::ErrorKind::InvalidData),
                "oversized HMAC key must fail through the bounded-reader contract: {error:#}"
            );
        }
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

    #[tokio::test]
    async fn direct_writer_ack_notifies_intent_and_terminal_before_continuation() {
        let home = tempfile::tempdir().unwrap();
        let wal_dir = home.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let (writer, join) = crate::wal::spawn_for_home(
            wal_dir.join("skill-direct-test-000001.wal"),
            home.path().to_path_buf(),
        )
        .unwrap();
        let mut transitions =
            super::super::registry::subscribe_runtime_authority_transitions_for_test();
        let generation = "c1".repeat(32);
        let mut binding = test_incarnation_binding(
            home.path(),
            "direct_signal",
            SkillMutationKind::Install,
            SkillMutationOrigin::CliInstall,
            Some(generation.clone()),
        )
        .unwrap();

        let IntentDelivery::Durable(intent_receipt) =
            deliver_intent(home.path(), Some(&writer), &binding)
                .await
                .unwrap()
        else {
            panic!("direct writer did not durably ACK the intent");
        };
        assert_eq!(
            recv_runtime_transition_for_test(&mut transitions, home.path()).await,
            super::super::registry::RuntimeAuthorityTransitionKind::InstallIntent
        );

        binding.intent_receipt = Some(intent_receipt);
        binding.commit_boundary_sha256 = Some("d2".repeat(32));
        binding.phase = SkillMutationPhase::Committed;
        binding.observed_generation_sha256 = Some(generation);
        deliver_terminal_once(home.path(), Some(&writer), &binding)
            .await
            .unwrap();
        assert_eq!(
            recv_runtime_transition_for_test(&mut transitions, home.path()).await,
            super::super::registry::RuntimeAuthorityTransitionKind::InstallResult
        );

        drop(writer);
        join.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn standalone_ack_notifies_but_pre_ack_failure_stays_silent() {
        let home = tempfile::tempdir().unwrap();
        let mut transitions =
            super::super::registry::subscribe_runtime_authority_transitions_for_test();
        let failed = test_incarnation_binding(
            home.path(),
            "failed_signal",
            SkillMutationKind::Install,
            SkillMutationOrigin::CliInstall,
            Some("e3".repeat(32)),
        )
        .unwrap();
        fail_next_skill_audit_deliveries(1);
        assert!(matches!(
            deliver_intent(home.path(), None, &failed).await.unwrap(),
            IntentDelivery::DefinitelyNotRecorded(_)
        ));
        let expected_home =
            std::fs::canonicalize(home.path()).unwrap_or_else(|_| home.path().to_path_buf());
        while let Ok((observed_home, _)) = transitions.try_recv() {
            assert_ne!(
                observed_home, expected_home,
                "a pre-durability failure must not wake its runtime"
            );
        }

        let durable = test_incarnation_binding(
            home.path(),
            "standalone_signal",
            SkillMutationKind::Install,
            SkillMutationOrigin::CliInstall,
            Some("f4".repeat(32)),
        )
        .unwrap();
        assert!(matches!(
            deliver_intent(home.path(), None, &durable).await.unwrap(),
            IntentDelivery::Durable(_)
        ));
        assert_eq!(
            recv_runtime_transition_for_test(&mut transitions, home.path()).await,
            super::super::registry::RuntimeAuthorityTransitionKind::InstallIntent
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
    async fn explicit_identical_replace_advances_install_incarnation() {
        let home = tempfile::tempdir().unwrap();
        let manifest = "id: writer_reinstall\n\
                        description: Explicit reinstall fixture\n\
                        trigger_keywords: [same]\n\
                        system_prompt: Same.\n";
        write_generated_writer_fixture(home.path(), "writer_reinstall", manifest);
        let before =
            installer::inspect_installed_target(&home.path().join("skills"), "writer_reinstall")
                .unwrap()
                .target_generation_sha256
                .unwrap();
        record_committed_install_incarnation_for_test(
            home.path(),
            "writer_reinstall",
            &before,
            SkillMutationOrigin::CliInstall,
        )
        .unwrap();

        let report = apply_skill_document_mutation(
            home.path(),
            installer::SkillDocumentMutationRequest {
                target_skills_dir: home.path().join("skills"),
                id: "writer_reinstall".to_string(),
                document: installer::SkillPackageDocument::Manifest,
                replacement: manifest.as_bytes().to_vec(),
                existing: super::super::creator::ExistingSkillPolicy::Replace,
                expected_target_generation_sha256: Some(Some(before.clone())),
                expected_document: None,
                origin: installer::SkillMutationOrigin::SelfImproveRollback,
            },
        )
        .await
        .unwrap();

        assert!(report.replaced_existing);
        assert_eq!(report.source_generation_sha256, before);
        let proof =
            authenticate_current_install_incarnation(home.path(), "writer_reinstall", &before)
                .unwrap();
        assert_eq!(proof.install_incarnation(), 2);
        assert_eq!(proof.origin(), SkillMutationOrigin::SelfImproveRollback);
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
        let installer::PreparedSkillDocumentMutation::Prepared(prepared) =
            installer::prepare_skill_document_mutation(
                &request,
                "cafe0000cafe0000cafe0000cafe0000",
            )
            .unwrap()
        else {
            panic!("replacement must prepare a real mutation");
        };
        let mut prepared = *prepared;
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
    fn install_incarnations_are_monotonic_across_identical_rollback_and_reinstall() {
        let home = tempfile::tempdir().unwrap();
        let generation_zero = "a".repeat(64);
        let generation_one = "b".repeat(64);
        record_committed_install_incarnation_for_test(
            home.path(),
            "alpha",
            &generation_zero,
            SkillMutationOrigin::CliInstall,
        )
        .unwrap();
        let first =
            authenticate_current_install_incarnation(home.path(), "alpha", &generation_zero)
                .unwrap();
        assert_eq!(first.install_incarnation(), 1);
        assert!(
            authenticate_current_install_incarnation(home.path(), "beta", &generation_zero)
                .is_err(),
            "an authenticated receipt is package-id scoped"
        );

        record_committed_install_incarnation_for_test(
            home.path(),
            "alpha",
            &generation_one,
            SkillMutationOrigin::SelfImproveAccept,
        )
        .unwrap();
        assert!(
            authenticate_current_install_incarnation(home.path(), "alpha", &generation_zero)
                .is_err(),
            "a stale generation cannot reuse its prior receipt"
        );
        record_committed_install_incarnation_for_test(
            home.path(),
            "alpha",
            &generation_zero,
            SkillMutationOrigin::SelfImproveRollback,
        )
        .unwrap();
        let rollback =
            authenticate_current_install_incarnation(home.path(), "alpha", &generation_zero)
                .unwrap();
        assert_eq!(rollback.install_incarnation(), 3);
        assert_ne!(
            rollback.terminal_receipt_sha256(),
            first.terminal_receipt_sha256()
        );

        record_committed_removal_incarnation_for_test(
            home.path(),
            "alpha",
            SkillMutationOrigin::CliUninstall,
        )
        .unwrap();
        assert!(
            authenticate_current_install_incarnation(home.path(), "alpha", &generation_zero)
                .is_err()
        );
        record_committed_install_incarnation_for_test(
            home.path(),
            "alpha",
            &generation_zero,
            SkillMutationOrigin::CliInstall,
        )
        .unwrap();
        let reinstalled =
            authenticate_current_install_incarnation(home.path(), "alpha", &generation_zero)
                .unwrap();
        assert_eq!(reinstalled.install_incarnation(), 5);
        assert_ne!(
            reinstalled.terminal_receipt_sha256(),
            rollback.terminal_receipt_sha256()
        );
    }

    #[test]
    fn pending_replacement_suspends_the_prior_install_incarnation() {
        let home = tempfile::tempdir().unwrap();
        let generation_zero = "a".repeat(64);
        let generation_one = "b".repeat(64);
        record_committed_install_incarnation_for_test(
            home.path(),
            "alpha",
            &generation_zero,
            SkillMutationOrigin::CliInstall,
        )
        .unwrap();
        record_pending_install_incarnation_for_test(
            home.path(),
            "alpha",
            &generation_one,
            SkillMutationOrigin::SelfImproveAccept,
        )
        .unwrap();

        let error =
            authenticate_current_install_incarnation(home.path(), "alpha", &generation_zero)
                .unwrap_err();
        assert!(format!("{error:#}").contains("pending"));
        assert!(
            prepare_skill_mutation_incarnation(
                &home.path().join("skills"),
                "alpha",
                SkillMutationKind::Replace
            )
            .is_err(),
            "no later operation may extend a pending incarnation"
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

    #[test]
    fn legacy_directory_name_is_admissible_only_for_authenticated_removal() {
        let legacy = "legacy skill.β";
        assert!(
            crate::skills::installer::validate_mutation_skill_id(legacy, SkillMutationKind::Remove)
                .is_ok()
        );
        assert!(
            crate::skills::installer::validate_mutation_skill_id(
                legacy,
                SkillMutationKind::Install
            )
            .is_err()
        );
        assert!(
            crate::skills::installer::validate_mutation_skill_id(
                legacy,
                SkillMutationKind::Replace
            )
            .is_err()
        );
        assert!(
            crate::skills::installer::validate_mutation_skill_id(
                "../escape",
                SkillMutationKind::Remove
            )
            .is_err()
        );
    }
}
