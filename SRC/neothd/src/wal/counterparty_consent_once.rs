//! Closed W209 counterparty-consent WAL descriptors and durable receipts.
//!
//! The public writer surface accepts these descriptors only through its
//! append-once APIs.  Their fields stay private so a generic WAL frame cannot
//! be re-labelled as an authenticated ceremony proof.

use anyhow::{Result, ensure};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::wal::{EventFlags, HeaderBuilder, WalSessionContext};

use super::events::{EVENT_TYPE_EXTENDED, ExtendedSubtype};
use super::header::EventHeaderV2;

const INPUT_DOMAIN: &[u8] = b"neoth/w209/counterparty-consent/input/v1\0";
const AUDIT_DOMAIN: &[u8] = b"neoth/w209/counterparty-consent/audit/v1\0";
const MAX_CEREMONY_PAYLOAD_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CounterpartyConsentOnceError {
    #[error("counterparty_consent_once_conflict")]
    Conflict,
    #[error("counterparty_consent_once_duplicate")]
    Duplicate,
    #[error("counterparty_consent_once_indeterminate")]
    Indeterminate,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct InputPayload<'a> {
    schema_version: u8,
    channel_id: &'a str,
    account_id: &'a str,
    scoped_sender_hash: &'a str,
    conversation_sha256: String,
    input_sha256: String,
}

#[derive(Clone)]
pub(crate) struct CounterpartyConsentInputDescriptor {
    header: EventHeaderV2,
    payload: Vec<u8>,
    channel_ref: crate::channels::registry::ChannelRef,
    scoped_sender_hash: String,
    conversation_sha256: [u8; 32],
    wal_session_id: [u8; 16],
    input_sha256: [u8; 32],
}

impl std::fmt::Debug for CounterpartyConsentInputDescriptor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CounterpartyConsentInputDescriptor([sealed])")
    }
}

impl CounterpartyConsentInputDescriptor {
    /// Build only from the accepted channel envelope and its private binding.
    /// The descriptor derives all durable scope values itself; no caller can
    /// substitute a free channel reference, sender hash, or conversation hash.
    pub(crate) fn from_admitted_input(
        admitted: &crate::cli::serve_pipeline::AdmittedCounterpartyConsentInput,
    ) -> Result<Self> {
        let binding = admitted.binding();
        let inbound = admitted.inbound();
        let wal_session = admitted.wal_session();
        let exact_command = admitted.exact_command();
        ensure!(inbound.channel == binding.channel_ref.channel_id, "W209 admitted channel binding");
        ensure!(!exact_command.is_empty() && exact_command.len() <= 512, "W209 command bound");
        let channel_ref = binding.channel_ref.clone();
        let scoped_sender_hash = crate::cli::serve_pipeline::scoped_sender_hash_of(binding, &inbound.sender_id);
        ensure!(
            !scoped_sender_hash.is_empty() && scoped_sender_hash.len() <= 128,
            "W209 scoped sender hash bounds"
        );
        let conversation_sha256 = conversation_sha256(binding, inbound)?;
        let input_sha256: [u8; 32] = Sha256::digest(exact_command).into();
        let payload = serde_json::to_vec(&InputPayload {
            schema_version: 1,
            channel_id: channel_ref.channel_id.as_str(),
            account_id: channel_ref.account_id.as_str(),
            scoped_sender_hash: &scoped_sender_hash,
            conversation_sha256: hex::encode(conversation_sha256),
            input_sha256: hex::encode(input_sha256),
        })?;
        ensure!(payload.len() <= MAX_CEREMONY_PAYLOAD_BYTES, "W209 input payload bound");
        let header = HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
            .event_subtype(ExtendedSubtype::CounterpartyConsentInput as u8)
            .flags(EventFlags::SYNTHETIC)
            .session_context(Some(wal_session))
            .build();
        Ok(Self {
            header,
            payload,
            channel_ref,
            scoped_sender_hash,
            conversation_sha256,
            wal_session_id: *wal_session.header_id().as_bytes(),
            input_sha256,
        })
    }

    pub(crate) fn header(&self) -> EventHeaderV2 { self.header }
    pub(crate) fn payload(&self) -> Vec<u8> { self.payload.clone() }
    fn receipt(&self, event_id: i64) -> CounterpartyConsentInputReceipt {
        CounterpartyConsentInputReceipt {
            channel_ref: self.channel_ref.clone(),
            scoped_sender_hash: self.scoped_sender_hash.clone(),
            conversation_sha256: self.conversation_sha256,
            event_id,
            wal_session_id: self.wal_session_id,
            input_sha256: self.input_sha256,
        }
    }

    #[cfg(test)]
    pub(crate) fn conflicting_test_descriptor(&self) -> Self {
        let mut payload = self.payload.clone();
        payload.push(b' ');
        let mut header = HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
            .event_subtype(ExtendedSubtype::CounterpartyConsentInput as u8)
            .flags(EventFlags::SYNTHETIC)
            .build();
        header.event_id = self.header.event_id;
        header.hlc = self.header.hlc;
        header.session_id = self.header.session_id;
        Self {
            header,
            payload,
            channel_ref: self.channel_ref.clone(),
            scoped_sender_hash: self.scoped_sender_hash.clone(),
            conversation_sha256: self.conversation_sha256,
            wal_session_id: self.wal_session_id,
            input_sha256: self.input_sha256,
        }
    }
}

fn conversation_sha256(
    binding: &crate::cli::serve_pipeline::AuthenticatedInboundBinding,
    inbound: &crate::channels::InboundMessage,
) -> Result<[u8; 32]> {
    let fields = [
        binding.channel_ref.channel_id.as_str().as_bytes(),
        binding.channel_ref.account_id.as_str().as_bytes(),
        inbound.chat_id.as_bytes(),
        inbound.thread_id.as_deref().map_or(&[][..], str::as_bytes),
        inbound.sender_id.as_bytes(),
    ];
    let size = fields.iter().try_fold(b"neoth/w209/conversation/v1\0".len(), |total, field| {
        total.checked_add(8).and_then(|value| value.checked_add(field.len()))
            .ok_or_else(|| anyhow::anyhow!("W209 conversation identity overflow"))
    })?;
    ensure!(size <= crate::wal::MAX_ADMITTED_IDENTITY_BYTES, "W209 conversation identity bound");
    let mut hasher = Sha256::new();
    hasher.update(b"neoth/w209/conversation/v1\0");
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    Ok(hasher.finalize().into())
}

#[derive(Clone)]
pub(crate) struct CounterpartyConsentAuditDescriptor {
    header: EventHeaderV2,
    payload: Vec<u8>,
    operation_id: String,
    action: String,
    payload_sha256: [u8; 32],
}

impl std::fmt::Debug for CounterpartyConsentAuditDescriptor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CounterpartyConsentAuditDescriptor([sealed])")
    }
}

impl CounterpartyConsentAuditDescriptor {
    /// The ceremony core owns `CeremonyAuditPayload`; this entrypoint accepts
    /// only that opaque plan and revalidates its canonical JSON before a WAL
    /// header is minted.
    pub(crate) fn from_ceremony_payload(
        payload: crate::memory::counterparty_consent_ceremony::CeremonyAuditPayload,
        wal_session: WalSessionContext,
    ) -> Result<Self> {
        Self::from_ceremony_payload_with_session_id(payload, *wal_session.header_id().as_bytes())
    }

    /// Recovery can inherit an existing sealed input receipt's session id but
    /// cannot mint or inspect a `WalSessionContext` from raw adapter data.
    pub(crate) fn from_recovered_ceremony_payload(
        payload: crate::memory::counterparty_consent_ceremony::CeremonyAuditPayload,
        input_receipt: &CounterpartyConsentInputReceipt,
    ) -> Result<Self> {
        Self::from_ceremony_payload_with_session_id(payload, input_receipt.wal_session_id)
    }

    fn from_ceremony_payload_with_session_id(
        payload: crate::memory::counterparty_consent_ceremony::CeremonyAuditPayload,
        wal_session_id: [u8; 16],
    ) -> Result<Self> {
        let bytes = payload.canonical_bytes()?;
        ensure!(bytes.len() <= MAX_CEREMONY_PAYLOAD_BYTES, "W209 audit payload bound");
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        let object = value.as_object().ok_or_else(|| anyhow::anyhow!("W209 audit payload object"))?;
        let required = [
            "schema_version", "operation_id", "action", "channel_id", "account_id",
            "scoped_sender_hash", "evidence_sha256", "input_receipt_event_id",
            "input_sha256", "baseline_consent_state", "baseline_consent_revision",
        ];
        ensure!(
            object.len() == required.len() && required.iter().all(|key| object.contains_key(*key)),
            "W209 audit payload fields"
        );
        let operation_id = object.get("operation_id").and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("W209 audit operation id"))?.to_owned();
        let action = object.get("action").and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("W209 audit action"))?.to_owned();
        ensure!(operation_id.len() == 32 && operation_id.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()), "W209 audit operation id canonical");
        let subtype = match action.as_str() {
            "verified_grant" => ExtendedSubtype::CounterpartyConsentGrant,
            "counterparty_revoke" => ExtendedSubtype::CounterpartyConsentRevoked,
            _ => anyhow::bail!("W209 audit action"),
        };
        let payload_sha256 = tagged_sha256(AUDIT_DOMAIN, &bytes);
        let mut header = HeaderBuilder::new(EVENT_TYPE_EXTENDED, &bytes)
            .event_subtype(subtype as u8)
            .flags(EventFlags::SYNTHETIC)
            .build();
        header.session_id = crate::wal::SessionId::from_bytes(wal_session_id);
        Ok(Self { header, payload: bytes, operation_id, action, payload_sha256 })
    }

    pub(crate) fn header(&self) -> EventHeaderV2 { self.header }
    pub(crate) fn payload(&self) -> Vec<u8> { self.payload.clone() }
    fn receipt(&self, event_id: i64) -> CounterpartyConsentAuditReceipt {
        CounterpartyConsentAuditReceipt { operation_id: self.operation_id.clone(), action: self.action.clone(), event_id, payload_sha256: self.payload_sha256 }
    }
}

/// Opaque successful durable input acknowledgement. There is no constructor
/// outside this module and no serde implementation.
#[derive(Clone, Debug)]
pub(crate) struct CounterpartyConsentInputReceipt {
    channel_ref: crate::channels::registry::ChannelRef,
    scoped_sender_hash: String,
    conversation_sha256: [u8; 32],
    event_id: i64,
    wal_session_id: [u8; 16],
    input_sha256: [u8; 32],
}
impl CounterpartyConsentInputReceipt {
    pub(crate) fn channel_ref(&self) -> &ChannelRef { &self.channel_ref }
    pub(crate) fn scoped_sender_hash(&self) -> &str { &self.scoped_sender_hash }
    pub(crate) const fn conversation_sha256(&self) -> [u8; 32] { self.conversation_sha256 }
    pub(crate) const fn event_id(&self) -> i64 { self.event_id }
    pub(crate) const fn wal_session_id(&self) -> [u8; 16] { self.wal_session_id }
    pub(crate) const fn input_sha256(&self) -> [u8; 32] { self.input_sha256 }
}

/// Opaque successful durable audit acknowledgement.
#[derive(Clone, Debug)]
pub(crate) struct CounterpartyConsentAuditReceipt {
    operation_id: String,
    action: String,
    event_id: i64,
    payload_sha256: [u8; 32],
}
impl CounterpartyConsentAuditReceipt {
    pub(crate) fn operation_id(&self) -> &str { &self.operation_id }
    pub(crate) fn action(&self) -> &str { &self.action }
    pub(crate) const fn event_id(&self) -> i64 { self.event_id }
    pub(crate) const fn payload_sha256(&self) -> [u8; 32] { self.payload_sha256 }
}

pub(crate) fn tagged_sha256(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

#[derive(Clone)]
pub(crate) enum CounterpartyConsentDescriptor {
    Input(CounterpartyConsentInputDescriptor),
    Audit(CounterpartyConsentAuditDescriptor),
}
impl CounterpartyConsentDescriptor {
    pub(crate) fn header(&self) -> EventHeaderV2 { match self { Self::Input(value) => value.header(), Self::Audit(value) => value.header() } }
    pub(crate) fn payload(&self) -> Vec<u8> { match self { Self::Input(value) => value.payload(), Self::Audit(value) => value.payload() } }
    fn receipt(&self, event_id: i64) -> CounterpartyConsentDurability { match self { Self::Input(value) => CounterpartyConsentDurability::Input(value.receipt(event_id)), Self::Audit(value) => CounterpartyConsentDurability::Audit(value.receipt(event_id)) } }
}

#[derive(Clone, Debug)]
pub(crate) enum CounterpartyConsentDurability {
    Input(CounterpartyConsentInputReceipt),
    Audit(CounterpartyConsentAuditReceipt),
}

pub(crate) enum Lookup {
    Exact(CounterpartyConsentDurability),
    AbsentComplete,
    Conflict,
    Duplicate,
    Indeterminate,
}

pub(crate) fn lookup_exact_at_home(home: &std::path::Path, expected: &CounterpartyConsentDescriptor) -> Lookup {
    let header = expected.header();
    let payload = expected.payload();
    let mut count = 0usize;
    let mut conflict = false;
    let scan = super::scan::for_each_authenticated_prefix_frame_at_home(
        home,
        super::scan::supported_home_scan_limits(),
        |_, frame| {
            if frame.header.event_type == EVENT_TYPE_EXTENDED
                && frame.header.event_id == header.event_id
                && frame.header.hlc == header.hlc
            {
                if frame.header == header && frame.payload == payload.as_slice() {
                    count = count.saturating_add(1);
                } else {
                    conflict = true;
                }
            }
            Ok(())
        },
    );
    let Ok(scan) = scan else { return Lookup::Indeterminate; };
    if conflict { Lookup::Conflict }
    else if count > 1 { Lookup::Duplicate }
    else if count == 1 {
        match i64::try_from(header.event_id.0) {
            Ok(event_id) if event_id > 0 => Lookup::Exact(expected.receipt(event_id)),
            _ => Lookup::Indeterminate,
        }
    } else if scan.complete { Lookup::AbsentComplete }
    else { Lookup::Indeterminate }
}

/// Rehydrate an input capability only from a marker-authenticated primary-WAL
/// frame with the exact receipt id and command digest. Recovery never accepts a
/// generic frame, a matching audit subtype, or an unbounded payload.
pub(crate) fn input_receipt_at_home(
    home: &std::path::Path,
    event_id: i64,
    input_sha256: [u8; 32],
) -> std::result::Result<Option<CounterpartyConsentInputReceipt>, CounterpartyConsentOnceError> {
    if event_id <= 0 { return Err(CounterpartyConsentOnceError::Indeterminate); }
    let mut found = None;
    let mut count = 0usize;
    let scan = super::scan::for_each_authenticated_prefix_frame_at_home(
        home,
        super::scan::supported_home_scan_limits(),
        |_, frame| {
            if frame.header.event_type != EVENT_TYPE_EXTENDED
                || frame.header.event_subtype != ExtendedSubtype::CounterpartyConsentInput as u8
                || i64::try_from(frame.header.event_id.0).ok() != Some(event_id)
            { return Ok(()); }
            if frame.payload.len() > MAX_CEREMONY_PAYLOAD_BYTES { return Err(anyhow::anyhow!("W209 input payload bound")); }
            let value: serde_json::Value = serde_json::from_slice(frame.payload)?;
            let object = value.as_object().ok_or_else(|| anyhow::anyhow!("W209 input payload object"))?;
            let channel = object.get("channel_id").and_then(serde_json::Value::as_str).ok_or_else(|| anyhow::anyhow!("W209 input channel"))?;
            let account = object.get("account_id").and_then(serde_json::Value::as_str).ok_or_else(|| anyhow::anyhow!("W209 input account"))?;
            let sender = object.get("scoped_sender_hash").and_then(serde_json::Value::as_str).ok_or_else(|| anyhow::anyhow!("W209 input sender"))?;
            let conversation = decode_sha256(object.get("conversation_sha256").and_then(serde_json::Value::as_str))?;
            let observed_input = decode_sha256(object.get("input_sha256").and_then(serde_json::Value::as_str))?;
            if observed_input != input_sha256 { return Ok(()); }
            let channel_id = crate::channels::registry::resolve_channel_id(channel).ok_or_else(|| anyhow::anyhow!("W209 input unknown channel"))?;
            let account_id = account.parse().map_err(|_| anyhow::anyhow!("W209 input account canonical"))?;
            let session = *frame.header.session_id.as_bytes();
            found = Some(CounterpartyConsentInputReceipt {
                channel_ref: crate::channels::registry::ChannelRef::new(channel_id, account_id),
                scoped_sender_hash: sender.to_owned(), conversation_sha256: conversation,
                event_id, wal_session_id: session, input_sha256,
            });
            count = count.saturating_add(1);
            Ok(())
        },
    ).map_err(|_| CounterpartyConsentOnceError::Indeterminate)?;
    if !scan.complete { return Err(CounterpartyConsentOnceError::Indeterminate); }
    if count > 1 { return Err(CounterpartyConsentOnceError::Duplicate); }
    Ok(found)
}

fn decode_sha256(value: Option<&str>) -> Result<[u8; 32]> {
    let value = value.ok_or_else(|| anyhow::anyhow!("W209 digest missing"))?;
    let bytes = hex::decode(value)?;
    ensure!(bytes.len() == 32 && hex::encode(&bytes) == value, "W209 digest canonical");
    let mut output = [0_u8; 32]; output.copy_from_slice(&bytes); Ok(output)
}
