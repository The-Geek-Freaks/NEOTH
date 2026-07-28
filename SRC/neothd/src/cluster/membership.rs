//! Authoritative cluster membership, stable node identity, and carrier binding.
//!
//! `cluster_passphrase` is deliberately absent from this module. It remains a
//! rendezvous/bootstrap proof, never an authorization source. Every effectful
//! cluster path must hold a [`MembershipGrant`] issued from this store.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, Weak};

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use rusqlite::{Connection, OptionalExtension as _, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const AUTHORITY_SCHEMA_VERSION: i64 = 4;
pub const MEMBERSHIP_SNAPSHOT_VERSION: u16 = 1;
pub const MEMBERSHIP_SNAPSHOT_WIRE_VERSION: u16 = 1;
pub const MEMBERSHIP_SNAPSHOT_OPERATION: &str = "cluster.membership.snapshot";
pub const MEMBERSHIP_REVOCATION_STATUS_OPERATION: &str = "cluster.membership.revoke_status";
pub const MEMBERSHIP_RUNTIME_HEALTH_WIRE_VERSION: u16 = 1;
const LOCAL_IDENTITY_VERSION: u16 = 1;
const ATTESTATION_PROTOCOL_VERSION: u16 = 2;
const LOCAL_IDENTITY_FILE: &str = "cluster-node-identity.json";
const LOCAL_IDENTITY_LOCK: &str = "cluster-node-identity.lock";
const AUTHORITY_DB_FILE: &str = "cluster-membership.db";

pub fn validate_revocation_request_id(value: &str) -> Result<()> {
    let parsed = uuid::Uuid::parse_str(value).context("revocation request id is not a UUID")?;
    anyhow::ensure!(
        parsed.to_string() == value,
        "revocation request id is not canonical"
    );
    anyhow::ensure!(
        parsed.get_version_num() == 7,
        "revocation request id is not UUIDv7"
    );
    Ok(())
}

pub fn new_revocation_request_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StableNodeId(String);

impl StableNodeId {
    pub fn from_verifying_key(key: &VerifyingKey) -> Self {
        Self(hex::encode(key.to_bytes()))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let decoded = hex::decode(&value).context("stable node id is not hexadecimal")?;
        anyhow::ensure!(
            decoded.len() == 32 && value.len() == 64 && value == value.to_ascii_lowercase(),
            "stable node id must be 32-byte lowercase hex"
        );
        Ok(Self(value))
    }

    fn from_legacy_transport(transport: &TransportIdentity) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"neoth-legacy-unattested-v1\0");
        digest.update(transport.as_str().as_bytes());
        Self(hex::encode(digest.finalize()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for StableNodeId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CarrierKind {
    Peeroxide,
    Iroh,
}

impl CarrierKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Peeroxide => "peeroxide",
            Self::Iroh => "iroh",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "peeroxide" => Ok(Self::Peeroxide),
            "iroh" => Ok(Self::Iroh),
            other => anyhow::bail!("unknown membership carrier `{other}`"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TransportIdentity(String);

impl TransportIdentity {
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        anyhow::ensure!(!value.is_empty(), "transport identity is empty");
        anyhow::ensure!(
            value.len() <= 512,
            "transport identity exceeds 512-byte limit"
        );
        anyhow::ensure!(
            value.trim() == value,
            "transport identity contains surrounding whitespace"
        );
        anyhow::ensure!(
            !value.chars().any(char::is_control),
            "transport identity contains control characters"
        );
        Ok(Self(value))
    }

    pub fn peeroxide(public_key: &[u8; 32]) -> Self {
        Self(hex::encode(public_key))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TransportIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct AuthEpoch(u64);

impl AuthEpoch {
    pub const INITIAL: Self = Self(1);

    pub fn new(value: u64) -> Result<Self> {
        anyhow::ensure!(value > 0, "auth epoch must be positive");
        Ok(Self(value))
    }

    pub fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> Result<Self> {
        self.0
            .checked_add(1)
            .map(Self)
            .context("auth epoch exhausted")
    }
}

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct MembershipEpoch(u64);

impl MembershipEpoch {
    pub const INITIAL: Self = Self(1);

    pub fn new(value: u64) -> Result<Self> {
        anyhow::ensure!(value > 0, "membership epoch must be positive");
        Ok(Self(value))
    }

    pub fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> Result<Self> {
        self.0
            .checked_add(1)
            .map(Self)
            .context("membership epoch exhausted")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BootId(String);

impl BootId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let parsed = uuid::Uuid::parse_str(&value).context("boot id is not a UUID")?;
        Ok(Self(parsed.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for BootId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipState {
    Discovered,
    Pending,
    Active,
    Revoked,
}

impl MembershipState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Discovered => "discovered",
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "discovered" => Ok(Self::Discovered),
            "pending" => Ok(Self::Pending),
            "active" => Ok(Self::Active),
            "revoked" => Ok(Self::Revoked),
            other => anyhow::bail!("unknown membership state `{other}`"),
        }
    }
}

#[derive(Clone)]
pub struct LocalNodeIdentity {
    signing_seed: [u8; 32],
    peeroxide_seed: [u8; 32],
    stable_node_id: StableNodeId,
}

impl std::fmt::Debug for LocalNodeIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalNodeIdentity")
            .field("stable_node_id", &self.stable_node_id)
            .field("signing_seed", &"<redacted>")
            .field("peeroxide_seed", &"<redacted>")
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalIdentityRecord {
    version: u16,
    signing_seed: [u8; 32],
    peeroxide_seed: [u8; 32],
}

impl LocalNodeIdentity {
    pub fn load_existing(home: &Path) -> Result<Option<Self>> {
        let path = home.join(LOCAL_IDENTITY_FILE);
        match std::fs::read(&path) {
            Ok(body) => {
                let record = serde_json::from_slice::<LocalIdentityRecord>(&body)
                    .with_context(|| format!("parse stable node identity {}", path.display()))?;
                Ok(Some(Self::from_record(record)?))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => {
                Err(error).with_context(|| format!("read stable node identity {}", path.display()))
            }
        }
    }

    pub fn load_or_create(home: &Path) -> Result<Self> {
        std::fs::create_dir_all(home)
            .with_context(|| format!("create NEOTH home {}", home.display()))?;
        let path = home.join(LOCAL_IDENTITY_FILE);
        let _lock = crate::util::locked_file::lock_file_blocking(
            &home.join(LOCAL_IDENTITY_LOCK),
            "cluster stable node identity",
        )?;
        let record = match std::fs::read(&path) {
            Ok(body) => serde_json::from_slice::<LocalIdentityRecord>(&body)
                .with_context(|| format!("parse stable node identity {}", path.display()))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut signing_seed = [0_u8; 32];
                let mut peeroxide_seed = [0_u8; 32];
                getrandom::getrandom(&mut signing_seed)
                    .context("mint stable node signing seed from OS RNG")?;
                getrandom::getrandom(&mut peeroxide_seed)
                    .context("mint stable peeroxide seed from OS RNG")?;
                let record = LocalIdentityRecord {
                    version: LOCAL_IDENTITY_VERSION,
                    signing_seed,
                    peeroxide_seed,
                };
                let body = serde_json::to_vec(&record).context("serialize stable node identity")?;
                crate::util::atomic_write::atomic_write_private(&path, &body)
                    .with_context(|| format!("persist stable node identity {}", path.display()))?;
                record
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("read stable node identity {}", path.display()));
            }
        };
        Self::from_record(record)
    }

    fn from_record(record: LocalIdentityRecord) -> Result<Self> {
        anyhow::ensure!(
            record.version == LOCAL_IDENTITY_VERSION,
            "unsupported stable node identity version {}",
            record.version
        );
        anyhow::ensure!(
            record.signing_seed.iter().any(|byte| *byte != 0)
                && record.peeroxide_seed.iter().any(|byte| *byte != 0)
                && record.signing_seed != record.peeroxide_seed,
            "stable node identity contains invalid or reused key material"
        );
        let signing_key = SigningKey::from_bytes(&record.signing_seed);
        let carrier_public = peeroxide::KeyPair::from_seed(record.peeroxide_seed).public_key;
        anyhow::ensure!(
            carrier_public != signing_key.verifying_key().to_bytes(),
            "stable node and peeroxide carrier identities must use distinct keys"
        );
        Ok(Self {
            stable_node_id: StableNodeId::from_verifying_key(&signing_key.verifying_key()),
            signing_seed: record.signing_seed,
            peeroxide_seed: record.peeroxide_seed,
        })
    }

    pub fn stable_node_id(&self) -> &StableNodeId {
        &self.stable_node_id
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        SigningKey::from_bytes(&self.signing_seed).verifying_key()
    }

    pub fn peeroxide_key_pair(&self) -> peeroxide::KeyPair {
        peeroxide::KeyPair::from_seed(self.peeroxide_seed)
    }

    pub fn attest_endpoint(
        &self,
        carrier: CarrierKind,
        transport_identity: TransportIdentity,
        boot_id: BootId,
        runtime_id: String,
        endpoint: String,
        auth_epoch: AuthEpoch,
        proof_membership_epoch: MembershipEpoch,
        invitation_digest: Option<String>,
        expires_at_unix: i64,
    ) -> Result<EndpointAttestation> {
        anyhow::ensure!(!runtime_id.trim().is_empty(), "runtime id is empty");
        anyhow::ensure!(!endpoint.trim().is_empty(), "endpoint is empty");
        let mut attestation = EndpointAttestation {
            protocol_version: ATTESTATION_PROTOCOL_VERSION,
            stable_node_id: self.stable_node_id.clone(),
            signing_public_key: self.verifying_key().to_bytes(),
            carrier,
            transport_identity,
            boot_id,
            runtime_id,
            endpoint,
            auth_epoch,
            proof_membership_epoch,
            invitation_digest,
            expires_at_unix,
            signature: Vec::new(),
        };
        let bytes = attestation.signable_bytes()?;
        attestation.signature = SigningKey::from_bytes(&self.signing_seed)
            .sign(&bytes)
            .to_bytes()
            .to_vec();
        Ok(attestation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointAttestation {
    pub protocol_version: u16,
    pub stable_node_id: StableNodeId,
    pub signing_public_key: [u8; 32],
    pub carrier: CarrierKind,
    pub transport_identity: TransportIdentity,
    pub boot_id: BootId,
    pub runtime_id: String,
    pub endpoint: String,
    pub auth_epoch: AuthEpoch,
    pub proof_membership_epoch: MembershipEpoch,
    pub invitation_digest: Option<String>,
    pub expires_at_unix: i64,
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
struct SignableEndpointAttestation<'a> {
    protocol_version: u16,
    stable_node_id: &'a StableNodeId,
    signing_public_key: &'a [u8; 32],
    carrier: CarrierKind,
    transport_identity: &'a TransportIdentity,
    boot_id: &'a BootId,
    runtime_id: &'a str,
    endpoint: &'a str,
    auth_epoch: AuthEpoch,
    proof_membership_epoch: MembershipEpoch,
    invitation_digest: &'a Option<String>,
    expires_at_unix: i64,
}

impl EndpointAttestation {
    fn signable_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&SignableEndpointAttestation {
            protocol_version: self.protocol_version,
            stable_node_id: &self.stable_node_id,
            signing_public_key: &self.signing_public_key,
            carrier: self.carrier,
            transport_identity: &self.transport_identity,
            boot_id: &self.boot_id,
            runtime_id: &self.runtime_id,
            endpoint: &self.endpoint,
            auth_epoch: self.auth_epoch,
            proof_membership_epoch: self.proof_membership_epoch,
            invitation_digest: &self.invitation_digest,
            expires_at_unix: self.expires_at_unix,
        })
        .context("serialize endpoint attestation")
    }

    pub fn verify_exact(
        &self,
        carrier: CarrierKind,
        authenticated_transport: &TransportIdentity,
        endpoint: &str,
        now_unix: i64,
    ) -> Result<()> {
        anyhow::ensure!(
            self.protocol_version == ATTESTATION_PROTOCOL_VERSION,
            "unsupported endpoint attestation protocol version {}",
            self.protocol_version
        );
        anyhow::ensure!(
            self.expires_at_unix > now_unix,
            "endpoint attestation expired"
        );
        anyhow::ensure!(
            self.carrier == carrier,
            "endpoint attestation carrier mismatch"
        );
        anyhow::ensure!(
            &self.transport_identity == authenticated_transport,
            "endpoint attestation transport identity mismatch"
        );
        anyhow::ensure!(
            self.endpoint == endpoint,
            "endpoint attestation endpoint mismatch"
        );
        let key = VerifyingKey::from_bytes(&self.signing_public_key)
            .context("invalid attestation signing key")?;
        anyhow::ensure!(
            self.stable_node_id == StableNodeId::from_verifying_key(&key),
            "attestation stable node id does not match signing key"
        );
        let signature_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .context("attestation signature must be 64 bytes")?;
        let signature = Signature::from_bytes(&signature_bytes);
        key.verify(&self.signable_bytes()?, &signature)
            .context("endpoint attestation signature invalid")
    }

    fn digest(&self) -> Result<String> {
        let mut digest = Sha256::new();
        digest.update(self.signable_bytes()?);
        digest.update(&self.signature);
        Ok(hex::encode(digest.finalize()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarrierBindingSnapshot {
    pub carrier: CarrierKind,
    pub transport_identity: TransportIdentity,
    pub endpoint: String,
    pub assurance: String,
    pub auth_epoch: AuthEpoch,
    pub membership_epoch: MembershipEpoch,
    pub expires_at_unix: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberSnapshot {
    pub stable_node_id: StableNodeId,
    pub label: String,
    pub state: MembershipState,
    pub auth_epoch: AuthEpoch,
    pub membership_epoch: MembershipEpoch,
    pub tombstoned: bool,
    pub bindings: Vec<CarrierBindingSnapshot>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipSnapshot {
    pub version: u16,
    pub authority_path: PathBuf,
    pub authority_epoch: MembershipEpoch,
    pub revocation_floor: MembershipEpoch,
    pub pending_outbox: u64,
    pub members: Vec<MemberSnapshot>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipSnapshotEnvelope {
    pub wire_version: u16,
    pub operation: String,
    pub snapshot_version: u16,
    pub snapshot_digest: String,
    pub snapshot: MembershipSnapshot,
}

impl MembershipSnapshot {
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.version == MEMBERSHIP_SNAPSHOT_VERSION,
            "unsupported membership snapshot version"
        );
        anyhow::ensure!(
            !self.authority_path.as_os_str().is_empty(),
            "membership snapshot authority path is empty"
        );
        MembershipEpoch::new(self.authority_epoch.get())
            .context("membership snapshot authority epoch is invalid")?;
        MembershipEpoch::new(self.revocation_floor.get())
            .context("membership snapshot revocation floor is invalid")?;
        anyhow::ensure!(
            self.revocation_floor <= self.authority_epoch,
            "membership snapshot revocation floor exceeds authority epoch"
        );

        let mut member_ids = HashSet::with_capacity(self.members.len());
        for member in &self.members {
            StableNodeId::parse(member.stable_node_id.as_str().to_string())
                .context("membership snapshot stable node id is invalid")?;
            AuthEpoch::new(member.auth_epoch.get())
                .context("membership snapshot member auth epoch is invalid")?;
            MembershipEpoch::new(member.membership_epoch.get())
                .context("membership snapshot member membership epoch is invalid")?;
            anyhow::ensure!(
                !member.label.trim().is_empty(),
                "membership snapshot member label is empty"
            );
            anyhow::ensure!(
                member.membership_epoch <= self.authority_epoch,
                "membership snapshot member epoch exceeds authority epoch"
            );
            anyhow::ensure!(
                member.tombstoned == (member.state == MembershipState::Revoked),
                "membership snapshot tombstone/state mismatch"
            );
            anyhow::ensure!(
                member.state != MembershipState::Active || !member.bindings.is_empty(),
                "active membership snapshot has no carrier binding"
            );
            anyhow::ensure!(
                member_ids.insert(member.stable_node_id.clone()),
                "membership snapshot contains duplicate stable node id"
            );

            let mut carriers = HashSet::with_capacity(member.bindings.len());
            for binding in &member.bindings {
                TransportIdentity::parse(binding.transport_identity.as_str().to_string())
                    .context("membership snapshot transport identity is invalid")?;
                AuthEpoch::new(binding.auth_epoch.get())
                    .context("membership snapshot binding auth epoch is invalid")?;
                MembershipEpoch::new(binding.membership_epoch.get())
                    .context("membership snapshot binding membership epoch is invalid")?;
                anyhow::ensure!(
                    carriers.insert(binding.carrier),
                    "membership snapshot contains duplicate carrier binding"
                );
                anyhow::ensure!(
                    !binding.endpoint.trim().is_empty()
                        && binding.endpoint.trim() == binding.endpoint
                        && !binding.endpoint.chars().any(char::is_control),
                    "membership snapshot binding endpoint is invalid"
                );
                anyhow::ensure!(
                    matches!(
                        binding.assurance.as_str(),
                        "signed_attestation" | "legacy_unattested"
                    ),
                    "membership snapshot binding assurance is invalid"
                );
                if member.state == MembershipState::Active {
                    anyhow::ensure!(
                        binding.assurance == "signed_attestation"
                            && binding.auth_epoch == member.auth_epoch
                            && binding.membership_epoch == member.membership_epoch,
                        "active membership snapshot binding is not authority-exact"
                    );
                } else {
                    anyhow::ensure!(
                        binding.auth_epoch <= member.auth_epoch
                            && binding.membership_epoch <= member.membership_epoch,
                        "inactive membership snapshot binding exceeds member generation"
                    );
                }
            }
        }
        Ok(())
    }

    pub fn canonical_digest(&self) -> Result<String> {
        let bytes =
            serde_json::to_vec(self).context("serialize canonical membership snapshot digest")?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    pub fn into_envelope(self) -> Result<MembershipSnapshotEnvelope> {
        self.validate()?;
        let snapshot_digest = self.canonical_digest()?;
        Ok(MembershipSnapshotEnvelope {
            wire_version: MEMBERSHIP_SNAPSHOT_WIRE_VERSION,
            operation: MEMBERSHIP_SNAPSHOT_OPERATION.to_string(),
            snapshot_version: self.version,
            snapshot_digest,
            snapshot: self,
        })
    }
}

impl MembershipSnapshotEnvelope {
    pub fn from_json(json: &str) -> Result<Self> {
        let envelope = serde_json::from_str::<Self>(json)
            .context("parse membership snapshot envelope JSON")?;
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.wire_version == MEMBERSHIP_SNAPSHOT_WIRE_VERSION,
            "unsupported membership wire version"
        );
        anyhow::ensure!(
            self.operation == MEMBERSHIP_SNAPSHOT_OPERATION,
            "unsupported membership snapshot operation"
        );
        anyhow::ensure!(
            self.snapshot_version == self.snapshot.version,
            "membership snapshot version envelope mismatch"
        );
        anyhow::ensure!(
            self.snapshot_digest.len() == 64
                && self
                    .snapshot_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "membership snapshot digest is not lowercase SHA-256"
        );
        self.snapshot.validate()?;
        anyhow::ensure!(
            self.snapshot_digest == self.snapshot.canonical_digest()?,
            "membership snapshot digest mismatch"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipAuthorityHealth {
    pub schema_version: i64,
    pub integrity: String,
    pub active: u64,
    pub pending: u64,
    pub expired_active: u64,
    pub legacy_unattested: u64,
    pub active_without_valid_binding: u64,
    pub floor_projection_mismatch: bool,
    pub pending_outbox: u64,
    pub pending_teardown: u64,
    pub pending_audit: u64,
    pub pending_revocations: u64,
    pub indeterminate_revocations: u64,
    pub expired_invites: u64,
    pub local_identity_valid: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveMembershipKind {
    Route,
    Network,
    QueuedProvider,
    ExternalPermit,
    InflightProvider,
    DurableCommit,
}

impl LiveMembershipKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Route => "route",
            Self::Network => "network",
            Self::QueuedProvider => "queued_provider",
            Self::ExternalPermit => "external_permit",
            Self::InflightProvider => "inflight_provider",
            Self::DurableCommit => "durable_commit",
        }
    }
}

impl std::fmt::Display for LiveMembershipKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveMembershipGeneration {
    pub stable_node_id: StableNodeId,
    pub carrier: CarrierKind,
    pub auth_epoch: AuthEpoch,
    pub membership_epoch: MembershipEpoch,
    pub kind: LiveMembershipKind,
}

fn compare_live_membership_generations(
    left: &LiveMembershipGeneration,
    right: &LiveMembershipGeneration,
) -> std::cmp::Ordering {
    left.stable_node_id
        .cmp(&right.stable_node_id)
        .then(left.carrier.cmp(&right.carrier))
        .then(left.auth_epoch.cmp(&right.auth_epoch))
        .then(left.membership_epoch.cmp(&right.membership_epoch))
        .then(left.kind.as_str().cmp(right.kind.as_str()))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipRuntimeHealth {
    pub wire_version: u16,
    pub live_generations: Vec<LiveMembershipGeneration>,
    pub invalid_live_generations: Vec<LiveMembershipGeneration>,
    pub unresolved_revocations: Vec<RevocationIntentStatus>,
}

pub fn inspect_authority_read_only(
    home: &Path,
    now_unix: i64,
) -> Result<Option<MembershipAuthorityHealth>> {
    let path = home.join(AUTHORITY_DB_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let flags =
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(&path, flags)
        .with_context(|| format!("open membership authority read-only {}", path.display()))?;
    let integrity: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    let schema_version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let count = |sql: &str| -> Result<u64> { Ok(conn.query_row(sql, [], |row| row.get(0))?) };
    let active = count("SELECT COUNT(*) FROM members WHERE state='active'")?;
    let pending = count("SELECT COUNT(*) FROM members WHERE state='pending'")?;
    let expired_active = conn.query_row(
        "SELECT COUNT(*) FROM members m WHERE m.state='active' AND NOT EXISTS(
             SELECT 1 FROM transport_bindings b WHERE b.stable_node_id=m.stable_node_id
               AND b.assurance='signed_attestation'
               AND b.auth_epoch=m.auth_epoch AND b.membership_epoch=m.membership_epoch
               AND (b.expires_at IS NULL OR b.expires_at>?1)
         )",
        [now_unix],
        |row| row.get(0),
    )?;
    let legacy_unattested =
        count("SELECT COUNT(*) FROM transport_bindings WHERE assurance='legacy_unattested'")?;
    let active_without_valid_binding = expired_active;
    let floor_projection_mismatch: bool = conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM members m,authority_meta a
             WHERE a.singleton=1 AND (
               (m.state='active' AND (m.membership_epoch!=a.membership_epoch OR
                                     m.membership_epoch<a.revocation_floor)) OR
               (m.state='revoked' AND NOT EXISTS(
                   SELECT 1 FROM revocation_tombstones t
                   WHERE t.stable_node_id=m.stable_node_id
                     AND t.auth_epoch=m.auth_epoch
               )) OR
               (m.state!='revoked' AND EXISTS(
                   SELECT 1 FROM revocation_tombstones t
                   WHERE t.stable_node_id=m.stable_node_id
                     AND t.auth_epoch=m.auth_epoch
               ))
             )
         )",
        [],
        |row| row.get(0),
    )?;
    let pending_outbox =
        count("SELECT COUNT(*) FROM membership_outbox WHERE delivered_at IS NULL")?;
    let pending_teardown = count(
        "SELECT COUNT(*) FROM membership_outbox
         WHERE delivered_at IS NULL AND kind='teardown'",
    )?;
    let pending_audit = count(
        "SELECT COUNT(*) FROM membership_outbox
         WHERE delivered_at IS NULL AND kind='audit'",
    )?;
    let (pending_revocations, indeterminate_revocations) =
        if schema_version >= AUTHORITY_SCHEMA_VERSION {
            (
                count("SELECT COUNT(*) FROM revocation_intents WHERE state='pending'")?,
                count("SELECT COUNT(*) FROM revocation_intents WHERE state='indeterminate'")?,
            )
        } else {
            (0, 0)
        };
    let expired_invites = conn.query_row(
        "SELECT COUNT(*) FROM enrollment_invites
         WHERE consumed_at IS NULL AND expires_at<=?1",
        [now_unix],
        |row| row.get(0),
    )?;
    let identity_path = home.join(LOCAL_IDENTITY_FILE);
    let local_identity_valid = match std::fs::read(&identity_path) {
        Ok(body) => serde_json::from_slice::<LocalIdentityRecord>(&body)
            .ok()
            .filter(|record| record.version == LOCAL_IDENTITY_VERSION)
            .map(|record| {
                let signing_key = SigningKey::from_bytes(&record.signing_seed);
                let stable = StableNodeId::from_verifying_key(&signing_key.verifying_key());
                let carrier_key = peeroxide::KeyPair::from_seed(record.peeroxide_seed).public_key;
                StableNodeId::parse(stable.as_str().to_string()).is_ok()
                    && carrier_key != signing_key.verifying_key().to_bytes()
                    && carrier_key.iter().any(|byte| *byte != 0)
                    && local_identity_permissions_are_private(&identity_path)
            })
            .unwrap_or(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => false,
    };
    Ok(Some(MembershipAuthorityHealth {
        schema_version,
        integrity,
        active,
        pending,
        expired_active,
        legacy_unattested,
        active_without_valid_binding,
        floor_projection_mismatch,
        pending_outbox,
        pending_teardown,
        pending_audit,
        pending_revocations,
        indeterminate_revocations,
        expired_invites,
        local_identity_valid,
    }))
}

#[cfg(unix)]
fn local_identity_permissions_are_private(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o077 == 0)
        .unwrap_or(false)
}

#[cfg(windows)]
fn local_identity_permissions_are_private(path: &Path) -> bool {
    crate::wal::win_native::verify_private_dacl(path).is_ok()
}

#[cfg(not(any(unix, windows)))]
fn local_identity_permissions_are_private(path: &Path) -> bool {
    std::fs::metadata(path).is_ok()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentInvite {
    pub invite_id: String,
    pub invitation_digest: String,
    pub stable_node_id: StableNodeId,
    pub carrier: CarrierKind,
    pub transport_identity: TransportIdentity,
    pub endpoint: String,
    pub label: String,
    pub auth_epoch: AuthEpoch,
    pub issued_at_membership_epoch: MembershipEpoch,
    pub expires_at_unix: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentReceipt {
    pub operation: String,
    pub invite_id: String,
    pub stable_node_id: StableNodeId,
    pub state: MembershipState,
    pub carrier: CarrierKind,
    pub transport_identity: TransportIdentity,
    pub assurance: String,
    pub auth_epoch: AuthEpoch,
    pub issued_at_membership_epoch: MembershipEpoch,
    pub committed_membership_epoch: MembershipEpoch,
    pub expires_at_unix: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipRevokeRequest {
    pub binding: MembershipRevokeBinding,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipRevokeBinding {
    pub request_id: String,
    pub stable_node_id: StableNodeId,
    pub reason: String,
    pub source: String,
    pub snapshot_version: u16,
    pub snapshot_digest: String,
    pub authority_epoch: MembershipEpoch,
    pub member_auth_epoch: AuthEpoch,
    pub member_membership_epoch: MembershipEpoch,
}

impl MembershipRevokeBinding {
    pub fn validate(&self) -> Result<()> {
        validate_revocation_request_id(&self.request_id)?;
        StableNodeId::parse(self.stable_node_id.as_str().to_string())?;
        anyhow::ensure!(
            !self.reason.trim().is_empty()
                && self.reason.trim() == self.reason
                && self.reason.len() <= 240
                && !self.reason.chars().any(char::is_control),
            "revocation reason is invalid"
        );
        anyhow::ensure!(
            !self.source.trim().is_empty()
                && self.source.trim() == self.source
                && self.source.len() <= 64
                && self
                    .source
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')),
            "revocation source is invalid"
        );
        anyhow::ensure!(
            self.snapshot_version == MEMBERSHIP_SNAPSHOT_VERSION,
            "revocation snapshot version is unsupported"
        );
        anyhow::ensure!(
            self.snapshot_digest.len() == 64
                && self
                    .snapshot_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "revocation snapshot digest is not lowercase SHA-256"
        );
        MembershipEpoch::new(self.authority_epoch.get())?;
        AuthEpoch::new(self.member_auth_epoch.get())?;
        MembershipEpoch::new(self.member_membership_epoch.get())?;
        anyhow::ensure!(
            self.member_membership_epoch == self.authority_epoch,
            "revocation member generation is not at the authority epoch"
        );
        Ok(())
    }

    pub fn request_digest(&self) -> Result<String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .context("serialize canonical membership revocation request")?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationIntentState {
    Pending,
    Indeterminate,
    Completed,
    NotFound,
}

impl RevocationIntentState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Indeterminate => "indeterminate",
            Self::Completed => "completed",
            Self::NotFound => "not_found",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "indeterminate" => Ok(Self::Indeterminate),
            "completed" => Ok(Self::Completed),
            "not_found" => Ok(Self::NotFound),
            other => anyhow::bail!("unknown revocation intent state `{other}`"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationIntentStatus {
    pub operation: String,
    pub request_id: String,
    pub request_digest: String,
    pub stable_node_id: StableNodeId,
    pub reason: String,
    pub source: String,
    pub state: RevocationIntentState,
    pub snapshot_version: u16,
    pub snapshot_digest: String,
    pub authority_epoch: MembershipEpoch,
    pub member_auth_epoch: AuthEpoch,
    pub member_membership_epoch: MembershipEpoch,
    pub external_effects_unclassified: bool,
    pub tombstone_committed: bool,
    pub receipt_id: Option<String>,
    pub indeterminate_reason: Option<String>,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

impl RevocationIntentStatus {
    pub fn immutable_binding(&self) -> Result<MembershipRevokeBinding> {
        let binding = MembershipRevokeBinding {
            request_id: self.request_id.clone(),
            stable_node_id: self.stable_node_id.clone(),
            reason: self.reason.clone(),
            source: self.source.clone(),
            snapshot_version: self.snapshot_version,
            snapshot_digest: self.snapshot_digest.clone(),
            authority_epoch: self.authority_epoch,
            member_auth_epoch: self.member_auth_epoch,
            member_membership_epoch: self.member_membership_epoch,
        };
        binding.validate()?;
        anyhow::ensure!(
            binding.request_digest()? == self.request_digest,
            "revocation status immutable binding digest mismatch"
        );
        Ok(binding)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipRevocationStatusEnvelope {
    pub operation: String,
    pub request_id: String,
    pub found: bool,
    pub status: Option<RevocationIntentStatus>,
}

impl MembershipRevocationStatusEnvelope {
    pub fn new(request_id: String, status: Option<RevocationIntentStatus>) -> Result<Self> {
        let envelope = Self {
            operation: MEMBERSHIP_REVOCATION_STATUS_OPERATION.into(),
            request_id,
            found: status.is_some(),
            status,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn from_json(json: &str) -> Result<Self> {
        let envelope = serde_json::from_str::<Self>(json)
            .context("parse membership revocation status JSON")?;
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.operation == MEMBERSHIP_REVOCATION_STATUS_OPERATION,
            "unsupported membership revocation status operation"
        );
        validate_revocation_request_id(&self.request_id)?;
        anyhow::ensure!(
            self.found == self.status.is_some(),
            "membership revocation status found flag is inconsistent"
        );
        let Some(status) = self.status.as_ref() else {
            return Ok(());
        };
        anyhow::ensure!(
            status.operation == "cluster.membership.revoke.status"
                && status.request_id == self.request_id,
            "membership revocation status is bound to a different request"
        );
        status.immutable_binding()?;
        anyhow::ensure!(
            !status.external_effects_unclassified || status.state == RevocationIntentState::Pending,
            "only a pending revocation may retain unclassified external effects"
        );
        match status.state {
            RevocationIntentState::Pending => anyhow::ensure!(
                !status.tombstone_committed
                    && status.receipt_id.is_none()
                    && status.indeterminate_reason.is_none(),
                "pending revocation status claims a terminal outcome"
            ),
            RevocationIntentState::Indeterminate => {
                let reason = status
                    .indeterminate_reason
                    .as_deref()
                    .context("indeterminate revocation status omitted its reason")?;
                anyhow::ensure!(
                    !reason.trim().is_empty()
                        && reason.trim() == reason
                        && !reason.chars().any(char::is_control),
                    "indeterminate revocation status reason is invalid"
                );
                anyhow::ensure!(
                    status.receipt_id.is_some() == status.tombstone_committed,
                    "indeterminate revocation receipt/tombstone state is inconsistent"
                );
            }
            RevocationIntentState::Completed => anyhow::ensure!(
                status.tombstone_committed
                    && status.receipt_id.is_some()
                    && status.indeterminate_reason.is_none()
                    && !status.external_effects_unclassified,
                "completed revocation status is not terminal"
            ),
            RevocationIntentState::NotFound => anyhow::ensure!(
                !status.tombstone_committed
                    && status.receipt_id.is_none()
                    && status.indeterminate_reason.is_none()
                    && !status.external_effects_unclassified,
                "not-found revocation status claims durable effects"
            ),
        }
        Ok(())
    }
}

impl MembershipRuntimeHealth {
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.wire_version == MEMBERSHIP_RUNTIME_HEALTH_WIRE_VERSION,
            "unsupported membership runtime-health wire version"
        );
        for generation in self
            .live_generations
            .iter()
            .chain(self.invalid_live_generations.iter())
        {
            StableNodeId::parse(generation.stable_node_id.as_str().to_string())?;
            AuthEpoch::new(generation.auth_epoch.get())?;
            MembershipEpoch::new(generation.membership_epoch.get())?;
        }
        anyhow::ensure!(
            self.invalid_live_generations
                .iter()
                .all(|generation| self.live_generations.contains(generation)),
            "invalid membership generations are not a subset of live generations"
        );
        let mut request_ids = HashSet::new();
        for status in &self.unresolved_revocations {
            anyhow::ensure!(
                matches!(
                    status.state,
                    RevocationIntentState::Pending | RevocationIntentState::Indeterminate
                ),
                "membership runtime-health contains a resolved revocation"
            );
            anyhow::ensure!(
                request_ids.insert(status.request_id.clone()),
                "membership runtime-health repeats a revocation request"
            );
            MembershipRevocationStatusEnvelope::new(
                status.request_id.clone(),
                Some(status.clone()),
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipInviteRequest {
    pub stable_node_id: StableNodeId,
    pub signing_public_key_hex: String,
    pub carrier: CarrierKind,
    pub transport_identity: TransportIdentity,
    pub endpoint: String,
    pub label: String,
    pub expires_at_unix: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipConfirmRequest {
    pub invite_id: String,
    pub attestation: EndpointAttestation,
    pub carrier: CarrierKind,
    pub authenticated_transport: TransportIdentity,
    pub endpoint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipLegacyPendingRequest {
    pub carrier: CarrierKind,
    pub transport_identity: TransportIdentity,
    pub endpoint: String,
    pub label: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CarrierTeardownReceipt {
    pub closed_sessions: usize,
    pub routes_evicted: usize,
    pub queued_effects_dropped: usize,
    pub status: String,
}

/// Carrier-specific live state that can be synchronously quarantined after the
/// tombstone commit. Implementations must be idempotent.
pub trait LiveCarrierSessions: Send + Sync {
    fn carrier(&self) -> CarrierKind;
    fn teardown_stable_node(&self, stable_node_id: &StableNodeId) -> CarrierTeardownReceipt;

    fn live_membership_generations(&self) -> Vec<LiveMembershipGeneration> {
        Vec::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MembershipEffectKind {
    Network,
    QueuedProvider,
    ExternalPermit,
    InflightProvider,
    DurableCommit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalEffectOutcome {
    Completed,
    FailedBeforeDispatch,
    AbortedWithProviderAck,
    Indeterminate,
}

impl From<MembershipEffectKind> for LiveMembershipKind {
    fn from(kind: MembershipEffectKind) -> Self {
        match kind {
            MembershipEffectKind::Network => Self::Network,
            MembershipEffectKind::QueuedProvider => Self::QueuedProvider,
            MembershipEffectKind::ExternalPermit => Self::ExternalPermit,
            MembershipEffectKind::InflightProvider => Self::InflightProvider,
            MembershipEffectKind::DurableCommit => Self::DurableCommit,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct MembershipGeneration {
    stable_node_id: StableNodeId,
    auth_epoch: AuthEpoch,
    membership_epoch: MembershipEpoch,
}

struct LiveMembershipEffect {
    generation: MembershipGeneration,
    carrier: CarrierKind,
    kind: MembershipEffectKind,
    cancel: tokio::sync::watch::Sender<Option<String>>,
}

#[derive(Default)]
struct GenerationEffectState {
    next_id: u64,
    minimum_membership_epoch: u64,
    revoked_auth_floor: HashMap<StableNodeId, AuthEpoch>,
    revoking: HashMap<MembershipGeneration, String>,
    effects: HashMap<u64, LiveMembershipEffect>,
}

/// Process-local cancellation/ack registry for authority generations.
///
/// SQLite remains the durable authority. This registry closes the gap between
/// a revocation intent and long-running daemon effects: revoke first closes the
/// process-local generation gate, commits the durable intent, then publishes
/// one cancellation fence. It does not commit the tombstone until every effect
/// captured by that fence has been classified and dropped its lease.
#[derive(Default)]
pub(crate) struct GenerationEffectRegistry {
    state: Mutex<GenerationEffectState>,
    quiesced: Condvar,
}

impl std::fmt::Debug for GenerationEffectRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        formatter
            .debug_struct("GenerationEffectRegistry")
            .field("minimum_membership_epoch", &state.minimum_membership_epoch)
            .field("live_effects", &state.effects.len())
            .finish()
    }
}

impl GenerationEffectRegistry {
    fn register(
        self: &Arc<Self>,
        generation: MembershipGeneration,
        carrier: CarrierKind,
        kind: MembershipEffectKind,
    ) -> Result<GenerationEffectLease> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        anyhow::ensure!(
            generation.membership_epoch.get() >= state.minimum_membership_epoch,
            "membership generation was cancelled by a newer authority epoch"
        );
        anyhow::ensure!(
            state
                .revoked_auth_floor
                .get(&generation.stable_node_id)
                .is_none_or(|floor| generation.auth_epoch > *floor),
            "membership authentication generation was revoked"
        );
        anyhow::ensure!(
            !state.revoking.contains_key(&generation),
            "membership generation has a revocation intent"
        );
        state.next_id = state
            .next_id
            .checked_add(1)
            .context("membership effect generation exhausted")?;
        let id = state.next_id;
        let (cancel, cancel_rx) = tokio::sync::watch::channel(None);
        state.effects.insert(
            id,
            LiveMembershipEffect {
                generation,
                carrier,
                kind,
                cancel,
            },
        );
        Ok(GenerationEffectLease {
            registry: Arc::clone(self),
            id,
            cancel_rx,
        })
    }

    fn transition(&self, id: u64, kind: MembershipEffectKind) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let generation = state
            .effects
            .get(&id)
            .context("membership effect lease is no longer live")?;
        anyhow::ensure!(
            generation.cancel.borrow().is_none(),
            "membership effect generation was cancelled"
        );
        let generation = generation.generation.clone();
        anyhow::ensure!(
            !state.revoking.contains_key(&generation),
            "membership effect generation has a revocation intent"
        );
        state
            .effects
            .get_mut(&id)
            .expect("membership effect checked under the same lock")
            .kind = kind;
        Ok(())
    }

    fn validate(&self, id: u64) -> Result<()> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let effect = state
            .effects
            .get(&id)
            .context("membership effect lease is no longer live")?;
        anyhow::ensure!(
            effect.cancel.borrow().is_none(),
            "membership effect generation was cancelled"
        );
        anyhow::ensure!(
            effect.generation.membership_epoch.get() >= state.minimum_membership_epoch,
            "membership effect generation was cancelled by a newer authority epoch"
        );
        anyhow::ensure!(
            state
                .revoked_auth_floor
                .get(&effect.generation.stable_node_id)
                .is_none_or(|floor| effect.generation.auth_epoch > *floor),
            "membership authentication generation was revoked"
        );
        anyhow::ensure!(
            !state.revoking.contains_key(&effect.generation),
            "membership effect generation has a revocation intent"
        );
        Ok(())
    }

    fn begin_revocation(
        self: &Arc<Self>,
        request_id: &str,
        generation: MembershipGeneration,
        committed_epoch: MembershipEpoch,
    ) -> GenerationCancellationFence {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state
            .revoking
            .entry(generation.clone())
            .and_modify(|existing| {
                debug_assert_eq!(existing, request_id);
            })
            .or_insert_with(|| request_id.to_string());
        state.minimum_membership_epoch = state.minimum_membership_epoch.max(committed_epoch.get());
        state
            .revoked_auth_floor
            .entry(generation.stable_node_id.clone())
            .and_modify(|floor| *floor = (*floor).max(generation.auth_epoch))
            .or_insert(generation.auth_epoch);

        let mut ids = Vec::new();
        let mut queued_by_carrier = BTreeMap::<CarrierKind, usize>::new();
        let mut external_effects_unclassified = false;
        for (id, effect) in &state.effects {
            let stale_authority = effect.generation.membership_epoch.get() < committed_epoch.get();
            let revoked_identity = effect.generation.stable_node_id == generation.stable_node_id
                && effect.generation.auth_epoch <= generation.auth_epoch;
            if stale_authority || revoked_identity {
                ids.push(*id);
                external_effects_unclassified |= matches!(
                    effect.kind,
                    MembershipEffectKind::ExternalPermit | MembershipEffectKind::InflightProvider
                );
                if effect.generation.stable_node_id == generation.stable_node_id
                    && effect.kind == MembershipEffectKind::QueuedProvider
                {
                    *queued_by_carrier.entry(effect.carrier).or_default() += 1;
                }
            }
        }
        GenerationCancellationFence {
            registry: Arc::clone(self),
            request_id: request_id.to_string(),
            stable_node_id: generation.stable_node_id,
            ids,
            queued_by_carrier,
            external_effects_unclassified,
        }
    }

    fn release(&self, id: u64) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.effects.remove(&id).is_some() {
            self.quiesced.notify_all();
        }
    }

    pub(crate) fn snapshot(&self) -> Vec<LiveMembershipGeneration> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut effects = state
            .effects
            .values()
            .map(|effect| LiveMembershipGeneration {
                stable_node_id: effect.generation.stable_node_id.clone(),
                carrier: effect.carrier,
                auth_epoch: effect.generation.auth_epoch,
                membership_epoch: effect.generation.membership_epoch,
                kind: effect.kind.into(),
            })
            .collect::<Vec<_>>();
        effects.sort_by(compare_live_membership_generations);
        effects
    }
}

struct GenerationEffectLease {
    registry: Arc<GenerationEffectRegistry>,
    id: u64,
    cancel_rx: tokio::sync::watch::Receiver<Option<String>>,
}

impl GenerationEffectLease {
    fn is_cancelled(&self) -> bool {
        self.cancel_rx.borrow().is_some()
    }

    fn cancellation_request_id(&self) -> Option<String> {
        self.cancel_rx.borrow().clone()
    }

    async fn cancelled(&mut self) -> Option<String> {
        while self.cancel_rx.borrow_and_update().is_none() {
            if self.cancel_rx.changed().await.is_err() {
                return None;
            }
        }
        self.cancel_rx.borrow().clone()
    }

    fn transition(&self, kind: MembershipEffectKind) -> Result<()> {
        self.registry.transition(self.id, kind)
    }

    fn validate(&self) -> Result<()> {
        self.registry.validate(self.id)
    }
}

impl Drop for GenerationEffectLease {
    fn drop(&mut self) {
        self.registry.release(self.id);
    }
}

#[derive(Clone)]
struct GenerationCancellationFence {
    registry: Arc<GenerationEffectRegistry>,
    request_id: String,
    stable_node_id: StableNodeId,
    ids: Vec<u64>,
    queued_by_carrier: BTreeMap<CarrierKind, usize>,
    external_effects_unclassified: bool,
}

impl GenerationCancellationFence {
    fn cancel(&self) {
        let state = self
            .registry
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for id in &self.ids {
            if let Some(effect) = state.effects.get(id) {
                let _ = effect.cancel.send(Some(self.request_id.clone()));
            }
        }
    }

    fn wait(&self) -> Result<()> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let ids = self.ids.iter().copied().collect::<HashSet<_>>();
        let mut state = self
            .registry
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while state.effects.keys().any(|id| ids.contains(id)) {
            let now = std::time::Instant::now();
            anyhow::ensure!(
                now < deadline,
                "membership revocation {} was not locally classified within 5 seconds",
                self.request_id
            );
            let wait = deadline.saturating_duration_since(now);
            let (next, _) = self
                .registry
                .quiesced
                .wait_timeout(state, wait)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next;
        }
        Ok(())
    }
}

/// Daemon-owned rendezvous for every live carrier generation. Weak references
/// ensure a stopped runtime generation disappears without a second lifecycle.
#[derive(Default)]
pub struct LiveSessionRegistry {
    carriers: Mutex<Vec<Weak<dyn LiveCarrierSessions>>>,
    #[cfg(test)]
    observed: Mutex<HashMap<(CarrierKind, StableNodeId), usize>>,
    effects: Arc<GenerationEffectRegistry>,
    cancellation_fences: Mutex<HashMap<String, GenerationCancellationFence>>,
}

impl LiveSessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn effect_registry(&self) -> Arc<GenerationEffectRegistry> {
        Arc::clone(&self.effects)
    }

    fn signal_revocation(
        &self,
        request_id: &str,
        stable_node_id: &StableNodeId,
        revoked_auth_epoch: AuthEpoch,
        revoked_membership_epoch: MembershipEpoch,
        committed_epoch: MembershipEpoch,
    ) -> bool {
        let fence = self.effects.begin_revocation(
            request_id,
            MembershipGeneration {
                stable_node_id: stable_node_id.clone(),
                auth_epoch: revoked_auth_epoch,
                membership_epoch: revoked_membership_epoch,
            },
            committed_epoch,
        );
        let external_effects_unclassified = fence.external_effects_unclassified;
        self.cancellation_fences
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(request_id.to_string())
            .or_insert(fence);
        external_effects_unclassified
    }

    fn wait_for_revocation(&self, request_id: &str) -> Result<()> {
        let fence = self
            .cancellation_fences
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(request_id)
            .cloned();
        if let Some(fence) = fence {
            fence.wait()?;
            self.cancellation_fences
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(request_id);
        }
        Ok(())
    }

    fn publish_revocation_cancellation(&self, request_id: &str) -> Result<()> {
        let fence = self
            .cancellation_fences
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(request_id)
            .cloned()
            .context("membership revocation cancellation fence is missing")?;
        fence.cancel();
        Ok(())
    }

    fn has_revocation_fence(&self, request_id: &str) -> bool {
        self.cancellation_fences
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(request_id)
    }

    pub fn register(&self, carrier: Arc<dyn LiveCarrierSessions>) {
        let mut carriers = self
            .carriers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        carriers.retain(|entry| entry.strong_count() > 0);
        carriers.push(Arc::downgrade(&carrier));
    }

    /// Test-only carrier seam. Production receipts are derived exclusively from
    /// carrier-owned live registries and can never accumulate historical counts.
    #[cfg(test)]
    pub fn note_session(&self, carrier: CarrierKind, stable_node_id: StableNodeId) {
        let mut observed = self
            .observed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *observed.entry((carrier, stable_node_id)).or_default() += 1;
    }

    pub fn teardown(
        &self,
        stable_node_id: &StableNodeId,
    ) -> BTreeMap<String, CarrierTeardownReceipt> {
        let mut result = BTreeMap::new();
        for carrier in [CarrierKind::Peeroxide, CarrierKind::Iroh] {
            result.insert(
                carrier.as_str().to_string(),
                CarrierTeardownReceipt {
                    status: "not_running".into(),
                    ..CarrierTeardownReceipt::default()
                },
            );
        }
        #[cfg(test)]
        {
            let mut observed = self
                .observed
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for carrier in [CarrierKind::Peeroxide, CarrierKind::Iroh] {
                let count = observed
                    .remove(&(carrier, stable_node_id.clone()))
                    .unwrap_or(0);
                if count > 0 {
                    let receipt = result
                        .get_mut(carrier.as_str())
                        .expect("carrier receipt initialized");
                    receipt.closed_sessions += count;
                    receipt.status = "closed".into();
                }
            }
        }
        let mut carriers = self
            .carriers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        carriers.retain(|entry| {
            let Some(carrier) = entry.upgrade() else {
                return false;
            };
            let update = carrier.teardown_stable_node(stable_node_id);
            let receipt = result
                .get_mut(carrier.carrier().as_str())
                .expect("carrier receipt initialized");
            receipt.closed_sessions += update.closed_sessions;
            receipt.routes_evicted += update.routes_evicted;
            receipt.queued_effects_dropped += update.queued_effects_dropped;
            if update.status != "not_running" {
                receipt.status = update.status;
            }
            true
        });
        let fences = self
            .cancellation_fences
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .filter(|fence| fence.stable_node_id == *stable_node_id)
            .cloned()
            .collect::<Vec<_>>();
        for fence in fences {
            for (carrier, queued) in &fence.queued_by_carrier {
                let receipt = result
                    .get_mut(carrier.as_str())
                    .expect("carrier receipt initialized");
                receipt.queued_effects_dropped += queued;
                if *queued > 0 && receipt.status == "not_running" {
                    receipt.status = "closed".into();
                }
            }
        }
        result
    }

    fn live_membership_generations(&self) -> Vec<LiveMembershipGeneration> {
        let mut generations = self.effects.snapshot();
        let mut carriers = self
            .carriers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        carriers.retain(|entry| {
            let Some(carrier) = entry.upgrade() else {
                return false;
            };
            generations.extend(carrier.live_membership_generations());
            true
        });
        generations.sort_by(compare_live_membership_generations);
        generations
    }
}

#[derive(Clone, Debug)]
pub struct MembershipGrant {
    stable_node_id: StableNodeId,
    carrier: CarrierKind,
    transport_identity: TransportIdentity,
    auth_epoch: AuthEpoch,
    membership_epoch: MembershipEpoch,
    expires_at_unix: Option<i64>,
    authority_path: PathBuf,
    effects: Arc<GenerationEffectRegistry>,
}

impl MembershipGrant {
    pub fn stable_node_id(&self) -> &StableNodeId {
        &self.stable_node_id
    }

    pub fn carrier(&self) -> CarrierKind {
        self.carrier
    }

    pub fn transport_identity(&self) -> &TransportIdentity {
        &self.transport_identity
    }

    pub fn auth_epoch(&self) -> AuthEpoch {
        self.auth_epoch
    }

    pub fn membership_epoch(&self) -> MembershipEpoch {
        self.membership_epoch
    }

    pub fn revalidate(&self, now_unix: i64) -> Result<()> {
        MembershipStore::open_path(self.authority_path.clone(), false)?
            .revalidate_grant(self, now_unix)
    }

    /// Start a membership-linearized effect. This read transaction remains
    /// deliberately short: long provider/network effects must never hold a
    /// SQLite read lock. [`MembershipEffectGuard::finish`] performs the second
    /// authority read immediately before the durable acknowledgement/cursor
    /// commit; a concurrent revoke therefore suppresses that commit.
    pub fn begin_effect(&self, now_unix: i64) -> Result<MembershipEffectGuard> {
        self.begin_effect_kind(now_unix, MembershipEffectKind::Network)
    }

    pub fn begin_effect_kind(
        &self,
        now_unix: i64,
        kind: MembershipEffectKind,
    ) -> Result<MembershipEffectGuard> {
        self.revalidate(now_unix)?;
        let generation = MembershipGeneration {
            stable_node_id: self.stable_node_id.clone(),
            auth_epoch: self.auth_epoch,
            membership_epoch: self.membership_epoch,
        };
        let lease = self.effects.register(generation, self.carrier, kind)?;
        let guard = MembershipEffectGuard {
            authority_path: self.authority_path.clone(),
            stable_node_id: self.stable_node_id.clone(),
            carrier: self.carrier,
            transport_identity: self.transport_identity.clone(),
            auth_epoch: self.auth_epoch,
            membership_epoch: self.membership_epoch,
            expires_at_unix: self.expires_at_unix,
            effects: Arc::clone(&self.effects),
            lease: Some(lease),
        };
        if let Err(error) = guard.validate(now_unix) {
            return Err(error);
        }
        Ok(guard)
    }
}

pub struct MembershipEffectGuard {
    authority_path: PathBuf,
    stable_node_id: StableNodeId,
    carrier: CarrierKind,
    transport_identity: TransportIdentity,
    auth_epoch: AuthEpoch,
    membership_epoch: MembershipEpoch,
    expires_at_unix: Option<i64>,
    effects: Arc<GenerationEffectRegistry>,
    lease: Option<GenerationEffectLease>,
}

impl std::fmt::Debug for MembershipEffectGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MembershipEffectGuard")
            .field("stable_node_id", &self.stable_node_id)
            .field("carrier", &self.carrier)
            .field("transport_identity", &self.transport_identity)
            .field("auth_epoch", &self.auth_epoch)
            .field("membership_epoch", &self.membership_epoch)
            .field("expires_at_unix", &self.expires_at_unix)
            .finish_non_exhaustive()
    }
}

impl MembershipEffectGuard {
    pub fn stable_node_id(&self) -> &StableNodeId {
        &self.stable_node_id
    }

    pub fn carrier(&self) -> CarrierKind {
        self.carrier
    }

    pub fn transport_identity(&self) -> &TransportIdentity {
        &self.transport_identity
    }

    pub fn auth_epoch(&self) -> AuthEpoch {
        self.auth_epoch
    }

    pub fn membership_epoch(&self) -> MembershipEpoch {
        self.membership_epoch
    }

    pub fn is_cancelled(&self) -> bool {
        self.lease
            .as_ref()
            .is_some_and(GenerationEffectLease::is_cancelled)
    }

    pub fn cancellation_request_id(&self) -> Option<String> {
        self.lease
            .as_ref()
            .and_then(GenerationEffectLease::cancellation_request_id)
    }

    pub async fn cancelled(&mut self) -> Option<String> {
        if let Some(lease) = self.lease.as_mut() {
            lease.cancelled().await
        } else {
            std::future::pending::<Option<String>>().await
        }
    }

    pub fn transition(&self, kind: MembershipEffectKind) -> Result<()> {
        self.lease
            .as_ref()
            .context("membership effect lease already finished")?
            .transition(kind)
    }

    pub fn validate(&self, now_unix: i64) -> Result<()> {
        self.lease
            .as_ref()
            .context("membership effect lease already finished")?
            .validate()?;
        anyhow::ensure!(
            !self.is_cancelled(),
            "membership effect generation was cancelled"
        );
        let grant = MembershipGrant {
            stable_node_id: self.stable_node_id.clone(),
            carrier: self.carrier,
            transport_identity: self.transport_identity.clone(),
            auth_epoch: self.auth_epoch,
            membership_epoch: self.membership_epoch,
            expires_at_unix: self.expires_at_unix,
            authority_path: self.authority_path.clone(),
            effects: Arc::clone(&self.effects),
        };
        grant.revalidate(now_unix)
    }

    pub(crate) fn attach_authority(&self, conn: &Connection) -> Result<()> {
        let already_attached: i64 = conn.query_row(
            "SELECT EXISTS(
               SELECT 1 FROM pragma_database_list WHERE name='membership_authority'
             )",
            [],
            |row| row.get(0),
        )?;
        if already_attached == 1 {
            let attached_path: PathBuf = conn.query_row(
                "SELECT file
                 FROM pragma_database_list
                 WHERE name='membership_authority'",
                [],
                |row| row.get::<_, String>(0).map(PathBuf::from),
            )?;
            let expected_path = std::fs::canonicalize(&self.authority_path)
                .unwrap_or_else(|_| self.authority_path.clone());
            let attached_path = std::fs::canonicalize(&attached_path).unwrap_or(attached_path);
            anyhow::ensure!(
                attached_path == expected_path,
                "durable transaction mixed membership authority databases"
            );
            return Ok(());
        }
        let path = self
            .authority_path
            .to_str()
            .context("membership authority path is not valid UTF-8")?;
        conn.execute("ATTACH DATABASE ?1 AS membership_authority", [path])
            .context("attach membership authority to durable effect transaction")?;
        Ok(())
    }

    pub(crate) fn validate_attached(&self, conn: &Connection, now_unix: i64) -> Result<()> {
        self.lease
            .as_ref()
            .context("membership effect lease already finished")?
            .validate()?;
        anyhow::ensure!(
            !self.is_cancelled(),
            "membership effect generation was cancelled"
        );
        anyhow::ensure!(
            self.expires_at_unix.is_none_or(|expiry| expiry > now_unix),
            "membership effect grant expired"
        );
        let valid: i64 = conn.query_row(
            "SELECT EXISTS(
               SELECT 1
               FROM membership_authority.members m
               JOIN membership_authority.transport_bindings b
                 ON b.stable_node_id=m.stable_node_id
               JOIN membership_authority.authority_meta a ON a.singleton=1
               WHERE m.stable_node_id=?1
                 AND m.state='active'
                 AND m.auth_epoch=?2
                 AND m.membership_epoch=?3
                 AND b.carrier=?4
                 AND b.transport_identity=?5
                 AND b.auth_epoch=m.auth_epoch
                 AND b.membership_epoch=m.membership_epoch
                 AND (b.expires_at IS NULL OR b.expires_at>?6)
                 AND m.membership_epoch=a.membership_epoch
                 AND m.membership_epoch>=a.revocation_floor
                 AND NOT EXISTS(
                   SELECT 1 FROM membership_authority.revocation_tombstones t
                   WHERE t.stable_node_id=m.stable_node_id
                     AND t.auth_epoch=m.auth_epoch
                 )
                 AND NOT EXISTS(
                   SELECT 1 FROM membership_authority.revocation_intents r
                   WHERE r.stable_node_id=m.stable_node_id
                     AND r.member_auth_epoch=m.auth_epoch
                     AND r.member_membership_epoch=m.membership_epoch
                     AND r.state IN ('pending','indeterminate')
                 )
             )",
            params![
                self.stable_node_id.as_str(),
                self.auth_epoch.get(),
                self.membership_epoch.get(),
                self.carrier.as_str(),
                self.transport_identity.as_str(),
                now_unix
            ],
            |row| row.get(0),
        )?;
        anyhow::ensure!(valid == 1, "membership authority rejected durable commit");
        Ok(())
    }

    pub fn finish(self) -> Result<()> {
        self.validate(crate::time::now_unix_i64())
    }

    /// Acquire the final local admission permit immediately before an
    /// irreversible carrier/provider operation. The registry transition is
    /// the process-local linearization point against revocation.
    pub fn begin_external(&mut self, now_unix: i64) -> Result<MembershipExternalEffectPermit<'_>> {
        self.validate(now_unix)?;
        self.transition(MembershipEffectKind::ExternalPermit)?;
        Ok(MembershipExternalEffectPermit {
            guard: self,
            // Permit acquisition is the final boundary immediately before the
            // carrier/provider call. Treat the transport as potentially
            // started from this point so a gate race cannot create an
            // unclassified micro-window before the caller's first await.
            transport_may_have_started: true,
        })
    }

    fn persist_indeterminate(&self, request_id: &str, reason: &str, now_unix: i64) -> Result<()> {
        MembershipStore::open_path(self.authority_path.clone(), false)?
            .mark_revocation_indeterminate(request_id, reason, now_unix)
    }
}

/// RAII admission permit held across the physical provider/carrier operation.
/// Dropping a provider future is only a local abort. If transport may have
/// started and revocation wins the race, callers must durably classify the
/// request as indeterminate before this permit (and its generation lease) is
/// released.
pub struct MembershipExternalEffectPermit<'a> {
    guard: &'a mut MembershipEffectGuard,
    transport_may_have_started: bool,
}

impl MembershipExternalEffectPermit<'_> {
    pub fn mark_transport_may_have_started(&mut self) {
        self.transport_may_have_started = true;
    }

    pub fn is_cancelled(&self) -> bool {
        self.guard.is_cancelled()
    }

    pub fn cancellation_request_id(&self) -> Option<String> {
        self.guard.cancellation_request_id()
    }

    pub async fn cancelled(&mut self) -> Option<String> {
        self.guard.cancelled().await
    }

    pub fn validate(&self, now_unix: i64) -> Result<()> {
        self.guard.validate(now_unix)
    }

    pub fn persist_indeterminate_if_cancelled(&self, reason: &str, now_unix: i64) -> Result<bool> {
        if !self.transport_may_have_started {
            return Ok(false);
        }
        let Some(request_id) = self.cancellation_request_id() else {
            return Ok(false);
        };
        self.guard
            .persist_indeterminate(&request_id, reason, now_unix)?;
        Ok(true)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeReceipt {
    pub operation: String,
    pub request_id: String,
    pub intent_state: RevocationIntentState,
    pub indeterminate_reason: Option<String>,
    pub receipt_id: String,
    pub stable_node_id: StableNodeId,
    pub auth_epoch: AuthEpoch,
    pub membership_epoch: MembershipEpoch,
    pub authority_path: PathBuf,
    pub post_state_digest: String,
    pub tombstone_committed: bool,
    pub already_revoked: bool,
    pub live_teardown: String,
    pub audit_pending: bool,
    pub pending_outbox: u64,
    pub per_carrier_teardown: BTreeMap<String, CarrierTeardownReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbox_error: Option<String>,
}

#[derive(Clone)]
pub struct MembershipController {
    store: MembershipStore,
    live_sessions: Arc<LiveSessionRegistry>,
    audit_writer: Option<crate::wal::writer::WalWriterHandle>,
    operations: Arc<Mutex<()>>,
}

impl MembershipController {
    pub fn new(store: MembershipStore, live_sessions: Arc<LiveSessionRegistry>) -> Self {
        let store = store.with_effect_registry(live_sessions.effect_registry());
        Self {
            store,
            live_sessions,
            audit_writer: None,
            operations: Arc::new(Mutex::new(())),
        }
    }

    pub fn with_audit_writer(
        store: MembershipStore,
        live_sessions: Arc<LiveSessionRegistry>,
        audit_writer: crate::wal::writer::WalWriterHandle,
    ) -> Self {
        let store = store.with_effect_registry(live_sessions.effect_registry());
        Self {
            store,
            live_sessions,
            audit_writer: Some(audit_writer),
            operations: Arc::new(Mutex::new(())),
        }
    }

    pub fn open(home: &Path, live_sessions: Arc<LiveSessionRegistry>) -> Result<Self> {
        Ok(Self::new(MembershipStore::open(home)?, live_sessions))
    }

    pub fn store(&self) -> &MembershipStore {
        &self.store
    }

    pub fn snapshot(&self) -> Result<MembershipSnapshot> {
        self.store.full_snapshot()
    }

    pub fn runtime_health(&self) -> Result<MembershipRuntimeHealth> {
        let live_generations = self.live_sessions.live_membership_generations();
        let invalid_live_generations = live_generations
            .iter()
            .filter_map(|generation| {
                match self.store.generation_is_active(
                    &generation.stable_node_id,
                    generation.carrier,
                    generation.auth_epoch,
                    generation.membership_epoch,
                    crate::time::now_unix_i64(),
                ) {
                    Ok(true) => None,
                    Ok(false) => Some(Ok(generation.clone())),
                    Err(error) => Some(Err(error)),
                }
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(MembershipRuntimeHealth {
            wire_version: MEMBERSHIP_RUNTIME_HEALTH_WIRE_VERSION,
            live_generations,
            invalid_live_generations,
            unresolved_revocations: self.store.unresolved_revocations()?,
        })
    }

    pub fn create_invite(
        &self,
        stable_node_id: &StableNodeId,
        signing_public_key: &[u8; 32],
        carrier: CarrierKind,
        transport_identity: &TransportIdentity,
        endpoint: &str,
        label: &str,
        now_unix: i64,
        expires_at_unix: i64,
    ) -> Result<EnrollmentInvite> {
        let _operation = self
            .operations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.store.create_invite(
            stable_node_id,
            signing_public_key,
            carrier,
            transport_identity,
            endpoint,
            label,
            now_unix,
            expires_at_unix,
        )
    }

    pub fn confirm_invite(
        &self,
        invite_id: &str,
        attestation: &EndpointAttestation,
        carrier: CarrierKind,
        authenticated_transport: &TransportIdentity,
        endpoint: &str,
        now_unix: i64,
    ) -> Result<EnrollmentReceipt> {
        let _operation = self
            .operations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.store.confirm_invite(
            invite_id,
            attestation,
            carrier,
            authenticated_transport,
            endpoint,
            now_unix,
        )
    }

    pub fn record_legacy_pending(
        &self,
        carrier: CarrierKind,
        transport_identity: &TransportIdentity,
        endpoint: &str,
        label: &str,
        now_unix: i64,
    ) -> Result<StableNodeId> {
        let _operation = self
            .operations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.store
            .record_legacy_pending(carrier, transport_identity, endpoint, label, now_unix)
    }

    pub fn revoke(
        &self,
        identifier: &str,
        reason: &str,
        now_unix: i64,
    ) -> Result<Option<RevokeReceipt>> {
        let request_id = uuid::Uuid::now_v7().to_string();
        self.revoke_with_request_id(identifier, reason, "internal", &request_id, now_unix)
    }

    pub fn revoke_with_request_id(
        &self,
        identifier: &str,
        reason: &str,
        source: &str,
        request_id: &str,
        now_unix: i64,
    ) -> Result<Option<RevokeReceipt>> {
        let _operation = self
            .operations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(binding) =
            self.store
                .build_revoke_binding(identifier, reason, source, Some(request_id))?
        else {
            return self.store.revoke_receipt_for_identifier(identifier);
        };
        self.revoke_bound_unlocked(&binding, now_unix).map(Some)
    }

    pub fn revoke_bound(
        &self,
        binding: &MembershipRevokeBinding,
        now_unix: i64,
    ) -> Result<RevokeReceipt> {
        let _operation = self
            .operations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.revoke_bound_unlocked(binding, now_unix)
    }

    fn revoke_bound_unlocked(
        &self,
        binding: &MembershipRevokeBinding,
        now_unix: i64,
    ) -> Result<RevokeReceipt> {
        binding.validate()?;
        if let Some(status) = self.store.revocation_status(&binding.request_id)? {
            anyhow::ensure!(
                status.immutable_binding()? == *binding,
                "revocation request id was reused with a different immutable binding"
            );
            if status.tombstone_committed {
                let mut receipt = self
                    .store
                    .revoke_receipt(&binding.stable_node_id)?
                    .context("completed revocation intent omitted its receipt")?;
                receipt.already_revoked = true;
                return Ok(receipt);
            }
            if status.state == RevocationIntentState::Pending
                && !self.live_sessions.has_revocation_fence(&binding.request_id)
            {
                self.store.mark_revocation_indeterminate(
                    &binding.request_id,
                    "pending_revocation_recovered_without_process_effect_classification",
                    now_unix,
                )?;
            }
        }

        let committed_epoch = binding.authority_epoch.next()?;
        let external_effects_unclassified = self.live_sessions.signal_revocation(
            &binding.request_id,
            &binding.stable_node_id,
            binding.member_auth_epoch,
            binding.member_membership_epoch,
            committed_epoch,
        );
        // The process gate is deliberately flipped before the durable write:
        // no external permit or already-running effect can linearize in the
        // insertion window. Cancellation is published only after the intent
        // row commits, so any transport uncertainty has a durable request to
        // classify. A failed write leaves the generation gate fail-closed.
        self.store
            .start_revocation_intent(binding, external_effects_unclassified, now_unix)?;
        self.live_sessions
            .publish_revocation_cancellation(&binding.request_id)?;
        let teardown_details = self.live_sessions.teardown(&binding.stable_node_id);
        self.live_sessions
            .wait_for_revocation(&binding.request_id)?;
        let live_teardown = if teardown_details
            .values()
            .any(|receipt| matches!(receipt.status.as_str(), "partial" | "pending"))
        {
            "partial"
        } else {
            "complete"
        };
        let mut receipt = self.store.finalize_revocation_intent(
            binding,
            live_teardown,
            &teardown_details,
            now_unix,
        )?;
        let outbox_error = self
            .drain_outbox_unlocked(now_unix)
            .err()
            .map(|error| format!("{error:#}"));
        receipt = self
            .store
            .revoke_receipt(&binding.stable_node_id)?
            .unwrap_or(receipt);
        receipt.outbox_error = outbox_error;
        let post_state = self.store.full_snapshot()?;
        receipt.authority_path = post_state.authority_path.clone();
        receipt.post_state_digest = post_state.canonical_digest()?;
        Ok(receipt)
    }

    pub fn revocation_status(&self, request_id: &str) -> Result<Option<RevocationIntentStatus>> {
        self.store.revocation_status(request_id)
    }

    /// Replay is intentionally synchronous and bounded by the finite durable
    /// outbox. It is called before carrier startup and after each mutation.
    pub fn drain_outbox(&self, now_unix: i64) -> Result<usize> {
        let _operation = self
            .operations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.drain_outbox_unlocked(now_unix)
    }

    fn drain_outbox_unlocked(&self, now_unix: i64) -> Result<usize> {
        let mut delivered = 0usize;
        let mut pending = self.store.pending_outbox()?;
        pending.sort_by_key(|event| match event.kind.as_str() {
            // Safety effects are replayed before proof delivery. A broken WAL
            // writer may leave the audit row pending, but it cannot postpone
            // carrier teardown or durable-state quarantine after a tombstone.
            "teardown" => 0_u8,
            "membership_revoked" => 1,
            "audit" => 2,
            _ => 3,
        });
        for event in pending {
            match event.kind.as_str() {
                "teardown" => {
                    let details = self.live_sessions.teardown(&event.stable_node_id);
                    let status = if details
                        .values()
                        .any(|receipt| matches!(receipt.status.as_str(), "partial" | "pending"))
                    {
                        "partial"
                    } else {
                        "complete"
                    };
                    self.store
                        .update_teardown(&event.receipt_id, status, &details, now_unix)?;
                }
                "audit" => {
                    let Some(writer) = self.audit_writer.as_ref() else {
                        continue;
                    };
                    let payload = event.payload.as_bytes().to_vec();
                    let header = crate::wal::HeaderBuilder::new(
                        crate::wal::events::EVENT_TYPE_CLUSTER_PEER_REVOKED,
                        &payload,
                    )
                    .build();
                    writer
                        .append_blocking(header, payload)
                        .context("append membership revoke audit to daemon WAL")?;
                    self.store.append_membership_audit(&event, now_unix)?;
                }
                "membership_revoked" => {
                    let views_path = self
                        .store
                        .path()
                        .parent()
                        .context("membership authority path has no home directory")?
                        .join("views.db");
                    crate::cluster::durable_sync::quarantine_revoked_membership(
                        &views_path,
                        &event.stable_node_id,
                    )?;
                    self.store.apply_membership_projection(&event, now_unix)?;
                }
                other => anyhow::bail!("unknown membership outbox kind `{other}`"),
            }
            self.store.mark_outbox_delivered(event.id, now_unix)?;
            delivered += 1;
        }
        Ok(delivered)
    }
}

#[derive(Clone, Debug)]
pub struct MembershipStore {
    path: PathBuf,
    effects: Arc<GenerationEffectRegistry>,
}

#[derive(Clone, Debug)]
struct PendingOutboxEvent {
    id: i64,
    kind: String,
    stable_node_id: StableNodeId,
    receipt_id: String,
    auth_epoch: AuthEpoch,
    membership_epoch: MembershipEpoch,
    payload: String,
}

impl MembershipStore {
    pub fn open(home: &Path) -> Result<Self> {
        let store = Self::open_path(home.join(AUTHORITY_DB_FILE), true)?;
        store.import_legacy_once(home)?;
        Ok(store)
    }

    pub fn open_existing(home: &Path) -> Result<Option<Self>> {
        let path = home.join(AUTHORITY_DB_FILE);
        if !path.exists() {
            return Ok(None);
        }
        Self::open_path(path, false).map(Some)
    }

    pub fn open_path(path: PathBuf, create_private: bool) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create membership DB parent {}", parent.display()))?;
        }
        if create_private && !path.exists() {
            crate::util::atomic_write::atomic_write_private(&path, &[])
                .with_context(|| format!("create private membership DB {}", path.display()))?;
        }
        let store = Self {
            path,
            effects: Arc::new(GenerationEffectRegistry::default()),
        };
        let conn = store.connection()?;
        migrate(&conn)?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn with_effect_registry(mut self, effects: Arc<GenerationEffectRegistry>) -> Self {
        self.effects = effects;
        self
    }

    fn connection(&self) -> Result<Connection> {
        let conn = Connection::open(&self.path)
            .with_context(|| format!("open membership DB {}", self.path.display()))?;
        conn.execute_batch(
            "PRAGMA foreign_keys=ON;
             PRAGMA busy_timeout=5000;
             PRAGMA synchronous=FULL;
             PRAGMA journal_mode=DELETE;",
        )
        .context("configure membership DB durability")?;
        Ok(conn)
    }

    pub fn integrity_check(&self) -> Result<()> {
        let conn = self.connection()?;
        let result: String = conn
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .context("run membership DB integrity check")?;
        anyhow::ensure!(result == "ok", "membership DB integrity check: {result}");
        let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        anyhow::ensure!(
            version == AUTHORITY_SCHEMA_VERSION,
            "membership DB schema version {version}, expected {AUTHORITY_SCHEMA_VERSION}"
        );
        Ok(())
    }

    pub fn authority_epochs(&self) -> Result<(MembershipEpoch, MembershipEpoch)> {
        let conn = self.connection()?;
        let (epoch, floor): (u64, u64) = conn.query_row(
            "SELECT membership_epoch, revocation_floor FROM authority_meta WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok((MembershipEpoch::new(epoch)?, MembershipEpoch::new(floor)?))
    }

    pub fn latest_invitation_digest(
        &self,
        stable_node_id: &StableNodeId,
    ) -> Result<Option<String>> {
        let conn = self.connection()?;
        conn.query_row(
            "SELECT invitation_digest
             FROM enrollment_invites
             WHERE stable_node_id=?1
             ORDER BY created_at DESC, invite_id DESC
             LIMIT 1",
            [stable_node_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .context("load latest enrollment invitation digest")
    }

    pub fn full_snapshot(&self) -> Result<MembershipSnapshot> {
        let (authority_epoch, revocation_floor) = self.authority_epochs()?;
        Ok(MembershipSnapshot {
            version: 1,
            authority_path: self.path.clone(),
            authority_epoch,
            revocation_floor,
            pending_outbox: self.pending_outbox_count()?,
            members: self.snapshot()?,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_invite(
        &self,
        stable_node_id: &StableNodeId,
        signing_public_key: &[u8; 32],
        carrier: CarrierKind,
        transport_identity: &TransportIdentity,
        endpoint: &str,
        label: &str,
        now_unix: i64,
        expires_at_unix: i64,
    ) -> Result<EnrollmentInvite> {
        anyhow::ensure!(!endpoint.trim().is_empty(), "invite endpoint is empty");
        anyhow::ensure!(!label.trim().is_empty(), "invite label is empty");
        anyhow::ensure!(endpoint.len() <= 1024, "invite endpoint is too long");
        anyhow::ensure!(label.len() <= 128, "invite label is too long");
        anyhow::ensure!(
            expires_at_unix > now_unix,
            "invite expiry must be in the future"
        );
        let key =
            VerifyingKey::from_bytes(signing_public_key).context("invalid invite signing key")?;
        anyhow::ensure!(
            stable_node_id == &StableNodeId::from_verifying_key(&key),
            "invite stable node id does not match signing key"
        );
        let invite_id = uuid::Uuid::new_v4().to_string();
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, u64)> = tx
            .query_row(
                "SELECT state,auth_epoch FROM members WHERE stable_node_id=?1",
                [stable_node_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let has_revocation_history: bool = tx.query_row(
            "SELECT EXISTS(
               SELECT 1 FROM revocation_tombstones WHERE stable_node_id=?1
             )",
            [stable_node_id.as_str()],
            |row| row.get(0),
        )?;
        anyhow::ensure!(
            existing.as_ref().is_none_or(|(state, _)| {
                matches!(state.as_str(), "discovered" | "pending" | "revoked")
            }),
            "active stable node cannot receive an enrollment invite"
        );
        let auth_epoch = match existing.as_ref() {
            Some((state, epoch)) if state == "revoked" => AuthEpoch::new(*epoch)?.next()?,
            Some((_, epoch)) => AuthEpoch::new(*epoch)?,
            None => AuthEpoch::INITIAL,
        };
        if has_revocation_history {
            let historically_used: i64 = tx.query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM transport_bindings
                    WHERE stable_node_id=?1 AND carrier=?2 AND transport_identity=?3
                   UNION ALL
                   SELECT 1 FROM enrollment_invites
                    WHERE stable_node_id=?1 AND carrier=?2 AND transport_identity=?3
                 )",
                params![
                    stable_node_id.as_str(),
                    carrier.as_str(),
                    transport_identity.as_str()
                ],
                |row| row.get(0),
            )?;
            anyhow::ensure!(
                historically_used == 0,
                "revoked stable node must re-enroll with a carrier transport identity never used before"
            );
        }
        let authority_epoch: u64 = tx.query_row(
            "SELECT membership_epoch FROM authority_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let issued_at_membership_epoch = MembershipEpoch::new(authority_epoch)?.next()?;
        let digest = invitation_digest(
            &invite_id,
            stable_node_id,
            signing_public_key,
            carrier,
            transport_identity,
            endpoint,
            label,
            auth_epoch,
            issued_at_membership_epoch,
            expires_at_unix,
        );
        tx.execute(
            "INSERT INTO members
             (stable_node_id,label,state,auth_epoch,membership_epoch,created_at,updated_at)
             VALUES (?1,?2,'pending',?3,?4,?5,?5)
             ON CONFLICT(stable_node_id) DO UPDATE SET
               label=excluded.label,state='pending',auth_epoch=excluded.auth_epoch,
               membership_epoch=excluded.membership_epoch,updated_at=excluded.updated_at",
            params![
                stable_node_id.as_str(),
                label,
                auth_epoch.get(),
                issued_at_membership_epoch.get(),
                now_unix
            ],
        )?;
        tx.execute(
            "INSERT INTO enrollment_invites
             (invite_id,invitation_digest,stable_node_id,signing_public_key,carrier,
              transport_identity,endpoint,label,auth_epoch,membership_epoch,
              created_at,expires_at,consumed_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,NULL)",
            params![
                invite_id,
                digest,
                stable_node_id.as_str(),
                signing_public_key.as_slice(),
                carrier.as_str(),
                transport_identity.as_str(),
                endpoint,
                label,
                auth_epoch.get(),
                issued_at_membership_epoch.get(),
                now_unix,
                expires_at_unix
            ],
        )?;
        tx.commit()?;
        Ok(EnrollmentInvite {
            invite_id,
            invitation_digest: digest,
            stable_node_id: stable_node_id.clone(),
            carrier,
            transport_identity: transport_identity.clone(),
            endpoint: endpoint.to_string(),
            label: label.to_string(),
            auth_epoch,
            issued_at_membership_epoch,
            expires_at_unix,
        })
    }

    pub fn confirm_invite(
        &self,
        invite_id: &str,
        attestation: &EndpointAttestation,
        carrier: CarrierKind,
        authenticated_transport: &TransportIdentity,
        endpoint: &str,
        now_unix: i64,
    ) -> Result<EnrollmentReceipt> {
        attestation.verify_exact(carrier, authenticated_transport, endpoint, now_unix)?;
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row: Option<(
            String,
            Vec<u8>,
            String,
            String,
            String,
            String,
            u64,
            u64,
            i64,
            Option<i64>,
        )> = tx
            .query_row(
                "SELECT invitation_digest,signing_public_key,stable_node_id,carrier,
                        transport_identity,endpoint,auth_epoch,membership_epoch,
                        expires_at,consumed_at
                 FROM enrollment_invites WHERE invite_id=?1",
                [invite_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            digest,
            signing_public_key,
            stable,
            expected_carrier,
            expected_transport,
            expected_endpoint,
            auth_epoch,
            issued_at_membership_epoch,
            expires_at,
            consumed_at,
        )) = row
        else {
            anyhow::bail!("unknown enrollment invite");
        };
        anyhow::ensure!(consumed_at.is_none(), "enrollment invite already consumed");
        anyhow::ensure!(expires_at > now_unix, "enrollment invite expired");
        anyhow::ensure!(
            attestation.expires_at_unix <= expires_at,
            "endpoint attestation exceeds authority invite expiry"
        );
        anyhow::ensure!(
            attestation.invitation_digest.as_deref() == Some(digest.as_str()),
            "endpoint attestation invitation digest mismatch"
        );
        anyhow::ensure!(
            expected_carrier == carrier.as_str(),
            "enrollment invite carrier mismatch"
        );
        anyhow::ensure!(
            expected_transport == authenticated_transport.as_str(),
            "enrollment invite transport identity mismatch"
        );
        anyhow::ensure!(
            expected_endpoint == endpoint,
            "enrollment invite endpoint mismatch"
        );
        anyhow::ensure!(
            stable == attestation.stable_node_id.as_str(),
            "enrollment invite stable node mismatch"
        );
        anyhow::ensure!(
            signing_public_key.as_slice() == attestation.signing_public_key,
            "enrollment invite signing key mismatch"
        );
        anyhow::ensure!(
            attestation.auth_epoch.get() == auth_epoch,
            "endpoint attestation auth epoch does not match enrollment invite"
        );
        anyhow::ensure!(
            attestation.proof_membership_epoch.get() == issued_at_membership_epoch,
            "endpoint attestation proof membership epoch does not match enrollment invite issue epoch"
        );
        let authority_epoch: u64 = tx.query_row(
            "SELECT membership_epoch FROM authority_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let committed_membership_epoch = if authority_epoch <= issued_at_membership_epoch {
            issued_at_membership_epoch
        } else {
            MembershipEpoch::new(authority_epoch)?.next()?.get()
        };
        if authority_epoch < committed_membership_epoch {
            tx.execute(
                "UPDATE authority_meta SET membership_epoch=?1 WHERE singleton=1",
                [committed_membership_epoch],
            )?;
            tx.execute(
                "UPDATE members SET membership_epoch=?1,updated_at=?2 WHERE state='active'",
                params![committed_membership_epoch, now_unix],
            )?;
            tx.execute(
                "UPDATE transport_bindings
                 SET membership_epoch=?1
                 WHERE stable_node_id IN (SELECT stable_node_id FROM members WHERE state='active')",
                [committed_membership_epoch],
            )?;
        }
        tx.execute(
            "UPDATE members
             SET state='active',auth_epoch=?2,membership_epoch=?3,updated_at=?4
             WHERE stable_node_id=?1
               AND auth_epoch=?2
               AND state IN ('pending','active')",
            params![stable, auth_epoch, committed_membership_epoch, now_unix],
        )?;
        anyhow::ensure!(
            tx.changes() == 1,
            "enrollment invite has no matching pending or active member generation"
        );
        let attestation_digest = attestation.digest()?;
        tx.execute(
            "INSERT INTO transport_bindings
             (stable_node_id,carrier,transport_identity,endpoint,assurance,auth_epoch,
              membership_epoch,expires_at,attestation_digest)
             VALUES (?1,?2,?3,?4,'signed_attestation',?5,?6,?7,?8)
             ON CONFLICT(stable_node_id,carrier) DO UPDATE SET
               transport_identity=excluded.transport_identity,
               endpoint=excluded.endpoint,assurance=excluded.assurance,
               auth_epoch=excluded.auth_epoch,membership_epoch=excluded.membership_epoch,
               expires_at=excluded.expires_at,
               attestation_digest=excluded.attestation_digest",
            params![
                stable,
                carrier.as_str(),
                authenticated_transport.as_str(),
                endpoint,
                auth_epoch,
                committed_membership_epoch,
                attestation.expires_at_unix,
                attestation_digest
            ],
        )?;
        tx.execute(
            "UPDATE enrollment_invites
             SET consumed_at=?2
             WHERE invite_id=?1 AND consumed_at IS NULL",
            params![invite_id, now_unix],
        )?;
        anyhow::ensure!(
            tx.changes() == 1,
            "enrollment invite consumption lost its serialized transaction"
        );
        tx.commit()?;
        Ok(EnrollmentReceipt {
            operation: "cluster.membership.confirm".into(),
            invite_id: invite_id.to_string(),
            stable_node_id: StableNodeId::parse(stable)?,
            state: MembershipState::Active,
            carrier,
            transport_identity: authenticated_transport.clone(),
            assurance: "signed_attestation".into(),
            auth_epoch: AuthEpoch::new(auth_epoch)?,
            issued_at_membership_epoch: MembershipEpoch::new(issued_at_membership_epoch)?,
            committed_membership_epoch: MembershipEpoch::new(committed_membership_epoch)?,
            expires_at_unix: attestation.expires_at_unix,
        })
    }

    pub fn record_legacy_pending(
        &self,
        carrier: CarrierKind,
        transport: &TransportIdentity,
        endpoint: &str,
        label: &str,
        now_unix: i64,
    ) -> Result<StableNodeId> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = tx
            .query_row(
                "SELECT stable_node_id FROM transport_bindings
                 WHERE carrier=?1 AND transport_identity=?2",
                params![carrier.as_str(), transport.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            tx.commit()?;
            return StableNodeId::parse(existing);
        }
        let authority_epoch: u64 = tx.query_row(
            "SELECT membership_epoch FROM authority_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let stable = StableNodeId::from_legacy_transport(transport);
        tx.execute(
            "INSERT INTO members
             (stable_node_id,label,state,auth_epoch,membership_epoch,created_at,updated_at)
             VALUES (?1,?2,'pending',1,?3,?4,?4)",
            params![stable.as_str(), label, authority_epoch, now_unix],
        )?;
        tx.execute(
            "INSERT INTO transport_bindings
             (stable_node_id,carrier,transport_identity,endpoint,assurance,auth_epoch,
              membership_epoch,expires_at,attestation_digest)
             VALUES (?1,?2,?3,?4,'legacy_unattested',1,?5,NULL,NULL)",
            params![
                stable.as_str(),
                carrier.as_str(),
                transport.as_str(),
                endpoint,
                authority_epoch
            ],
        )?;
        tx.commit()?;
        Ok(stable)
    }

    #[cfg(test)]
    pub fn confirm_attestation(
        &self,
        attestation: &EndpointAttestation,
        carrier: CarrierKind,
        authenticated_transport: &TransportIdentity,
        endpoint: &str,
        label: &str,
        now_unix: i64,
    ) -> Result<StableNodeId> {
        attestation.verify_exact(carrier, authenticated_transport, endpoint, now_unix)?;
        let digest = attestation.digest()?;
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (authority_epoch, revocation_floor): (u64, u64) = tx.query_row(
            "SELECT membership_epoch,revocation_floor
             FROM authority_meta WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        anyhow::ensure!(
            attestation.proof_membership_epoch.get() > revocation_floor,
            "attestation proof membership epoch is at or below the revocation floor"
        );
        anyhow::ensure!(
            attestation.proof_membership_epoch.get() >= authority_epoch,
            "attestation proof membership epoch is stale"
        );
        let committed_epoch = attestation.proof_membership_epoch.get();
        let existing: Option<(String, u64, u64)> = tx
            .query_row(
                "SELECT state,auth_epoch,membership_epoch FROM members WHERE stable_node_id=?1",
                [attestation.stable_node_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if let Some((state, auth_epoch, membership_epoch)) = existing {
            anyhow::ensure!(
                MembershipState::parse(&state)? != MembershipState::Revoked,
                "revoked stable node cannot be reactivated; enroll a new signing key"
            );
            anyhow::ensure!(
                auth_epoch == attestation.auth_epoch.get(),
                "attestation auth epoch does not match existing member"
            );
            anyhow::ensure!(
                MembershipState::parse(&state)? == MembershipState::Pending
                    || membership_epoch == authority_epoch,
                "existing member is not stamped at the current authority epoch"
            );
        }
        tx.execute(
            "UPDATE authority_meta SET membership_epoch=?1 WHERE singleton=1",
            [committed_epoch],
        )?;
        tx.execute(
            "UPDATE transport_bindings
             SET membership_epoch=?1
             WHERE stable_node_id IN (SELECT stable_node_id FROM members WHERE state='active')",
            [committed_epoch],
        )?;
        tx.execute(
            "UPDATE members SET membership_epoch=?1,updated_at=?2 WHERE state='active'",
            params![committed_epoch, now_unix],
        )?;
        tx.execute(
            "INSERT INTO members
             (stable_node_id,label,state,auth_epoch,membership_epoch,created_at,updated_at)
             VALUES (?1,?2,'active',?3,?4,?5,?5)
             ON CONFLICT(stable_node_id) DO UPDATE SET
               label=excluded.label,
               state='active',
               auth_epoch=excluded.auth_epoch,
               membership_epoch=excluded.membership_epoch,
               updated_at=excluded.updated_at",
            params![
                attestation.stable_node_id.as_str(),
                label,
                attestation.auth_epoch.get(),
                committed_epoch,
                now_unix
            ],
        )?;
        tx.execute(
            "INSERT INTO transport_bindings
             (stable_node_id,carrier,transport_identity,endpoint,assurance,auth_epoch,
              membership_epoch,expires_at,attestation_digest)
             VALUES (?1,?2,?3,?4,'signed_attestation',?5,?6,?7,?8)
             ON CONFLICT(stable_node_id,carrier) DO UPDATE SET
               transport_identity=excluded.transport_identity,
               endpoint=excluded.endpoint,
               assurance=excluded.assurance,
               auth_epoch=excluded.auth_epoch,
               membership_epoch=excluded.membership_epoch,
               expires_at=excluded.expires_at,
               attestation_digest=excluded.attestation_digest",
            params![
                attestation.stable_node_id.as_str(),
                carrier.as_str(),
                authenticated_transport.as_str(),
                endpoint,
                attestation.auth_epoch.get(),
                committed_epoch,
                attestation.expires_at_unix,
                digest
            ],
        )
        .context("persist exact carrier binding")?;
        tx.commit()?;
        Ok(attestation.stable_node_id.clone())
    }

    pub fn admit(
        &self,
        carrier: CarrierKind,
        authenticated_transport: &TransportIdentity,
        now_unix: i64,
    ) -> Result<MembershipGrant> {
        let conn = self.connection()?;
        let row: Option<(String, String, u64, u64, Option<i64>, i64)> = conn
            .query_row(
                "SELECT m.stable_node_id,m.state,m.auth_epoch,m.membership_epoch,
                        b.expires_at,
                        EXISTS(SELECT 1 FROM revocation_tombstones t
                               WHERE t.stable_node_id=m.stable_node_id
                                 AND t.auth_epoch=m.auth_epoch)
                 FROM transport_bindings b
                 JOIN members m ON m.stable_node_id=b.stable_node_id
                 JOIN authority_meta a ON a.singleton=1
                 WHERE b.carrier=?1 AND b.transport_identity=?2
                   AND b.auth_epoch=m.auth_epoch
                   AND b.membership_epoch=m.membership_epoch
                   AND m.membership_epoch=a.membership_epoch
                   AND m.membership_epoch>=a.revocation_floor
                   AND NOT EXISTS(
                     SELECT 1 FROM revocation_intents r
                     WHERE r.stable_node_id=m.stable_node_id
                       AND r.member_auth_epoch=m.auth_epoch
                       AND r.member_membership_epoch=m.membership_epoch
                       AND r.state IN ('pending','indeterminate')
                   )",
                params![carrier.as_str(), authenticated_transport.as_str()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((stable, state, auth_epoch, membership_epoch, expires_at, tombstoned)) = row
        else {
            anyhow::bail!("authenticated transport has no current membership binding");
        };
        anyhow::ensure!(
            MembershipState::parse(&state)? == MembershipState::Active,
            "membership is not active"
        );
        anyhow::ensure!(tombstoned == 0, "membership is permanently revoked");
        anyhow::ensure!(
            expires_at.is_none_or(|expiry| expiry > now_unix),
            "membership binding expired"
        );
        Ok(MembershipGrant {
            stable_node_id: StableNodeId::parse(stable)?,
            carrier,
            transport_identity: authenticated_transport.clone(),
            auth_epoch: AuthEpoch::new(auth_epoch)?,
            membership_epoch: MembershipEpoch::new(membership_epoch)?,
            expires_at_unix: expires_at,
            authority_path: self.path.clone(),
            effects: Arc::clone(&self.effects),
        })
    }

    pub fn admit_identifier(&self, identifier: &str, now_unix: i64) -> Result<MembershipGrant> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let stable = resolve_member(&tx, identifier)?
            .with_context(|| format!("unknown membership `{}`", identifier.trim()))?;
        let (carrier, transport): (String, String) = tx
            .query_row(
                "SELECT carrier,transport_identity FROM transport_bindings
                 WHERE stable_node_id=?1
                 ORDER BY CASE carrier WHEN 'peeroxide' THEN 0 ELSE 1 END",
                [stable.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context("active membership has no carrier binding")?;
        tx.commit()?;
        self.admit(
            CarrierKind::parse(&carrier)?,
            &TransportIdentity::parse(transport)?,
            now_unix,
        )
    }

    fn revalidate_grant(&self, grant: &MembershipGrant, now_unix: i64) -> Result<()> {
        let conn = self.connection()?;
        revalidate_grant_on(&conn, grant, now_unix)
    }

    fn generation_is_active(
        &self,
        stable_node_id: &StableNodeId,
        carrier: CarrierKind,
        auth_epoch: AuthEpoch,
        membership_epoch: MembershipEpoch,
        now_unix: i64,
    ) -> Result<bool> {
        let conn = self.connection()?;
        let active: i64 = conn.query_row(
            "SELECT EXISTS(
               SELECT 1
               FROM members m
               JOIN transport_bindings b ON b.stable_node_id=m.stable_node_id
               JOIN authority_meta a ON a.singleton=1
               WHERE m.stable_node_id=?1
                 AND m.state='active'
                 AND m.auth_epoch=?2
                 AND m.membership_epoch=?3
                 AND b.carrier=?4
                 AND b.auth_epoch=m.auth_epoch
                 AND b.membership_epoch=m.membership_epoch
                 AND (b.expires_at IS NULL OR b.expires_at>?5)
                 AND m.membership_epoch=a.membership_epoch
                 AND m.membership_epoch>=a.revocation_floor
                 AND NOT EXISTS(
                   SELECT 1 FROM revocation_tombstones t
                   WHERE t.stable_node_id=m.stable_node_id
                     AND t.auth_epoch=m.auth_epoch
                 )
                 AND NOT EXISTS(
                   SELECT 1 FROM revocation_intents r
                   WHERE r.stable_node_id=m.stable_node_id
                     AND r.member_auth_epoch=m.auth_epoch
                     AND r.member_membership_epoch=m.membership_epoch
                     AND r.state IN ('pending','indeterminate')
                 )
             )",
            params![
                stable_node_id.as_str(),
                auth_epoch.get(),
                membership_epoch.get(),
                carrier.as_str(),
                now_unix
            ],
            |row| row.get(0),
        )?;
        Ok(active == 1)
    }

    pub fn build_revoke_binding(
        &self,
        identifier: &str,
        reason: &str,
        source: &str,
        request_id: Option<&str>,
    ) -> Result<Option<MembershipRevokeBinding>> {
        let conn = self.connection()?;
        let tx = conn.unchecked_transaction()?;
        let stable_node_id = resolve_member(&tx, identifier)?;
        tx.commit()?;
        let Some(stable_node_id) = stable_node_id else {
            return Ok(None);
        };
        let snapshot = self.full_snapshot()?;
        let member = snapshot
            .members
            .iter()
            .find(|member| member.stable_node_id == stable_node_id)
            .context("resolved membership vanished from authority snapshot")?;
        if member.state == MembershipState::Revoked {
            return Ok(None);
        }
        anyhow::ensure!(
            member.state == MembershipState::Active && !member.tombstoned,
            "only an active membership can be revoked"
        );
        let binding = MembershipRevokeBinding {
            request_id: request_id
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| uuid::Uuid::now_v7().to_string()),
            stable_node_id,
            reason: reason.to_string(),
            source: source.to_string(),
            snapshot_version: snapshot.version,
            snapshot_digest: snapshot.canonical_digest()?,
            authority_epoch: snapshot.authority_epoch,
            member_auth_epoch: member.auth_epoch,
            member_membership_epoch: member.membership_epoch,
        };
        binding.validate()?;
        Ok(Some(binding))
    }

    fn revoke_receipt_for_identifier(&self, identifier: &str) -> Result<Option<RevokeReceipt>> {
        let conn = self.connection()?;
        let tx = conn.unchecked_transaction()?;
        let stable_node_id = resolve_member(&tx, identifier)?;
        tx.commit()?;
        match stable_node_id {
            Some(stable_node_id) => self.revoke_receipt(&stable_node_id),
            None => Ok(None),
        }
    }

    pub fn revocation_status(&self, request_id: &str) -> Result<Option<RevocationIntentStatus>> {
        let request_id =
            uuid::Uuid::parse_str(request_id).context("revocation request id is not a UUID")?;
        let conn = self.connection()?;
        revocation_status_on(&conn, &request_id.to_string())
    }

    pub fn unresolved_revocations(&self) -> Result<Vec<RevocationIntentStatus>> {
        let conn = self.connection()?;
        let request_ids = {
            let mut statement = conn.prepare(
                "SELECT request_id FROM revocation_intents
                 WHERE state IN ('pending','indeterminate')
                 ORDER BY created_at,request_id",
            )?;
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        request_ids
            .into_iter()
            .map(|request_id| {
                revocation_status_on(&conn, &request_id)?
                    .context("revocation intent disappeared during status read")
            })
            .collect()
    }

    fn start_revocation_intent(
        &self,
        binding: &MembershipRevokeBinding,
        external_effects_unclassified: bool,
        now_unix: i64,
    ) -> Result<RevocationIntentStatus> {
        binding.validate()?;
        let request_digest = binding.request_digest()?;
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = revocation_status_on(&tx, &binding.request_id)? {
            anyhow::ensure!(
                existing.request_digest == request_digest
                    && existing.stable_node_id == binding.stable_node_id
                    && existing.snapshot_version == binding.snapshot_version
                    && existing.snapshot_digest == binding.snapshot_digest
                    && existing.authority_epoch == binding.authority_epoch
                    && existing.member_auth_epoch == binding.member_auth_epoch
                    && existing.member_membership_epoch == binding.member_membership_epoch,
                "revocation request id was reused with a different immutable binding"
            );
            tx.commit()?;
            return Ok(existing);
        }

        let snapshot = full_snapshot_on(&tx, &self.path)?;
        anyhow::ensure!(
            snapshot.version == binding.snapshot_version
                && snapshot.canonical_digest()? == binding.snapshot_digest
                && snapshot.authority_epoch == binding.authority_epoch,
            "revocation confirmation snapshot is stale"
        );
        let member = snapshot
            .members
            .iter()
            .find(|member| member.stable_node_id == binding.stable_node_id)
            .context("revocation target is absent from the confirmed snapshot")?;
        anyhow::ensure!(
            member.state == MembershipState::Active
                && !member.tombstoned
                && member.auth_epoch == binding.member_auth_epoch
                && member.membership_epoch == binding.member_membership_epoch,
            "revocation target generation no longer matches the confirmed snapshot"
        );
        let conflicting: i64 = tx.query_row(
            "SELECT EXISTS(
               SELECT 1 FROM revocation_intents
               WHERE stable_node_id=?1
                 AND state IN ('pending','indeterminate')
             )",
            [binding.stable_node_id.as_str()],
            |row| row.get(0),
        )?;
        anyhow::ensure!(
            conflicting == 0,
            "membership already has an unresolved revocation request"
        );
        tx.execute(
            "INSERT INTO revocation_intents
             (request_id,request_digest,stable_node_id,reason,source,
              snapshot_version,snapshot_digest,authority_epoch,
              member_auth_epoch,member_membership_epoch,state,
              external_effects_unclassified,tombstone_committed,receipt_id,
              indeterminate_reason,created_at,updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'pending',?11,0,NULL,NULL,?12,?12)",
            params![
                binding.request_id,
                request_digest,
                binding.stable_node_id.as_str(),
                binding.reason,
                binding.source,
                binding.snapshot_version,
                binding.snapshot_digest,
                binding.authority_epoch.get(),
                binding.member_auth_epoch.get(),
                binding.member_membership_epoch.get(),
                i64::from(external_effects_unclassified),
                now_unix
            ],
        )?;
        let status = revocation_status_on(&tx, &binding.request_id)?
            .context("inserted revocation intent is unreadable")?;
        tx.commit()?;
        Ok(status)
    }

    fn mark_revocation_indeterminate(
        &self,
        request_id: &str,
        reason: &str,
        now_unix: i64,
    ) -> Result<()> {
        anyhow::ensure!(
            !reason.trim().is_empty()
                && reason.trim() == reason
                && reason.len() <= 512
                && !reason.chars().any(char::is_control),
            "indeterminate revocation reason is invalid"
        );
        let request_id =
            uuid::Uuid::parse_str(request_id).context("revocation request id is not a UUID")?;
        let conn = self.connection()?;
        let changed = conn.execute(
            "UPDATE revocation_intents
             SET state='indeterminate',
                 indeterminate_reason=COALESCE(indeterminate_reason,?2),
                 external_effects_unclassified=0,
                 updated_at=?3
             WHERE request_id=?1
               AND state IN ('pending','indeterminate')",
            params![request_id.to_string(), reason, now_unix],
        )?;
        anyhow::ensure!(
            changed == 1,
            "revocation intent is not unresolved or does not exist"
        );
        Ok(())
    }

    fn finalize_revocation_intent(
        &self,
        binding: &MembershipRevokeBinding,
        live_teardown: &str,
        teardown_details: &BTreeMap<String, CarrierTeardownReceipt>,
        now_unix: i64,
    ) -> Result<RevokeReceipt> {
        binding.validate()?;
        let request_digest = binding.request_digest()?;
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let status = revocation_status_on(&tx, &binding.request_id)?
            .context("revocation intent does not exist")?;
        anyhow::ensure!(
            status.request_digest == request_digest
                && status.stable_node_id == binding.stable_node_id
                && status.snapshot_digest == binding.snapshot_digest,
            "revocation intent immutable binding mismatch"
        );
        if status.tombstone_committed {
            tx.commit()?;
            return self
                .revoke_receipt(&binding.stable_node_id)?
                .context("completed revocation intent omitted its tombstone receipt");
        }
        anyhow::ensure!(
            matches!(
                status.state,
                RevocationIntentState::Pending | RevocationIntentState::Indeterminate
            ),
            "revocation intent is not finalizable"
        );
        anyhow::ensure!(
            !status.external_effects_unclassified,
            "revocation external effects remain durably unclassified"
        );
        let current: (String, u64, u64, u64) = tx.query_row(
            "SELECT m.state,m.auth_epoch,m.membership_epoch,a.membership_epoch
             FROM members m
             JOIN authority_meta a ON a.singleton=1
             WHERE m.stable_node_id=?1",
            [binding.stable_node_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        anyhow::ensure!(
            MembershipState::parse(&current.0)? == MembershipState::Active
                && current.1 == binding.member_auth_epoch.get()
                && current.2 == binding.member_membership_epoch.get()
                && current.3 == binding.authority_epoch.get(),
            "revocation target changed after intent admission"
        );

        let auth_epoch = binding.member_auth_epoch.next()?;
        let committed_epoch = binding.authority_epoch.next()?;
        let receipt_id = uuid::Uuid::now_v7().to_string();
        tx.execute(
            "UPDATE authority_meta
             SET membership_epoch=?1,revocation_floor=MAX(revocation_floor,?1)
             WHERE singleton=1",
            [committed_epoch.get()],
        )?;
        tx.execute(
            "UPDATE transport_bindings
             SET membership_epoch=?1
             WHERE stable_node_id IN (SELECT stable_node_id FROM members WHERE state='active')",
            [committed_epoch.get()],
        )?;
        tx.execute(
            "UPDATE members SET membership_epoch=?1,updated_at=?2 WHERE state='active'",
            params![committed_epoch.get(), now_unix],
        )?;
        tx.execute(
            "UPDATE members
             SET state='revoked',auth_epoch=?2,membership_epoch=?3,updated_at=?4,revoked_at=?4
             WHERE stable_node_id=?1 AND state='active' AND auth_epoch=?5",
            params![
                binding.stable_node_id.as_str(),
                auth_epoch.get(),
                committed_epoch.get(),
                now_unix,
                binding.member_auth_epoch.get()
            ],
        )?;
        anyhow::ensure!(
            tx.changes() == 1,
            "revocation target lost its serialized generation"
        );
        tx.execute(
            "INSERT INTO revocation_tombstones
             (stable_node_id,auth_epoch,membership_epoch,reason,revoked_at,receipt_id)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                binding.stable_node_id.as_str(),
                auth_epoch.get(),
                committed_epoch.get(),
                binding.reason,
                now_unix,
                receipt_id
            ],
        )?;
        let payload = serde_json::json!({
            "request_id": binding.request_id,
            "receipt_id": receipt_id,
            "stable_node_id": binding.stable_node_id,
            "auth_epoch": auth_epoch,
            "membership_epoch": committed_epoch,
            "reason": binding.reason,
            "intent_state": status.state,
        });
        for kind in ["membership_revoked", "audit", "teardown"] {
            tx.execute(
                "INSERT INTO membership_outbox
                 (kind,stable_node_id,auth_epoch,membership_epoch,payload,created_at)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    kind,
                    binding.stable_node_id.as_str(),
                    auth_epoch.get(),
                    committed_epoch.get(),
                    payload.to_string(),
                    now_unix
                ],
            )?;
        }
        tx.execute(
            "INSERT INTO teardown_receipts
             (receipt_id,stable_node_id,status,details,updated_at)
             VALUES (?1,?2,?3,?4,?5)",
            params![
                receipt_id,
                binding.stable_node_id.as_str(),
                live_teardown,
                serde_json::to_string(teardown_details)?,
                now_unix
            ],
        )?;
        tx.execute(
            "UPDATE revocation_intents
             SET state=CASE WHEN state='pending' THEN 'completed' ELSE state END,
                 tombstone_committed=1,receipt_id=?2,updated_at=?3
             WHERE request_id=?1 AND state IN ('pending','indeterminate')",
            params![binding.request_id, receipt_id, now_unix],
        )?;
        anyhow::ensure!(
            tx.changes() == 1,
            "revocation intent finalization lost its serialized state"
        );
        tx.commit()?;

        let post_state = self.full_snapshot()?;
        let post_state_digest = post_state.canonical_digest()?;
        Ok(RevokeReceipt {
            operation: "cluster.membership.revoke".into(),
            request_id: binding.request_id.clone(),
            intent_state: if status.state == RevocationIntentState::Pending {
                RevocationIntentState::Completed
            } else {
                status.state
            },
            indeterminate_reason: status.indeterminate_reason,
            receipt_id,
            stable_node_id: binding.stable_node_id.clone(),
            auth_epoch,
            membership_epoch: committed_epoch,
            authority_path: post_state.authority_path,
            post_state_digest,
            tombstone_committed: true,
            already_revoked: false,
            live_teardown: live_teardown.to_string(),
            audit_pending: true,
            pending_outbox: 3,
            per_carrier_teardown: teardown_details.clone(),
            outbox_error: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn revoke(
        &self,
        identifier: &str,
        reason: &str,
        now_unix: i64,
        live_teardown: &str,
    ) -> Result<Option<RevokeReceipt>> {
        let request_id = uuid::Uuid::now_v7().to_string();
        let Some(binding) =
            self.build_revoke_binding(identifier, reason, "membership_store", Some(&request_id))?
        else {
            return self.revoke_receipt_for_identifier(identifier);
        };
        self.start_revocation_intent(&binding, false, now_unix)?;
        self.finalize_revocation_intent(&binding, live_teardown, &BTreeMap::new(), now_unix)
            .map(Some)
    }

    pub fn mark_outbox_delivered(&self, id: i64, delivered_at: i64) -> Result<()> {
        let conn = self.connection()?;
        let changed = conn.execute(
            "UPDATE membership_outbox SET delivered_at=?2
             WHERE id=?1 AND delivered_at IS NULL",
            params![id, delivered_at],
        )?;
        anyhow::ensure!(
            changed == 1,
            "membership outbox event {id} was concurrently delivered or disappeared"
        );
        Ok(())
    }

    pub fn pending_outbox_count(&self) -> Result<u64> {
        let conn = self.connection()?;
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM membership_outbox WHERE delivered_at IS NULL",
            [],
            |row| row.get(0),
        )?)
    }

    fn pending_outbox(&self) -> Result<Vec<PendingOutboxEvent>> {
        let conn = self.connection()?;
        let mut statement = conn.prepare(
            "SELECT id,kind,stable_node_id,auth_epoch,membership_epoch,payload
             FROM membership_outbox WHERE delivered_at IS NULL ORDER BY id",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u64>(3)?,
                    row.get::<_, u64>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(
                |(id, kind, stable, auth_epoch, membership_epoch, payload)| {
                    let receipt_id = serde_json::from_str::<serde_json::Value>(&payload)
                        .context("parse membership outbox payload")?
                        .get("receipt_id")
                        .and_then(|value| value.as_str())
                        .context("membership outbox payload has no receipt id")?
                        .to_string();
                    Ok(PendingOutboxEvent {
                        id,
                        kind,
                        stable_node_id: StableNodeId::parse(stable)?,
                        receipt_id,
                        auth_epoch: AuthEpoch::new(auth_epoch)?,
                        membership_epoch: MembershipEpoch::new(membership_epoch)?,
                        payload,
                    })
                },
            )
            .collect()
    }

    fn update_teardown(
        &self,
        receipt_id: &str,
        status: &str,
        details: &BTreeMap<String, CarrierTeardownReceipt>,
        now_unix: i64,
    ) -> Result<()> {
        let conn = self.connection()?;
        let existing: Option<(String, Option<String>)> = conn
            .query_row(
                "SELECT status,details FROM teardown_receipts WHERE receipt_id=?1",
                [receipt_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((existing_status, existing_details)) = existing else {
            anyhow::bail!("teardown receipt `{receipt_id}` does not exist");
        };
        let mut merged: BTreeMap<String, CarrierTeardownReceipt> = existing_details
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .context("parse existing carrier teardown receipt")?
            .unwrap_or_default();
        for (carrier, update) in details {
            let receipt = merged.entry(carrier.clone()).or_default();
            receipt.closed_sessions = receipt.closed_sessions.max(update.closed_sessions);
            receipt.routes_evicted = receipt.routes_evicted.max(update.routes_evicted);
            receipt.queued_effects_dropped = receipt
                .queued_effects_dropped
                .max(update.queued_effects_dropped);
            if matches!(
                receipt.status.as_str(),
                "" | "not_running" | "no_live_sessions"
            ) || matches!(update.status.as_str(), "partial" | "pending")
            {
                receipt.status = update.status.clone();
            }
        }
        // A short carrier teardown observation is never upgraded merely
        // because a later registry lookup finds no route. Only carrier-owned
        // evidence may turn partial into closed.
        let merged_status = if existing_status == "partial" {
            "partial"
        } else {
            status
        };
        conn.execute(
            "UPDATE teardown_receipts
             SET status=?2,details=?3,updated_at=?4 WHERE receipt_id=?1",
            params![
                receipt_id,
                merged_status,
                serde_json::to_string(&merged)?,
                now_unix
            ],
        )?;
        Ok(())
    }

    fn append_membership_audit(&self, event: &PendingOutboxEvent, now_unix: i64) -> Result<()> {
        let conn = self.connection()?;
        conn.execute(
            "INSERT OR IGNORE INTO membership_audit
             (receipt_id,kind,stable_node_id,auth_epoch,membership_epoch,payload,recorded_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                event.receipt_id,
                event.kind,
                event.stable_node_id.as_str(),
                event.auth_epoch.get(),
                event.membership_epoch.get(),
                event.payload,
                now_unix
            ],
        )?;
        Ok(())
    }

    fn apply_membership_projection(&self, event: &PendingOutboxEvent, now_unix: i64) -> Result<()> {
        let conn = self.connection()?;
        conn.execute(
            "INSERT OR IGNORE INTO membership_projection_log
             (receipt_id,stable_node_id,auth_epoch,membership_epoch,payload,applied_at)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                event.receipt_id,
                event.stable_node_id.as_str(),
                event.auth_epoch.get(),
                event.membership_epoch.get(),
                event.payload,
                now_unix
            ],
        )?;
        Ok(())
    }

    pub fn revoke_receipt(&self, stable_node_id: &StableNodeId) -> Result<Option<RevokeReceipt>> {
        let conn = self.connection()?;
        let row: Option<(
            u64,
            u64,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        )> = conn
            .query_row(
                "SELECT t.auth_epoch,t.membership_epoch,t.receipt_id,r.status,r.details,
                        i.request_id,i.state,i.indeterminate_reason
                 FROM revocation_tombstones t
                 JOIN teardown_receipts r ON r.receipt_id=t.receipt_id
                 LEFT JOIN revocation_intents i ON i.receipt_id=t.receipt_id
                 WHERE t.stable_node_id=?1
                 ORDER BY t.auth_epoch DESC LIMIT 1",
                [stable_node_id.as_str()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            auth,
            membership,
            receipt_id,
            status,
            details,
            request_id,
            intent_state,
            indeterminate_reason,
        )) = row
        else {
            return Ok(None);
        };
        let pending_outbox: u64 = conn.query_row(
            "SELECT COUNT(*) FROM membership_outbox
             WHERE stable_node_id=?1 AND auth_epoch=?2 AND membership_epoch=?3
               AND delivered_at IS NULL",
            params![stable_node_id.as_str(), auth, membership],
            |row| row.get(0),
        )?;
        let audit_pending: bool = conn.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM membership_outbox
                 WHERE stable_node_id=?1 AND auth_epoch=?2 AND membership_epoch=?3
                   AND kind='audit' AND delivered_at IS NULL
             )",
            params![stable_node_id.as_str(), auth, membership],
            |row| row.get(0),
        )?;
        let per_carrier_teardown = details
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .context("parse persisted carrier teardown receipt")?
            .unwrap_or_default();
        Ok(Some(RevokeReceipt {
            operation: "cluster.membership.revoke".into(),
            request_id: request_id.unwrap_or_else(|| receipt_id.clone()),
            intent_state: intent_state
                .as_deref()
                .map(RevocationIntentState::parse)
                .transpose()?
                .unwrap_or(RevocationIntentState::Completed),
            indeterminate_reason,
            receipt_id,
            stable_node_id: stable_node_id.clone(),
            auth_epoch: AuthEpoch::new(auth)?,
            membership_epoch: MembershipEpoch::new(membership)?,
            authority_path: self.path.clone(),
            post_state_digest: String::new(),
            tombstone_committed: true,
            already_revoked: true,
            live_teardown: status,
            audit_pending,
            pending_outbox,
            per_carrier_teardown,
            outbox_error: None,
        }))
    }

    pub fn snapshot(&self) -> Result<Vec<MemberSnapshot>> {
        let conn = self.connection()?;
        let mut member_statement = conn.prepare(
            "SELECT m.stable_node_id,m.label,m.state,m.auth_epoch,m.membership_epoch,
                    EXISTS(SELECT 1 FROM revocation_tombstones t
                           WHERE t.stable_node_id=m.stable_node_id
                             AND t.auth_epoch=m.auth_epoch)
             FROM members m ORDER BY m.stable_node_id",
        )?;
        let members = member_statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u64>(3)?,
                    row.get::<_, u64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut result = Vec::with_capacity(members.len());
        for (stable, label, state, auth_epoch, membership_epoch, tombstoned) in members {
            let stable_id = StableNodeId::parse(stable)?;
            let mut binding_statement = conn.prepare(
                "SELECT carrier,transport_identity,endpoint,assurance,auth_epoch,
                        membership_epoch,expires_at
                 FROM transport_bindings WHERE stable_node_id=?1 ORDER BY carrier",
            )?;
            let raw_bindings = binding_statement
                .query_map([stable_id.as_str()], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, u64>(4)?,
                        row.get::<_, u64>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let bindings = raw_bindings
                .into_iter()
                .map(
                    |(
                        carrier,
                        transport_identity,
                        endpoint,
                        assurance,
                        auth_epoch,
                        membership_epoch,
                        expires_at_unix,
                    )| {
                        Ok(CarrierBindingSnapshot {
                            carrier: CarrierKind::parse(&carrier)?,
                            transport_identity: TransportIdentity::parse(transport_identity)?,
                            endpoint,
                            assurance,
                            auth_epoch: AuthEpoch::new(auth_epoch)?,
                            membership_epoch: MembershipEpoch::new(membership_epoch)?,
                            expires_at_unix,
                        })
                    },
                )
                .collect::<Result<Vec<_>>>()?;
            result.push(MemberSnapshot {
                stable_node_id: stable_id,
                label,
                state: MembershipState::parse(&state)?,
                auth_epoch: AuthEpoch::new(auth_epoch)?,
                membership_epoch: MembershipEpoch::new(membership_epoch)?,
                tombstoned: tombstoned != 0,
                bindings,
            });
        }
        Ok(result)
    }

    fn import_legacy_once(&self, home: &Path) -> Result<()> {
        let mut conn = self.connection()?;
        let imported: u64 = conn.query_row(
            "SELECT legacy_import_generation FROM authority_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if imported > 0 {
            return Ok(());
        }
        let legacy = crate::cluster::registry::load(home)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for peer in legacy.peers {
            let transport = TransportIdentity::parse(peer.pub_key_hex)?;
            let stable = StableNodeId::from_legacy_transport(&transport);
            tx.execute(
                "INSERT OR IGNORE INTO members
                 (stable_node_id,label,state,auth_epoch,membership_epoch,created_at,updated_at)
                 VALUES (?1,?2,'pending',1,1,?3,?3)",
                params![stable.as_str(), peer.instance_label, peer.paired_at_unix],
            )?;
            tx.execute(
                "INSERT OR IGNORE INTO transport_bindings
                 (stable_node_id,carrier,transport_identity,endpoint,assurance,auth_epoch,
                  membership_epoch,expires_at,attestation_digest)
                 VALUES (?1,'peeroxide',?2,?3,'legacy_unattested',1,1,NULL,NULL)",
                params![stable.as_str(), transport.as_str(), peer.addr],
            )?;
        }
        tx.execute(
            "UPDATE authority_meta SET legacy_import_generation=1 WHERE singleton=1",
            [],
        )?;
        tx.commit()?;
        Ok(())
    }
}

fn revocation_status_on(
    conn: &Connection,
    request_id: &str,
) -> Result<Option<RevocationIntentStatus>> {
    let row: Option<(
        String,
        String,
        String,
        String,
        String,
        u16,
        String,
        u64,
        u64,
        u64,
        i64,
        i64,
        Option<String>,
        Option<String>,
        i64,
        i64,
    )> = conn
        .query_row(
            "SELECT request_digest,stable_node_id,state,reason,source,
                    snapshot_version,snapshot_digest,
                    authority_epoch,member_auth_epoch,member_membership_epoch,
                    external_effects_unclassified,tombstone_committed,
                    receipt_id,indeterminate_reason,
                    created_at,updated_at
             FROM revocation_intents WHERE request_id=?1",
            [request_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                    row.get(15)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(
            request_digest,
            stable_node_id,
            state,
            reason,
            source,
            snapshot_version,
            snapshot_digest,
            authority_epoch,
            member_auth_epoch,
            member_membership_epoch,
            external_effects_unclassified,
            tombstone_committed,
            receipt_id,
            indeterminate_reason,
            created_at_unix,
            updated_at_unix,
        )| {
            Ok(RevocationIntentStatus {
                operation: "cluster.membership.revoke.status".into(),
                request_id: request_id.to_string(),
                request_digest,
                stable_node_id: StableNodeId::parse(stable_node_id)?,
                reason,
                source,
                state: RevocationIntentState::parse(&state)?,
                snapshot_version,
                snapshot_digest,
                authority_epoch: MembershipEpoch::new(authority_epoch)?,
                member_auth_epoch: AuthEpoch::new(member_auth_epoch)?,
                member_membership_epoch: MembershipEpoch::new(member_membership_epoch)?,
                external_effects_unclassified: external_effects_unclassified != 0,
                tombstone_committed: tombstone_committed != 0,
                receipt_id,
                indeterminate_reason,
                created_at_unix,
                updated_at_unix,
            })
        },
    )
    .transpose()
}

fn full_snapshot_on(conn: &Connection, authority_path: &Path) -> Result<MembershipSnapshot> {
    let (authority_epoch, revocation_floor): (u64, u64) = conn.query_row(
        "SELECT membership_epoch,revocation_floor FROM authority_meta WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let pending_outbox = conn.query_row(
        "SELECT COUNT(*) FROM membership_outbox WHERE delivered_at IS NULL",
        [],
        |row| row.get(0),
    )?;
    let mut member_statement = conn.prepare(
        "SELECT m.stable_node_id,m.label,m.state,m.auth_epoch,m.membership_epoch,
                EXISTS(SELECT 1 FROM revocation_tombstones t
                       WHERE t.stable_node_id=m.stable_node_id
                         AND t.auth_epoch=m.auth_epoch)
         FROM members m ORDER BY m.stable_node_id",
    )?;
    let raw_members = member_statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, u64>(3)?,
                row.get::<_, u64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut members = Vec::with_capacity(raw_members.len());
    for (stable, label, state, auth_epoch, membership_epoch, tombstoned) in raw_members {
        let stable_node_id = StableNodeId::parse(stable)?;
        let mut binding_statement = conn.prepare(
            "SELECT carrier,transport_identity,endpoint,assurance,auth_epoch,
                    membership_epoch,expires_at
             FROM transport_bindings WHERE stable_node_id=?1 ORDER BY carrier",
        )?;
        let raw_bindings = binding_statement
            .query_map([stable_node_id.as_str()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, u64>(4)?,
                    row.get::<_, u64>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let bindings = raw_bindings
            .into_iter()
            .map(
                |(
                    carrier,
                    transport_identity,
                    endpoint,
                    assurance,
                    auth_epoch,
                    membership_epoch,
                    expires_at_unix,
                )| {
                    Ok(CarrierBindingSnapshot {
                        carrier: CarrierKind::parse(&carrier)?,
                        transport_identity: TransportIdentity::parse(transport_identity)?,
                        endpoint,
                        assurance,
                        auth_epoch: AuthEpoch::new(auth_epoch)?,
                        membership_epoch: MembershipEpoch::new(membership_epoch)?,
                        expires_at_unix,
                    })
                },
            )
            .collect::<Result<Vec<_>>>()?;
        members.push(MemberSnapshot {
            stable_node_id,
            label,
            state: MembershipState::parse(&state)?,
            auth_epoch: AuthEpoch::new(auth_epoch)?,
            membership_epoch: MembershipEpoch::new(membership_epoch)?,
            tombstoned: tombstoned != 0,
            bindings,
        });
    }
    Ok(MembershipSnapshot {
        version: MEMBERSHIP_SNAPSHOT_VERSION,
        authority_path: authority_path.to_path_buf(),
        authority_epoch: MembershipEpoch::new(authority_epoch)?,
        revocation_floor: MembershipEpoch::new(revocation_floor)?,
        pending_outbox,
        members,
    })
}

fn revalidate_grant_on(conn: &Connection, grant: &MembershipGrant, now_unix: i64) -> Result<()> {
    anyhow::ensure!(
        grant.expires_at_unix.is_none_or(|expiry| expiry > now_unix),
        "membership grant expired"
    );
    let current: Option<(String, u64, u64, Option<i64>, i64, i64, u64, u64)> = conn
        .query_row(
            "SELECT m.state,m.auth_epoch,m.membership_epoch,b.expires_at,
                    EXISTS(SELECT 1 FROM revocation_tombstones t
                           WHERE t.stable_node_id=m.stable_node_id
                             AND t.auth_epoch=m.auth_epoch),
                    EXISTS(SELECT 1 FROM revocation_intents r
                           WHERE r.stable_node_id=m.stable_node_id
                             AND r.member_auth_epoch=m.auth_epoch
                             AND r.member_membership_epoch=m.membership_epoch
                             AND r.state IN ('pending','indeterminate')),
                    a.membership_epoch,a.revocation_floor
             FROM members m
             JOIN transport_bindings b ON b.stable_node_id=m.stable_node_id
             JOIN authority_meta a ON a.singleton=1
             WHERE m.stable_node_id=?1 AND b.carrier=?2 AND b.transport_identity=?3
               AND b.auth_epoch=m.auth_epoch AND b.membership_epoch=m.membership_epoch",
            params![
                grant.stable_node_id.as_str(),
                grant.carrier.as_str(),
                grant.transport_identity.as_str()
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .optional()?;
    let Some((
        state,
        auth_epoch,
        membership_epoch,
        expires_at,
        tombstoned,
        revocation_pending,
        authority_epoch,
        revocation_floor,
    )) = current
    else {
        anyhow::bail!("membership grant binding no longer exists");
    };
    anyhow::ensure!(
        MembershipState::parse(&state)? == MembershipState::Active,
        "membership grant is no longer active"
    );
    anyhow::ensure!(tombstoned == 0, "membership grant is revoked");
    anyhow::ensure!(
        revocation_pending == 0,
        "membership grant has a pending revocation intent"
    );
    anyhow::ensure!(
        auth_epoch == grant.auth_epoch.get() && membership_epoch == grant.membership_epoch.get(),
        "membership grant epoch is stale"
    );
    anyhow::ensure!(
        membership_epoch == authority_epoch && membership_epoch >= revocation_floor,
        "membership grant is below the authority revocation floor"
    );
    anyhow::ensure!(
        expires_at.is_none_or(|expiry| expiry > now_unix),
        "membership grant binding expired"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn invitation_digest(
    invite_id: &str,
    stable_node_id: &StableNodeId,
    signing_public_key: &[u8; 32],
    carrier: CarrierKind,
    transport_identity: &TransportIdentity,
    endpoint: &str,
    label: &str,
    auth_epoch: AuthEpoch,
    issued_at_membership_epoch: MembershipEpoch,
    expires_at_unix: i64,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"neoth-membership-invite-v1\0");
    for field in [
        invite_id.as_bytes(),
        stable_node_id.as_str().as_bytes(),
        carrier.as_str().as_bytes(),
        transport_identity.as_str().as_bytes(),
        endpoint.as_bytes(),
        label.as_bytes(),
    ] {
        digest.update((field.len() as u64).to_le_bytes());
        digest.update(field);
    }
    digest.update(signing_public_key);
    digest.update(auth_epoch.get().to_le_bytes());
    digest.update(issued_at_membership_epoch.get().to_le_bytes());
    digest.update(expires_at_unix.to_le_bytes());
    hex::encode(digest.finalize())
}

fn migrate(conn: &Connection) -> Result<()> {
    let current: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    anyhow::ensure!(
        current <= AUTHORITY_SCHEMA_VERSION,
        "membership DB schema {current} is newer than supported {AUTHORITY_SCHEMA_VERSION}"
    );
    if current == AUTHORITY_SCHEMA_VERSION {
        return Ok(());
    }
    let tx = conn.unchecked_transaction()?;
    if current == 0 {
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS authority_meta (
             singleton INTEGER PRIMARY KEY CHECK(singleton=1),
             authority_mode TEXT NOT NULL,
             membership_epoch INTEGER NOT NULL CHECK(membership_epoch > 0),
             revocation_floor INTEGER NOT NULL CHECK(revocation_floor > 0),
             legacy_import_generation INTEGER NOT NULL CHECK(legacy_import_generation >= 0)
         );
         INSERT OR IGNORE INTO authority_meta
           (singleton,authority_mode,membership_epoch,revocation_floor,legacy_import_generation)
           VALUES (1,'local_owner',1,1,0);
         CREATE TABLE IF NOT EXISTS members (
             stable_node_id TEXT PRIMARY KEY,
             label TEXT NOT NULL,
             state TEXT NOT NULL CHECK(state IN ('discovered','pending','active','revoked')),
             auth_epoch INTEGER NOT NULL CHECK(auth_epoch > 0),
             membership_epoch INTEGER NOT NULL CHECK(membership_epoch > 0),
             created_at INTEGER NOT NULL,
             updated_at INTEGER NOT NULL,
             revoked_at INTEGER
         );
         CREATE TABLE IF NOT EXISTS transport_bindings (
             stable_node_id TEXT NOT NULL REFERENCES members(stable_node_id),
             carrier TEXT NOT NULL CHECK(carrier IN ('peeroxide','iroh')),
             transport_identity TEXT NOT NULL,
             endpoint TEXT NOT NULL,
             assurance TEXT NOT NULL CHECK(assurance IN ('signed_attestation','legacy_unattested')),
             auth_epoch INTEGER NOT NULL CHECK(auth_epoch > 0),
             membership_epoch INTEGER NOT NULL CHECK(membership_epoch > 0),
             expires_at INTEGER,
             attestation_digest TEXT,
             PRIMARY KEY(stable_node_id,carrier),
             UNIQUE(carrier,transport_identity)
         );
         CREATE TABLE IF NOT EXISTS revocation_tombstones (
             stable_node_id TEXT NOT NULL REFERENCES members(stable_node_id),
             auth_epoch INTEGER NOT NULL,
             membership_epoch INTEGER NOT NULL,
             reason TEXT NOT NULL,
             revoked_at INTEGER NOT NULL,
             receipt_id TEXT NOT NULL UNIQUE,
             PRIMARY KEY(stable_node_id,auth_epoch)
         );
         CREATE TABLE IF NOT EXISTS membership_outbox (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             kind TEXT NOT NULL,
             stable_node_id TEXT NOT NULL,
             auth_epoch INTEGER NOT NULL,
             membership_epoch INTEGER NOT NULL,
             payload TEXT NOT NULL,
             created_at INTEGER NOT NULL,
             delivered_at INTEGER
         );
         CREATE TABLE IF NOT EXISTS teardown_receipts (
             receipt_id TEXT PRIMARY KEY,
             stable_node_id TEXT NOT NULL,
             status TEXT NOT NULL,
             details TEXT,
             updated_at INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS enrollment_invites (
             invite_id TEXT PRIMARY KEY,
             invitation_digest TEXT NOT NULL UNIQUE,
             stable_node_id TEXT NOT NULL REFERENCES members(stable_node_id),
             signing_public_key BLOB NOT NULL CHECK(length(signing_public_key)=32),
             carrier TEXT NOT NULL CHECK(carrier IN ('peeroxide','iroh')),
             transport_identity TEXT NOT NULL,
             endpoint TEXT NOT NULL,
             label TEXT NOT NULL,
             auth_epoch INTEGER NOT NULL CHECK(auth_epoch > 0),
             membership_epoch INTEGER NOT NULL CHECK(membership_epoch > 0),
             created_at INTEGER NOT NULL,
             expires_at INTEGER NOT NULL,
             consumed_at INTEGER
         );
         CREATE TABLE IF NOT EXISTS membership_audit (
             receipt_id TEXT NOT NULL,
             kind TEXT NOT NULL,
             stable_node_id TEXT NOT NULL,
             auth_epoch INTEGER NOT NULL,
             membership_epoch INTEGER NOT NULL,
             payload TEXT NOT NULL,
             recorded_at INTEGER NOT NULL,
             PRIMARY KEY(receipt_id,kind)
         );
         CREATE TABLE IF NOT EXISTS membership_projection_log (
             receipt_id TEXT PRIMARY KEY,
             stable_node_id TEXT NOT NULL,
             auth_epoch INTEGER NOT NULL,
             membership_epoch INTEGER NOT NULL,
             payload TEXT NOT NULL,
             applied_at INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS revocation_intents (
             request_id TEXT PRIMARY KEY,
             request_digest TEXT NOT NULL CHECK(length(request_digest)=64),
             stable_node_id TEXT NOT NULL REFERENCES members(stable_node_id),
             reason TEXT NOT NULL,
             source TEXT NOT NULL,
             snapshot_version INTEGER NOT NULL CHECK(snapshot_version > 0),
             snapshot_digest TEXT NOT NULL CHECK(length(snapshot_digest)=64),
             authority_epoch INTEGER NOT NULL CHECK(authority_epoch > 0),
             member_auth_epoch INTEGER NOT NULL CHECK(member_auth_epoch > 0),
             member_membership_epoch INTEGER NOT NULL CHECK(member_membership_epoch > 0),
             state TEXT NOT NULL CHECK(state IN ('pending','indeterminate','completed','not_found')),
             external_effects_unclassified INTEGER NOT NULL DEFAULT 0
                 CHECK(external_effects_unclassified IN (0,1)),
             tombstone_committed INTEGER NOT NULL DEFAULT 0 CHECK(tombstone_committed IN (0,1)),
             receipt_id TEXT,
             indeterminate_reason TEXT,
             created_at INTEGER NOT NULL,
             updated_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS revocation_intents_target_state
             ON revocation_intents(stable_node_id,state);
         PRAGMA user_version=4;",
        )?;
    } else if current == 1 {
        tx.execute_batch(
            "ALTER TABLE teardown_receipts ADD COLUMN details TEXT;
             CREATE TABLE enrollment_invites (
                 invite_id TEXT PRIMARY KEY,
                 invitation_digest TEXT NOT NULL UNIQUE,
                 stable_node_id TEXT NOT NULL REFERENCES members(stable_node_id),
                 signing_public_key BLOB NOT NULL CHECK(length(signing_public_key)=32),
                 carrier TEXT NOT NULL CHECK(carrier IN ('peeroxide','iroh')),
                 transport_identity TEXT NOT NULL,
                 endpoint TEXT NOT NULL,
                 label TEXT NOT NULL,
                 auth_epoch INTEGER NOT NULL CHECK(auth_epoch > 0),
                 membership_epoch INTEGER NOT NULL CHECK(membership_epoch > 0),
                 created_at INTEGER NOT NULL,
                 expires_at INTEGER NOT NULL,
                 consumed_at INTEGER
             );
             CREATE TABLE membership_audit (
                 receipt_id TEXT NOT NULL,
                 kind TEXT NOT NULL,
                 stable_node_id TEXT NOT NULL,
                 auth_epoch INTEGER NOT NULL,
                 membership_epoch INTEGER NOT NULL,
                 payload TEXT NOT NULL,
                 recorded_at INTEGER NOT NULL,
                 PRIMARY KEY(receipt_id,kind)
             );
             CREATE TABLE membership_projection_log (
                 receipt_id TEXT PRIMARY KEY,
                 stable_node_id TEXT NOT NULL,
                 auth_epoch INTEGER NOT NULL,
                 membership_epoch INTEGER NOT NULL,
                 payload TEXT NOT NULL,
                 applied_at INTEGER NOT NULL
             );
             ALTER TABLE revocation_tombstones RENAME TO revocation_tombstones_v2;
             CREATE TABLE revocation_tombstones (
                 stable_node_id TEXT NOT NULL REFERENCES members(stable_node_id),
                 auth_epoch INTEGER NOT NULL,
                 membership_epoch INTEGER NOT NULL,
                 reason TEXT NOT NULL,
                 revoked_at INTEGER NOT NULL,
                 receipt_id TEXT NOT NULL UNIQUE,
                 PRIMARY KEY(stable_node_id,auth_epoch)
             );
             INSERT INTO revocation_tombstones
                 (stable_node_id,auth_epoch,membership_epoch,reason,revoked_at,receipt_id)
             SELECT stable_node_id,auth_epoch,membership_epoch,reason,revoked_at,receipt_id
             FROM revocation_tombstones_v2;
             DROP TABLE revocation_tombstones_v2;
             CREATE TABLE revocation_intents (
                 request_id TEXT PRIMARY KEY,
                 request_digest TEXT NOT NULL CHECK(length(request_digest)=64),
                 stable_node_id TEXT NOT NULL REFERENCES members(stable_node_id),
                 reason TEXT NOT NULL,
                 source TEXT NOT NULL,
                 snapshot_version INTEGER NOT NULL CHECK(snapshot_version > 0),
                 snapshot_digest TEXT NOT NULL CHECK(length(snapshot_digest)=64),
                 authority_epoch INTEGER NOT NULL CHECK(authority_epoch > 0),
                 member_auth_epoch INTEGER NOT NULL CHECK(member_auth_epoch > 0),
                 member_membership_epoch INTEGER NOT NULL CHECK(member_membership_epoch > 0),
                 state TEXT NOT NULL CHECK(state IN ('pending','indeterminate','completed','not_found')),
                 external_effects_unclassified INTEGER NOT NULL DEFAULT 0
                     CHECK(external_effects_unclassified IN (0,1)),
                 tombstone_committed INTEGER NOT NULL DEFAULT 0 CHECK(tombstone_committed IN (0,1)),
                 receipt_id TEXT,
                 indeterminate_reason TEXT,
                 created_at INTEGER NOT NULL,
                 updated_at INTEGER NOT NULL
             );
             CREATE INDEX revocation_intents_target_state
                 ON revocation_intents(stable_node_id,state);
             PRAGMA user_version=4;",
        )?;
    } else if current == 2 {
        tx.execute_batch(
            "ALTER TABLE revocation_tombstones RENAME TO revocation_tombstones_v2;
             CREATE TABLE revocation_tombstones (
                 stable_node_id TEXT NOT NULL REFERENCES members(stable_node_id),
                 auth_epoch INTEGER NOT NULL,
                 membership_epoch INTEGER NOT NULL,
                 reason TEXT NOT NULL,
                 revoked_at INTEGER NOT NULL,
                 receipt_id TEXT NOT NULL UNIQUE,
                 PRIMARY KEY(stable_node_id,auth_epoch)
             );
             INSERT INTO revocation_tombstones
                 (stable_node_id,auth_epoch,membership_epoch,reason,revoked_at,receipt_id)
             SELECT stable_node_id,auth_epoch,membership_epoch,reason,revoked_at,receipt_id
             FROM revocation_tombstones_v2;
             DROP TABLE revocation_tombstones_v2;
             CREATE TABLE revocation_intents (
                 request_id TEXT PRIMARY KEY,
                 request_digest TEXT NOT NULL CHECK(length(request_digest)=64),
                 stable_node_id TEXT NOT NULL REFERENCES members(stable_node_id),
                 reason TEXT NOT NULL,
                 source TEXT NOT NULL,
                 snapshot_version INTEGER NOT NULL CHECK(snapshot_version > 0),
                 snapshot_digest TEXT NOT NULL CHECK(length(snapshot_digest)=64),
                 authority_epoch INTEGER NOT NULL CHECK(authority_epoch > 0),
                 member_auth_epoch INTEGER NOT NULL CHECK(member_auth_epoch > 0),
                 member_membership_epoch INTEGER NOT NULL CHECK(member_membership_epoch > 0),
                 state TEXT NOT NULL CHECK(state IN ('pending','indeterminate','completed','not_found')),
                 external_effects_unclassified INTEGER NOT NULL DEFAULT 0
                     CHECK(external_effects_unclassified IN (0,1)),
                 tombstone_committed INTEGER NOT NULL DEFAULT 0 CHECK(tombstone_committed IN (0,1)),
                 receipt_id TEXT,
                 indeterminate_reason TEXT,
                 created_at INTEGER NOT NULL,
                 updated_at INTEGER NOT NULL
             );
             CREATE INDEX revocation_intents_target_state
                 ON revocation_intents(stable_node_id,state);
             PRAGMA user_version=4;",
        )?;
    } else if current == 3 {
        tx.execute_batch(
            "CREATE TABLE revocation_intents (
                 request_id TEXT PRIMARY KEY,
                 request_digest TEXT NOT NULL CHECK(length(request_digest)=64),
                 stable_node_id TEXT NOT NULL REFERENCES members(stable_node_id),
                 reason TEXT NOT NULL,
                 source TEXT NOT NULL,
                 snapshot_version INTEGER NOT NULL CHECK(snapshot_version > 0),
                 snapshot_digest TEXT NOT NULL CHECK(length(snapshot_digest)=64),
                 authority_epoch INTEGER NOT NULL CHECK(authority_epoch > 0),
                 member_auth_epoch INTEGER NOT NULL CHECK(member_auth_epoch > 0),
                 member_membership_epoch INTEGER NOT NULL CHECK(member_membership_epoch > 0),
                 state TEXT NOT NULL CHECK(state IN ('pending','indeterminate','completed','not_found')),
                 external_effects_unclassified INTEGER NOT NULL DEFAULT 0
                     CHECK(external_effects_unclassified IN (0,1)),
                 tombstone_committed INTEGER NOT NULL DEFAULT 0 CHECK(tombstone_committed IN (0,1)),
                 receipt_id TEXT,
                 indeterminate_reason TEXT,
                 created_at INTEGER NOT NULL,
                 updated_at INTEGER NOT NULL
             );
             CREATE INDEX revocation_intents_target_state
                 ON revocation_intents(stable_node_id,state);
             PRAGMA user_version=4;",
        )?;
    }
    tx.commit()?;
    Ok(())
}

fn resolve_member(tx: &Transaction<'_>, identifier: &str) -> Result<Option<StableNodeId>> {
    let identifier = identifier.trim();
    anyhow::ensure!(!identifier.is_empty(), "membership identifier is empty");
    let mut statement = tx.prepare(
        "SELECT DISTINCT m.stable_node_id FROM members m
         LEFT JOIN transport_bindings b ON b.stable_node_id=m.stable_node_id
         WHERE m.stable_node_id=?1 OR m.stable_node_id LIKE (?1 || '%')
            OR m.label=?1 OR b.transport_identity=?1
         ORDER BY m.stable_node_id",
    )?;
    let matches = statement
        .query_map([identifier], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    match matches.as_slice() {
        [] => Ok(None),
        [stable] => Ok(Some(StableNodeId::parse(stable.clone())?)),
        _ => anyhow::bail!("membership identifier `{identifier}` is ambiguous"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_runtime_generation_round_trips_and_validates() {
        let health = MembershipRuntimeHealth {
            wire_version: MEMBERSHIP_RUNTIME_HEALTH_WIRE_VERSION,
            live_generations: vec![LiveMembershipGeneration {
                stable_node_id: StableNodeId::parse("11".repeat(32)).unwrap(),
                carrier: CarrierKind::Peeroxide,
                auth_epoch: AuthEpoch::new(1).unwrap(),
                membership_epoch: MembershipEpoch::new(1).unwrap(),
                kind: LiveMembershipKind::Route,
            }],
            invalid_live_generations: Vec::new(),
            unresolved_revocations: Vec::new(),
        };

        health.validate().unwrap();
        let json = serde_json::to_string(&health).unwrap();
        assert!(json.contains(r#""kind":"route""#));
        assert_eq!(
            serde_json::from_str::<MembershipRuntimeHealth>(&json).unwrap(),
            health
        );

        let mut unknown_kind = serde_json::to_value(&health).unwrap();
        unknown_kind["live_generations"][0]["kind"] = serde_json::json!("future_kind");
        assert!(
            serde_json::from_value::<MembershipRuntimeHealth>(unknown_kind).is_err(),
            "unknown runtime generation kinds must fail closed"
        );
    }

    #[test]
    fn runtime_generation_order_stays_wire_lexicographic() {
        let stable_node_id = StableNodeId::parse("22".repeat(32)).unwrap();
        let generation = |kind| LiveMembershipGeneration {
            stable_node_id: stable_node_id.clone(),
            carrier: CarrierKind::Peeroxide,
            auth_epoch: AuthEpoch::new(1).unwrap(),
            membership_epoch: MembershipEpoch::new(1).unwrap(),
            kind,
        };
        let mut generations = vec![
            generation(LiveMembershipKind::Route),
            generation(LiveMembershipKind::Network),
            generation(LiveMembershipKind::QueuedProvider),
            generation(LiveMembershipKind::ExternalPermit),
            generation(LiveMembershipKind::InflightProvider),
            generation(LiveMembershipKind::DurableCommit),
        ];

        generations.sort_by(compare_live_membership_generations);

        assert_eq!(
            generations
                .iter()
                .map(|entry| entry.kind.as_str())
                .collect::<Vec<_>>(),
            vec![
                "durable_commit",
                "external_permit",
                "inflight_provider",
                "network",
                "queued_provider",
                "route",
            ]
        );
    }

    fn identity_and_attestation(
        home: &Path,
        now: i64,
    ) -> (LocalNodeIdentity, EndpointAttestation, TransportIdentity) {
        let identity = LocalNodeIdentity::load_or_create(home).unwrap();
        let transport = TransportIdentity::peeroxide(&identity.peeroxide_key_pair().public_key);
        let attestation = identity
            .attest_endpoint(
                CarrierKind::Peeroxide,
                transport.clone(),
                BootId::new(),
                "runtime-a".into(),
                "127.0.0.1:1234".into(),
                AuthEpoch::INITIAL,
                MembershipEpoch::new(2).unwrap(),
                Some("invite-digest".into()),
                now + 60,
            )
            .unwrap();
        (identity, attestation, transport)
    }

    #[test]
    fn stable_keys_survive_restart_and_cluster_rotation() {
        let home = tempfile::tempdir().unwrap();
        let first = LocalNodeIdentity::load_or_create(home.path()).unwrap();
        let stable = first.stable_node_id().clone();
        let peeroxide = first.peeroxide_key_pair().public_key;
        std::fs::write(
            home.path().join("credentials.yaml"),
            "cluster_passphrase: rotated",
        )
        .unwrap();
        let second = LocalNodeIdentity::load_or_create(home.path()).unwrap();
        assert_eq!(second.stable_node_id(), &stable);
        assert_eq!(second.peeroxide_key_pair().public_key, peeroxide);
    }

    #[test]
    fn signed_attestation_is_exact_and_tamper_evident() {
        let home = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let (_, mut attestation, transport) = identity_and_attestation(home.path(), now);
        attestation
            .verify_exact(CarrierKind::Peeroxide, &transport, "127.0.0.1:1234", now)
            .unwrap();
        assert!(
            attestation
                .verify_exact(CarrierKind::Iroh, &transport, "127.0.0.1:1234", now)
                .is_err()
        );
        attestation.endpoint.push('5');
        assert!(
            attestation
                .verify_exact(
                    CarrierKind::Peeroxide,
                    &transport,
                    &attestation.endpoint,
                    now
                )
                .is_err()
        );
    }

    #[test]
    fn fresh_store_matches_migrated_store_and_passes_integrity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authority.db");
        let conn = Connection::open(&path).unwrap();
        conn.pragma_update(None, "user_version", 0).unwrap();
        drop(conn);
        let migrated = MembershipStore::open_path(path, false).unwrap();
        migrated.integrity_check().unwrap();
        assert_eq!(
            migrated.authority_epochs().unwrap(),
            (MembershipEpoch::INITIAL, MembershipEpoch::INITIAL)
        );
    }

    #[test]
    fn revocation_request_ids_require_canonical_uuid_v7() {
        let request_id = new_revocation_request_id();
        validate_revocation_request_id(&request_id).unwrap();
        assert!(validate_revocation_request_id("550e8400-e29b-41d4-a716-446655440000").is_err());
        assert!(validate_revocation_request_id(&request_id.to_uppercase()).is_err());
    }

    #[test]
    fn membership_snapshot_envelope_is_strict_versioned_and_digest_bound() {
        let snapshot = MembershipSnapshot {
            version: MEMBERSHIP_SNAPSHOT_VERSION,
            authority_path: PathBuf::from("cluster-membership.db"),
            authority_epoch: MembershipEpoch::INITIAL,
            revocation_floor: MembershipEpoch::INITIAL,
            pending_outbox: 0,
            members: Vec::new(),
        };
        let envelope = snapshot.into_envelope().unwrap();
        let json = serde_json::to_string(&envelope).unwrap();
        assert_eq!(
            MembershipSnapshotEnvelope::from_json(&json).unwrap(),
            envelope
        );

        let mut unknown: serde_json::Value = serde_json::from_str(&json).unwrap();
        unknown["unexpected"] = serde_json::json!(true);
        assert!(MembershipSnapshotEnvelope::from_json(&unknown.to_string()).is_err());

        let mut future: serde_json::Value = serde_json::from_str(&json).unwrap();
        future["wire_version"] = serde_json::json!(MEMBERSHIP_SNAPSHOT_WIRE_VERSION + 1);
        assert!(MembershipSnapshotEnvelope::from_json(&future.to_string()).is_err());

        let mut tampered: serde_json::Value = serde_json::from_str(&json).unwrap();
        tampered["snapshot"]["pending_outbox"] = serde_json::json!(1);
        assert!(MembershipSnapshotEnvelope::from_json(&tampered.to_string()).is_err());
    }

    #[test]
    fn membership_snapshot_rejects_non_exact_active_binding_generation() {
        let snapshot = MembershipSnapshot {
            version: MEMBERSHIP_SNAPSHOT_VERSION,
            authority_path: PathBuf::from("cluster-membership.db"),
            authority_epoch: MembershipEpoch::new(2).unwrap(),
            revocation_floor: MembershipEpoch::INITIAL,
            pending_outbox: 0,
            members: vec![MemberSnapshot {
                stable_node_id: StableNodeId::parse("a".repeat(64)).unwrap(),
                label: "peer".into(),
                state: MembershipState::Active,
                auth_epoch: AuthEpoch::new(2).unwrap(),
                membership_epoch: MembershipEpoch::new(2).unwrap(),
                tombstoned: false,
                bindings: vec![CarrierBindingSnapshot {
                    carrier: CarrierKind::Peeroxide,
                    transport_identity: TransportIdentity::parse("peeroxide:peer").unwrap(),
                    endpoint: "127.0.0.1:7700".into(),
                    assurance: "signed_attestation".into(),
                    auth_epoch: AuthEpoch::INITIAL,
                    membership_epoch: MembershipEpoch::new(2).unwrap(),
                    expires_at_unix: None,
                }],
            }],
        };
        assert!(snapshot.validate().is_err());
        assert!(snapshot.into_envelope().is_err());
    }

    #[test]
    fn pending_unknown_revoked_and_expired_never_admit() {
        let home = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let (_, attestation, transport) = identity_and_attestation(home.path(), now);
        let store = MembershipStore::open(home.path()).unwrap();
        assert!(
            store
                .admit(CarrierKind::Peeroxide, &transport, now)
                .is_err()
        );
        store
            .confirm_attestation(
                &attestation,
                CarrierKind::Peeroxide,
                &transport,
                "127.0.0.1:1234",
                "peer",
                now,
            )
            .unwrap();
        store
            .admit(CarrierKind::Peeroxide, &transport, now)
            .unwrap();
        assert!(
            store
                .admit(CarrierKind::Peeroxide, &transport, now + 61)
                .is_err()
        );
        store
            .revoke(
                attestation.stable_node_id.as_str(),
                "test",
                now + 1,
                "closed",
            )
            .unwrap();
        assert!(
            store
                .admit(CarrierKind::Peeroxide, &transport, now + 2)
                .is_err()
        );
    }

    #[test]
    fn revoke_tombstone_epochs_and_outbox_are_atomic_and_idempotent() {
        let home = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let (_, attestation, transport) = identity_and_attestation(home.path(), now);
        let store = MembershipStore::open(home.path()).unwrap();
        store
            .confirm_attestation(
                &attestation,
                CarrierKind::Peeroxide,
                &transport,
                "127.0.0.1:1234",
                "peer",
                now,
            )
            .unwrap();
        let first = store
            .revoke(
                attestation.stable_node_id.as_str(),
                "operator",
                now + 1,
                "closed",
            )
            .unwrap()
            .unwrap();
        assert!(first.tombstone_committed && !first.already_revoked);
        assert_eq!(store.pending_outbox_count().unwrap(), 3);
        assert_eq!(first.authority_path, home.path().join(AUTHORITY_DB_FILE));
        assert_eq!(first.post_state_digest.len(), 64);
        assert!(
            first
                .post_state_digest
                .chars()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        assert_eq!(
            first.post_state_digest,
            store.full_snapshot().unwrap().canonical_digest().unwrap()
        );
        let second = store
            .revoke(
                attestation.stable_node_id.as_str(),
                "operator",
                now + 2,
                "closed",
            )
            .unwrap()
            .unwrap();
        assert!(second.already_revoked);
        assert_eq!(second.receipt_id, first.receipt_id);
        assert_eq!(second.authority_path, first.authority_path);
        assert_eq!(
            second.post_state_digest,
            store.full_snapshot().unwrap().canonical_digest().unwrap()
        );
        assert_eq!(store.pending_outbox_count().unwrap(), 3);
        let snapshots = store.snapshot().unwrap();
        assert_eq!(snapshots[0].state, MembershipState::Revoked);
        assert!(snapshots[0].tombstoned);
    }

    #[test]
    fn completed_revocation_retries_exact_binding_and_rejects_uuid_reuse() {
        let home = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let (_, attestation, transport) = identity_and_attestation(home.path(), now);
        let store = MembershipStore::open(home.path()).unwrap();
        store
            .confirm_attestation(
                &attestation,
                CarrierKind::Peeroxide,
                &transport,
                "127.0.0.1:1234",
                "peer",
                now,
            )
            .unwrap();
        let controller = MembershipController::new(store, Arc::new(LiveSessionRegistry::new()));
        let binding = controller
            .store()
            .build_revoke_binding(
                attestation.stable_node_id.as_str(),
                "operator_cli",
                "operator_cli",
                Some(&new_revocation_request_id()),
            )
            .unwrap()
            .unwrap();

        let first = controller.revoke_bound(&binding, now + 1).unwrap();
        let retry = controller.revoke_bound(&binding, now + 2).unwrap();
        assert!(retry.already_revoked);
        assert_eq!(retry.request_id, binding.request_id);
        assert_eq!(retry.receipt_id, first.receipt_id);

        let status = controller
            .revocation_status(&binding.request_id)
            .unwrap()
            .unwrap();
        let envelope =
            MembershipRevocationStatusEnvelope::new(binding.request_id.clone(), Some(status))
                .unwrap();
        assert!(envelope.found);
        assert_eq!(
            envelope.status.as_ref().unwrap().state,
            RevocationIntentState::Completed
        );
        let resolved_health = MembershipRuntimeHealth {
            wire_version: MEMBERSHIP_RUNTIME_HEALTH_WIRE_VERSION,
            live_generations: Vec::new(),
            invalid_live_generations: Vec::new(),
            unresolved_revocations: vec![envelope.status.as_ref().unwrap().clone()],
        };
        assert!(resolved_health.validate().is_err());
        let json = serde_json::to_string(&envelope).unwrap();
        assert_eq!(
            MembershipRevocationStatusEnvelope::from_json(&json).unwrap(),
            envelope
        );
        let mut unknown_field = serde_json::to_value(&envelope).unwrap();
        unknown_field["future_status_field"] = serde_json::json!(true);
        assert!(
            MembershipRevocationStatusEnvelope::from_json(
                &serde_json::to_string(&unknown_field).unwrap()
            )
            .is_err()
        );
        let missing =
            MembershipRevocationStatusEnvelope::new(new_revocation_request_id(), None).unwrap();
        assert!(!missing.found);
        assert!(missing.status.is_none());

        let mut changed = binding;
        changed.reason = "different immutable reason".into();
        let error = controller.revoke_bound(&changed, now + 3).unwrap_err();
        assert!(error.to_string().contains("different immutable binding"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn external_effect_first_persists_indeterminate_before_tombstone() {
        let home = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let (_, attestation, transport) = identity_and_attestation(home.path(), now);
        let store = MembershipStore::open(home.path()).unwrap();
        store
            .confirm_attestation(
                &attestation,
                CarrierKind::Peeroxide,
                &transport,
                "127.0.0.1:1234",
                "peer",
                now,
            )
            .unwrap();
        let live_sessions = Arc::new(LiveSessionRegistry::new());
        let controller = Arc::new(MembershipController::new(store, live_sessions));
        let grant = controller
            .store()
            .admit(CarrierKind::Peeroxide, &transport, now)
            .unwrap();
        let mut effect = grant.begin_effect(now).unwrap();
        let mut external = effect.begin_external(now).unwrap();
        let binding = controller
            .store()
            .build_revoke_binding(
                grant.stable_node_id().as_str(),
                "operator_cli",
                "operator_cli",
                Some(&new_revocation_request_id()),
            )
            .unwrap()
            .unwrap();
        let revoke_controller = Arc::clone(&controller);
        let revoke_binding = binding.clone();
        let revoke = tokio::task::spawn_blocking(move || {
            revoke_controller.revoke_bound(&revoke_binding, now + 1)
        });

        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(2), external.cancelled(),)
                .await
                .expect("external effect did not observe revocation"),
            Some(binding.request_id.clone())
        );
        let pending = controller
            .revocation_status(&binding.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(pending.state, RevocationIntentState::Pending);
        assert!(pending.external_effects_unclassified);
        assert!(!pending.tombstone_committed);
        let runtime_health = controller.runtime_health().unwrap();
        runtime_health.validate().unwrap();
        assert_eq!(runtime_health.unresolved_revocations, vec![pending.clone()]);
        assert!(
            controller
                .store()
                .admit(CarrierKind::Peeroxide, &transport, now + 1)
                .is_err(),
            "pending intent must deny a fresh membership effect"
        );
        assert_eq!(
            controller
                .store()
                .connection()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM revocation_tombstones", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );

        assert!(
            external
                .persist_indeterminate_if_cancelled(
                    "test_external_effect_has_no_remote_ack",
                    now + 1,
                )
                .unwrap()
        );
        drop(external);
        drop(effect);
        let receipt = revoke.await.unwrap().unwrap();
        assert_eq!(receipt.intent_state, RevocationIntentState::Indeterminate);
        assert!(receipt.tombstone_committed);
        let status = controller
            .revocation_status(&binding.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(status.state, RevocationIntentState::Indeterminate);
        assert!(!status.external_effects_unclassified);
        let runtime_health = controller.runtime_health().unwrap();
        runtime_health.validate().unwrap();
        assert_eq!(runtime_health.unresolved_revocations, vec![status]);
    }

    #[test]
    fn restart_recovers_unclassified_external_effect_as_indeterminate() {
        let home = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let (_, attestation, transport) = identity_and_attestation(home.path(), now);
        let store = MembershipStore::open(home.path()).unwrap();
        store
            .confirm_attestation(
                &attestation,
                CarrierKind::Peeroxide,
                &transport,
                "127.0.0.1:1234",
                "peer",
                now,
            )
            .unwrap();
        let live_sessions = Arc::new(LiveSessionRegistry::new());
        let controller = MembershipController::new(store, Arc::clone(&live_sessions));
        let grant = controller
            .store()
            .admit(CarrierKind::Peeroxide, &transport, now)
            .unwrap();
        let mut effect = grant.begin_effect(now).unwrap();
        let external = effect.begin_external(now).unwrap();
        let binding = controller
            .store()
            .build_revoke_binding(
                grant.stable_node_id().as_str(),
                "operator_cli",
                "operator_cli",
                Some(&new_revocation_request_id()),
            )
            .unwrap()
            .unwrap();
        let external_unclassified = live_sessions.signal_revocation(
            &binding.request_id,
            &binding.stable_node_id,
            binding.member_auth_epoch,
            binding.member_membership_epoch,
            binding.authority_epoch.next().unwrap(),
        );
        assert!(external_unclassified);
        controller
            .store()
            .start_revocation_intent(&binding, external_unclassified, now + 1)
            .unwrap();
        live_sessions
            .publish_revocation_cancellation(&binding.request_id)
            .unwrap();
        let pending = controller
            .revocation_status(&binding.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(pending.state, RevocationIntentState::Pending);
        assert!(pending.external_effects_unclassified);
        assert!(!pending.tombstone_committed);

        // Simulate a process crash after provider/network start and a failed
        // Indeterminate write: all process-local leases disappear, but the
        // durable unclassified marker survives.
        drop(external);
        drop(effect);
        drop(controller);
        drop(live_sessions);

        let restarted = MembershipController::new(
            MembershipStore::open(home.path()).unwrap(),
            Arc::new(LiveSessionRegistry::new()),
        );
        let receipt = restarted.revoke_bound(&binding, now + 2).unwrap();
        assert_eq!(receipt.intent_state, RevocationIntentState::Indeterminate);
        assert_eq!(
            receipt.indeterminate_reason.as_deref(),
            Some("pending_revocation_recovered_without_process_effect_classification")
        );
        assert!(receipt.tombstone_committed);
        let recovered = restarted
            .revocation_status(&binding.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(recovered.state, RevocationIntentState::Indeterminate);
        assert!(!recovered.external_effects_unclassified);
    }

    #[test]
    fn grant_revalidation_stops_old_epoch_after_revoke() {
        let home = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let (_, attestation, transport) = identity_and_attestation(home.path(), now);
        let store = MembershipStore::open(home.path()).unwrap();
        store
            .confirm_attestation(
                &attestation,
                CarrierKind::Peeroxide,
                &transport,
                "127.0.0.1:1234",
                "peer",
                now,
            )
            .unwrap();
        let grant = store
            .admit(CarrierKind::Peeroxide, &transport, now)
            .unwrap();
        grant.revalidate(now).unwrap();
        store
            .revoke(
                grant.stable_node_id().as_str(),
                "operator",
                now + 1,
                "closed",
            )
            .unwrap();
        assert!(grant.revalidate(now + 2).is_err());
    }

    #[test]
    fn revoke_restamps_survivors_and_rejects_attestations_at_the_floor() {
        let authority_home = tempfile::tempdir().unwrap();
        let revoked_home = tempfile::tempdir().unwrap();
        let survivor_home = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let (_, revoked_attestation, revoked_transport) =
            identity_and_attestation(revoked_home.path(), now);
        let (survivor_identity, survivor_attestation, survivor_transport) =
            identity_and_attestation(survivor_home.path(), now);
        let store = MembershipStore::open(authority_home.path()).unwrap();
        for (attestation, transport, label) in [
            (&revoked_attestation, &revoked_transport, "revoked"),
            (&survivor_attestation, &survivor_transport, "survivor"),
        ] {
            store
                .confirm_attestation(
                    attestation,
                    CarrierKind::Peeroxide,
                    transport,
                    "127.0.0.1:1234",
                    label,
                    now,
                )
                .unwrap();
        }
        let old_survivor_grant = store
            .admit(CarrierKind::Peeroxide, &survivor_transport, now)
            .unwrap();
        store
            .revoke(
                revoked_attestation.stable_node_id.as_str(),
                "operator",
                now + 1,
                "closed",
            )
            .unwrap()
            .unwrap();

        assert!(old_survivor_grant.revalidate(now + 2).is_err());
        let new_survivor_grant = store
            .admit(CarrierKind::Peeroxide, &survivor_transport, now + 2)
            .unwrap();
        assert_eq!(new_survivor_grant.membership_epoch().get(), 3);
        assert!(
            store
                .confirm_attestation(
                    &survivor_attestation,
                    CarrierKind::Peeroxide,
                    &survivor_transport,
                    "127.0.0.1:1234",
                    "survivor",
                    now + 2,
                )
                .is_err()
        );

        let fresh_attestation = survivor_identity
            .attest_endpoint(
                CarrierKind::Peeroxide,
                survivor_transport.clone(),
                BootId::new(),
                "runtime-b".into(),
                "127.0.0.1:1234".into(),
                AuthEpoch::INITIAL,
                MembershipEpoch::new(4).unwrap(),
                Some("invite-digest".into()),
                now + 60,
            )
            .unwrap();
        store
            .confirm_attestation(
                &fresh_attestation,
                CarrierKind::Peeroxide,
                &survivor_transport,
                "127.0.0.1:1234",
                "survivor",
                now + 2,
            )
            .unwrap();
        assert_eq!(
            store
                .admit(CarrierKind::Peeroxide, &survivor_transport, now + 2)
                .unwrap()
                .membership_epoch()
                .get(),
            4
        );
    }

    #[test]
    fn long_effect_never_holds_sqlite_lock_and_revoke_suppresses_commit() {
        let home = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let (_, attestation, transport) = identity_and_attestation(home.path(), now);
        let store = MembershipStore::open(home.path()).unwrap();
        store
            .confirm_attestation(
                &attestation,
                CarrierKind::Peeroxide,
                &transport,
                "127.0.0.1:1234",
                "peer",
                now,
            )
            .unwrap();
        let grant = store
            .admit(CarrierKind::Peeroxide, &transport, now)
            .unwrap();
        let effect = grant.begin_effect(now).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        let started = std::time::Instant::now();
        let receipt = store
            .revoke(
                grant.stable_node_id().as_str(),
                "operator",
                now + 1,
                "closed",
            )
            .unwrap()
            .unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert!(receipt.tombstone_committed);
        assert!(
            effect.finish().is_err(),
            "revoked long effect must not commit its durable acknowledgement"
        );
    }

    #[test]
    fn legacy_import_is_pending_and_idempotent() {
        let home = tempfile::tempdir().unwrap();
        let key = "ab".repeat(32);
        let legacy = crate::cluster::registry::ClusterRegistry {
            peers: vec![crate::cluster::registry::PairedPeer {
                pub_key_hex: key.clone(),
                instance_label: "legacy".into(),
                ..Default::default()
            }],
        };
        let body = serde_yaml::to_string(&legacy).unwrap();
        std::fs::write(home.path().join("cluster.yaml"), body).unwrap();
        let first = MembershipStore::open(home.path()).unwrap();
        let snapshots = first.snapshot().unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].state, MembershipState::Pending);
        assert_eq!(snapshots[0].bindings[0].assurance, "legacy_unattested");
        let second = MembershipStore::open(home.path()).unwrap();
        assert_eq!(second.snapshot().unwrap().len(), 1);
        assert!(
            second
                .admit(
                    CarrierKind::Peeroxide,
                    &TransportIdentity::parse(key).unwrap(),
                    1
                )
                .is_err()
        );
    }

    #[test]
    fn ambiguous_lookup_fails_without_revoking_any_member() {
        let home = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let store = MembershipStore::open(home.path()).unwrap();
        for index in 0..2 {
            let peer_home = tempfile::tempdir().unwrap();
            let (_, attestation, transport) = identity_and_attestation(peer_home.path(), now);
            store
                .confirm_attestation(
                    &attestation,
                    CarrierKind::Peeroxide,
                    &transport,
                    "127.0.0.1:1234",
                    "same-label",
                    now + index,
                )
                .unwrap();
        }
        assert!(
            store
                .revoke("same-label", "operator", now, "closed")
                .is_err()
        );
        assert!(
            store
                .snapshot()
                .unwrap()
                .iter()
                .all(|member| member.state == MembershipState::Active)
        );
    }

    #[test]
    fn authority_invite_owns_epochs_and_exact_binding() {
        let authority = tempfile::tempdir().unwrap();
        let peer = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let identity = LocalNodeIdentity::load_or_create(peer.path()).unwrap();
        let transport = TransportIdentity::peeroxide(&identity.peeroxide_key_pair().public_key);
        let store = MembershipStore::open(authority.path()).unwrap();
        let invite = store
            .create_invite(
                identity.stable_node_id(),
                &identity.verifying_key().to_bytes(),
                CarrierKind::Peeroxide,
                &transport,
                "127.0.0.1:31337",
                "peer-a",
                now,
                now + 60,
            )
            .unwrap();
        let forged_proof_epoch = identity
            .attest_endpoint(
                CarrierKind::Peeroxide,
                transport.clone(),
                BootId::new(),
                "runtime-a".into(),
                "127.0.0.1:31337".into(),
                invite.auth_epoch,
                invite.issued_at_membership_epoch.next().unwrap(),
                Some(invite.invitation_digest.clone()),
                now + 30,
            )
            .unwrap();
        let proof_error = store
            .confirm_invite(
                &invite.invite_id,
                &forged_proof_epoch,
                CarrierKind::Peeroxide,
                &transport,
                "127.0.0.1:31337",
                now + 1,
            )
            .unwrap_err();
        assert!(
            format!("{proof_error:#}").contains("proof membership epoch"),
            "a signed but tampered proof epoch must fail against the authority-issued invite"
        );
        let forged_epochs = identity
            .attest_endpoint(
                CarrierKind::Peeroxide,
                transport.clone(),
                BootId::new(),
                "runtime-a".into(),
                "127.0.0.1:31337".into(),
                AuthEpoch::new(99).unwrap(),
                MembershipEpoch::new(999).unwrap(),
                Some(invite.invitation_digest.clone()),
                now + 30,
            )
            .unwrap();
        assert!(
            store
                .confirm_invite(
                    &invite.invite_id,
                    &forged_epochs,
                    CarrierKind::Peeroxide,
                    &transport,
                    "127.0.0.1:31337",
                    now + 1,
                )
                .is_err(),
            "the peer cannot replace authority-issued enrollment epochs"
        );
        let attestation = identity
            .attest_endpoint(
                CarrierKind::Peeroxide,
                transport.clone(),
                BootId::new(),
                "runtime-a".into(),
                "127.0.0.1:31337".into(),
                invite.auth_epoch,
                invite.issued_at_membership_epoch,
                Some(invite.invitation_digest.clone()),
                now + 30,
            )
            .unwrap();
        let receipt = store
            .confirm_invite(
                &invite.invite_id,
                &attestation,
                CarrierKind::Peeroxide,
                &transport,
                "127.0.0.1:31337",
                now + 1,
            )
            .unwrap();
        assert_eq!(receipt.auth_epoch, invite.auth_epoch);
        assert_eq!(
            receipt.issued_at_membership_epoch,
            invite.issued_at_membership_epoch
        );
        assert_eq!(
            receipt.committed_membership_epoch,
            invite.issued_at_membership_epoch
        );
        assert_eq!(receipt.auth_epoch, attestation.auth_epoch);
        assert_eq!(
            receipt.issued_at_membership_epoch,
            attestation.proof_membership_epoch
        );
        assert!(
            store
                .admit(CarrierKind::Peeroxide, &transport, now + 2)
                .is_ok()
        );
    }

    #[test]
    fn two_independent_outstanding_invites_can_confirm() {
        let authority = tempfile::tempdir().unwrap();
        let first_peer = tempfile::tempdir().unwrap();
        let second_peer = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let first_identity = LocalNodeIdentity::load_or_create(first_peer.path()).unwrap();
        let second_identity = LocalNodeIdentity::load_or_create(second_peer.path()).unwrap();
        let first_transport =
            TransportIdentity::peeroxide(&first_identity.peeroxide_key_pair().public_key);
        let second_transport =
            TransportIdentity::peeroxide(&second_identity.peeroxide_key_pair().public_key);
        let store = MembershipStore::open(authority.path()).unwrap();
        let authority_epoch_before = store.authority_epochs().unwrap().0;

        let first_invite = store
            .create_invite(
                first_identity.stable_node_id(),
                &first_identity.verifying_key().to_bytes(),
                CarrierKind::Peeroxide,
                &first_transport,
                "127.0.0.1:31337",
                "first-peer",
                now,
                now + 60,
            )
            .unwrap();
        let second_invite = store
            .create_invite(
                second_identity.stable_node_id(),
                &second_identity.verifying_key().to_bytes(),
                CarrierKind::Peeroxide,
                &second_transport,
                "127.0.0.1:31338",
                "second-peer",
                now + 1,
                now + 61,
            )
            .unwrap();
        assert_eq!(store.authority_epochs().unwrap().0, authority_epoch_before);
        assert_eq!(
            first_invite.issued_at_membership_epoch,
            second_invite.issued_at_membership_epoch
        );

        let first_attestation = first_identity
            .attest_endpoint(
                CarrierKind::Peeroxide,
                first_transport.clone(),
                BootId::new(),
                "runtime-first".into(),
                "127.0.0.1:31337".into(),
                first_invite.auth_epoch,
                first_invite.issued_at_membership_epoch,
                Some(first_invite.invitation_digest.clone()),
                now + 30,
            )
            .unwrap();
        let second_attestation = second_identity
            .attest_endpoint(
                CarrierKind::Peeroxide,
                second_transport.clone(),
                BootId::new(),
                "runtime-second".into(),
                "127.0.0.1:31338".into(),
                second_invite.auth_epoch,
                second_invite.issued_at_membership_epoch,
                Some(second_invite.invitation_digest.clone()),
                now + 31,
            )
            .unwrap();
        store
            .confirm_invite(
                &first_invite.invite_id,
                &first_attestation,
                CarrierKind::Peeroxide,
                &first_transport,
                "127.0.0.1:31337",
                now + 2,
            )
            .unwrap();
        store
            .confirm_invite(
                &second_invite.invite_id,
                &second_attestation,
                CarrierKind::Peeroxide,
                &second_transport,
                "127.0.0.1:31338",
                now + 3,
            )
            .unwrap();

        assert!(
            store
                .admit(CarrierKind::Peeroxide, &first_transport, now + 4)
                .is_ok()
        );
        assert!(
            store
                .admit(CarrierKind::Peeroxide, &second_transport, now + 4)
                .is_ok()
        );
        assert!(
            store
                .confirm_invite(
                    &first_invite.invite_id,
                    &first_attestation,
                    CarrierKind::Peeroxide,
                    &first_transport,
                    "127.0.0.1:31337",
                    now + 5,
                )
                .is_err(),
            "the exact consumed invite must remain single-use"
        );
    }

    #[test]
    fn same_stable_identity_outstanding_invites_for_distinct_carriers_can_confirm() {
        let authority = tempfile::tempdir().unwrap();
        let peer = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let identity = LocalNodeIdentity::load_or_create(peer.path()).unwrap();
        let peeroxide_transport =
            TransportIdentity::peeroxide(&identity.peeroxide_key_pair().public_key);
        let iroh_transport = TransportIdentity::parse("cd".repeat(32)).unwrap();
        let store = MembershipStore::open(authority.path()).unwrap();

        let peeroxide_invite = store
            .create_invite(
                identity.stable_node_id(),
                &identity.verifying_key().to_bytes(),
                CarrierKind::Peeroxide,
                &peeroxide_transport,
                "127.0.0.1:31337",
                "peeroxide",
                now,
                now + 60,
            )
            .unwrap();
        let iroh_invite = store
            .create_invite(
                identity.stable_node_id(),
                &identity.verifying_key().to_bytes(),
                CarrierKind::Iroh,
                &iroh_transport,
                "127.0.0.1:31338",
                "iroh",
                now + 1,
                now + 61,
            )
            .unwrap();
        assert_eq!(peeroxide_invite.auth_epoch, iroh_invite.auth_epoch);
        assert_eq!(
            peeroxide_invite.issued_at_membership_epoch,
            iroh_invite.issued_at_membership_epoch
        );

        let peeroxide_attestation = identity
            .attest_endpoint(
                CarrierKind::Peeroxide,
                peeroxide_transport.clone(),
                BootId::new(),
                "runtime-peeroxide".into(),
                "127.0.0.1:31337".into(),
                peeroxide_invite.auth_epoch,
                peeroxide_invite.issued_at_membership_epoch,
                Some(peeroxide_invite.invitation_digest.clone()),
                now + 30,
            )
            .unwrap();
        let iroh_attestation = identity
            .attest_endpoint(
                CarrierKind::Iroh,
                iroh_transport.clone(),
                BootId::new(),
                "runtime-iroh".into(),
                "127.0.0.1:31338".into(),
                iroh_invite.auth_epoch,
                iroh_invite.issued_at_membership_epoch,
                Some(iroh_invite.invitation_digest.clone()),
                now + 31,
            )
            .unwrap();
        store
            .confirm_invite(
                &peeroxide_invite.invite_id,
                &peeroxide_attestation,
                CarrierKind::Peeroxide,
                &peeroxide_transport,
                "127.0.0.1:31337",
                now + 2,
            )
            .unwrap();
        store
            .confirm_invite(
                &iroh_invite.invite_id,
                &iroh_attestation,
                CarrierKind::Iroh,
                &iroh_transport,
                "127.0.0.1:31338",
                now + 3,
            )
            .unwrap();

        assert!(
            store
                .admit(CarrierKind::Peeroxide, &peeroxide_transport, now + 4)
                .is_ok()
        );
        assert!(
            store
                .admit(CarrierKind::Iroh, &iroh_transport, now + 4)
                .is_ok()
        );
        let member = store
            .snapshot()
            .unwrap()
            .into_iter()
            .find(|member| member.stable_node_id == *identity.stable_node_id())
            .unwrap();
        assert_eq!(member.bindings.len(), 2);
        assert!(
            store
                .confirm_invite(
                    &peeroxide_invite.invite_id,
                    &peeroxide_attestation,
                    CarrierKind::Peeroxide,
                    &peeroxide_transport,
                    "127.0.0.1:31337",
                    now + 5,
                )
                .is_err(),
            "the exact consumed invite must remain single-use"
        );
    }

    #[test]
    fn pre_revoke_outstanding_invite_cannot_resurrect_stable_identity() {
        let authority = tempfile::tempdir().unwrap();
        let peer = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let identity = LocalNodeIdentity::load_or_create(peer.path()).unwrap();
        let peeroxide_transport =
            TransportIdentity::peeroxide(&identity.peeroxide_key_pair().public_key);
        let old_iroh_transport = TransportIdentity::parse("cd".repeat(32)).unwrap();
        let fresh_iroh_transport = TransportIdentity::parse("ef".repeat(32)).unwrap();
        let store = MembershipStore::open(authority.path()).unwrap();
        let peeroxide_invite = store
            .create_invite(
                identity.stable_node_id(),
                &identity.verifying_key().to_bytes(),
                CarrierKind::Peeroxide,
                &peeroxide_transport,
                "127.0.0.1:31337",
                "peeroxide",
                now,
                now + 100,
            )
            .unwrap();
        let old_iroh_invite = store
            .create_invite(
                identity.stable_node_id(),
                &identity.verifying_key().to_bytes(),
                CarrierKind::Iroh,
                &old_iroh_transport,
                "127.0.0.1:31338",
                "old-iroh",
                now + 1,
                now + 101,
            )
            .unwrap();
        let peeroxide_attestation = identity
            .attest_endpoint(
                CarrierKind::Peeroxide,
                peeroxide_transport.clone(),
                BootId::new(),
                "runtime-peeroxide".into(),
                "127.0.0.1:31337".into(),
                peeroxide_invite.auth_epoch,
                peeroxide_invite.issued_at_membership_epoch,
                Some(peeroxide_invite.invitation_digest.clone()),
                now + 90,
            )
            .unwrap();
        let old_iroh_attestation = identity
            .attest_endpoint(
                CarrierKind::Iroh,
                old_iroh_transport.clone(),
                BootId::new(),
                "runtime-old-iroh".into(),
                "127.0.0.1:31338".into(),
                old_iroh_invite.auth_epoch,
                old_iroh_invite.issued_at_membership_epoch,
                Some(old_iroh_invite.invitation_digest.clone()),
                now + 90,
            )
            .unwrap();
        store
            .confirm_invite(
                &peeroxide_invite.invite_id,
                &peeroxide_attestation,
                CarrierKind::Peeroxide,
                &peeroxide_transport,
                "127.0.0.1:31337",
                now + 2,
            )
            .unwrap();
        store
            .revoke(
                identity.stable_node_id().as_str(),
                "rotate-generation",
                now + 3,
                "closed",
            )
            .unwrap()
            .unwrap();
        let fresh_iroh_invite = store
            .create_invite(
                identity.stable_node_id(),
                &identity.verifying_key().to_bytes(),
                CarrierKind::Iroh,
                &fresh_iroh_transport,
                "127.0.0.1:31339",
                "fresh-iroh",
                now + 4,
                now + 104,
            )
            .unwrap();
        assert!(fresh_iroh_invite.auth_epoch > old_iroh_invite.auth_epoch);
        assert!(
            store
                .confirm_invite(
                    &old_iroh_invite.invite_id,
                    &old_iroh_attestation,
                    CarrierKind::Iroh,
                    &old_iroh_transport,
                    "127.0.0.1:31338",
                    now + 5,
                )
                .is_err(),
            "an outstanding pre-revoke invite must not match the new auth generation"
        );
        let fresh_iroh_attestation = identity
            .attest_endpoint(
                CarrierKind::Iroh,
                fresh_iroh_transport.clone(),
                BootId::new(),
                "runtime-fresh-iroh".into(),
                "127.0.0.1:31339".into(),
                fresh_iroh_invite.auth_epoch,
                fresh_iroh_invite.issued_at_membership_epoch,
                Some(fresh_iroh_invite.invitation_digest.clone()),
                now + 90,
            )
            .unwrap();
        store
            .confirm_invite(
                &fresh_iroh_invite.invite_id,
                &fresh_iroh_attestation,
                CarrierKind::Iroh,
                &fresh_iroh_transport,
                "127.0.0.1:31339",
                now + 6,
            )
            .unwrap();
    }

    #[test]
    fn creating_invite_does_not_advance_authority_or_invalidate_active_grant() {
        let authority = tempfile::tempdir().unwrap();
        let active_peer = tempfile::tempdir().unwrap();
        let invited_peer = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let (_, active_attestation, active_transport) =
            identity_and_attestation(active_peer.path(), now);
        let invited_identity = LocalNodeIdentity::load_or_create(invited_peer.path()).unwrap();
        let invited_transport =
            TransportIdentity::peeroxide(&invited_identity.peeroxide_key_pair().public_key);
        let store = MembershipStore::open(authority.path()).unwrap();
        store
            .confirm_attestation(
                &active_attestation,
                CarrierKind::Peeroxide,
                &active_transport,
                "127.0.0.1:1234",
                "active-peer",
                now,
            )
            .unwrap();
        let active_grant = store
            .admit(CarrierKind::Peeroxide, &active_transport, now + 1)
            .unwrap();
        let authority_epochs_before = store.authority_epochs().unwrap();

        store
            .create_invite(
                invited_identity.stable_node_id(),
                &invited_identity.verifying_key().to_bytes(),
                CarrierKind::Peeroxide,
                &invited_transport,
                "127.0.0.1:31337",
                "invited-peer",
                now + 2,
                now + 62,
            )
            .unwrap();

        assert_eq!(store.authority_epochs().unwrap(), authority_epochs_before);
        active_grant.revalidate(now + 3).unwrap();
    }

    #[test]
    fn unrelated_revokes_do_not_orphan_invite_and_wire_epochs_are_explicit() {
        let authority = tempfile::tempdir().unwrap();
        let first_active_peer = tempfile::tempdir().unwrap();
        let second_active_peer = tempfile::tempdir().unwrap();
        let invited_peer = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let (first_identity, first_attestation, first_transport) =
            identity_and_attestation(first_active_peer.path(), now);
        let (second_identity, second_attestation, second_transport) =
            identity_and_attestation(second_active_peer.path(), now);
        let invited_identity = LocalNodeIdentity::load_or_create(invited_peer.path()).unwrap();
        let invited_transport =
            TransportIdentity::peeroxide(&invited_identity.peeroxide_key_pair().public_key);
        let store = MembershipStore::open(authority.path()).unwrap();
        store
            .confirm_attestation(
                &first_attestation,
                CarrierKind::Peeroxide,
                &first_transport,
                "127.0.0.1:1234",
                "first-active",
                now,
            )
            .unwrap();
        store
            .confirm_attestation(
                &second_attestation,
                CarrierKind::Peeroxide,
                &second_transport,
                "127.0.0.1:1234",
                "second-active",
                now + 1,
            )
            .unwrap();
        let invite = store
            .create_invite(
                invited_identity.stable_node_id(),
                &invited_identity.verifying_key().to_bytes(),
                CarrierKind::Peeroxide,
                &invited_transport,
                "127.0.0.1:31337",
                "invited",
                now + 2,
                now + 120,
            )
            .unwrap();
        let invite_json = serde_json::to_value(&invite).unwrap();
        assert!(invite_json.get("issued_at_membership_epoch").is_some());
        assert!(invite_json.get("membership_epoch").is_none());
        let attestation = invited_identity
            .attest_endpoint(
                CarrierKind::Peeroxide,
                invited_transport.clone(),
                BootId::new(),
                "runtime-invited".into(),
                "127.0.0.1:31337".into(),
                invite.auth_epoch,
                invite.issued_at_membership_epoch,
                Some(invite.invitation_digest.clone()),
                now + 90,
            )
            .unwrap();
        let attestation_json = serde_json::to_value(&attestation).unwrap();
        assert_eq!(
            attestation_json.get("protocol_version"),
            Some(&serde_json::json!(2))
        );
        assert!(attestation_json.get("proof_membership_epoch").is_some());
        assert!(attestation_json.get("membership_epoch").is_none());
        let mut ambiguous_attestation_json = attestation_json.clone();
        let proof_epoch = ambiguous_attestation_json
            .as_object_mut()
            .unwrap()
            .remove("proof_membership_epoch")
            .unwrap();
        ambiguous_attestation_json
            .as_object_mut()
            .unwrap()
            .insert("membership_epoch".into(), proof_epoch);
        assert!(
            serde_json::from_value::<EndpointAttestation>(ambiguous_attestation_json).is_err(),
            "the v2 wire format must reject the ambiguous legacy epoch field"
        );

        store
            .revoke(
                first_identity.stable_node_id().as_str(),
                "unrelated-first",
                now + 3,
                "closed",
            )
            .unwrap()
            .unwrap();
        store
            .revoke(
                second_identity.stable_node_id().as_str(),
                "unrelated-second",
                now + 4,
                "closed",
            )
            .unwrap()
            .unwrap();
        assert!(
            store.authority_epochs().unwrap().0 > invite.issued_at_membership_epoch,
            "the regression requires an invite proof epoch older than current authority"
        );

        let receipt = store
            .confirm_invite(
                &invite.invite_id,
                &attestation,
                CarrierKind::Peeroxide,
                &invited_transport,
                "127.0.0.1:31337",
                now + 5,
            )
            .unwrap();
        assert_eq!(
            receipt.issued_at_membership_epoch,
            invite.issued_at_membership_epoch
        );
        assert!(receipt.committed_membership_epoch > receipt.issued_at_membership_epoch);
        assert_eq!(
            receipt.committed_membership_epoch,
            store.authority_epochs().unwrap().0
        );
        let receipt_json = serde_json::to_value(&receipt).unwrap();
        assert!(receipt_json.get("issued_at_membership_epoch").is_some());
        assert!(receipt_json.get("committed_membership_epoch").is_some());
        assert!(receipt_json.get("membership_epoch").is_none());
        assert!(
            store
                .admit(CarrierKind::Peeroxide, &invited_transport, now + 6)
                .is_ok()
        );
    }

    #[test]
    fn revoked_stable_identity_reenrolls_at_higher_auth_epoch_with_history_intact() {
        let authority = tempfile::tempdir().unwrap();
        let peer = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let identity = LocalNodeIdentity::load_or_create(peer.path()).unwrap();
        let first_transport =
            TransportIdentity::peeroxide(&identity.peeroxide_key_pair().public_key);
        let abandoned_transport =
            TransportIdentity::peeroxide(&peeroxide::KeyPair::from_seed([42; 32]).public_key);
        let store = MembershipStore::open(authority.path()).unwrap();

        let enroll =
            |store: &MembershipStore, transport: &TransportIdentity, at: i64, label: &str| {
                let invite = store
                    .create_invite(
                        identity.stable_node_id(),
                        &identity.verifying_key().to_bytes(),
                        CarrierKind::Peeroxide,
                        &transport,
                        "127.0.0.1:31337",
                        label,
                        at,
                        at + 60,
                    )
                    .unwrap();
                let attestation = identity
                    .attest_endpoint(
                        CarrierKind::Peeroxide,
                        transport.clone(),
                        BootId::new(),
                        format!("runtime-{label}"),
                        "127.0.0.1:31337".into(),
                        invite.auth_epoch,
                        invite.issued_at_membership_epoch,
                        Some(invite.invitation_digest.clone()),
                        at + 30,
                    )
                    .unwrap();
                let receipt = store
                    .confirm_invite(
                        &invite.invite_id,
                        &attestation,
                        CarrierKind::Peeroxide,
                        &transport,
                        "127.0.0.1:31337",
                        at + 1,
                    )
                    .unwrap();
                (invite, receipt)
            };

        let (_, first_enrollment) = enroll(&store, &first_transport, now, "first");
        let old_grant = store
            .admit(CarrierKind::Peeroxide, &first_transport, now + 2)
            .unwrap();
        let first_revoke = store
            .revoke(
                identity.stable_node_id().as_str(),
                "first-cycle",
                now + 3,
                "closed",
            )
            .unwrap()
            .unwrap();
        assert!(old_grant.revalidate(now + 4).is_err());

        assert!(
            store
                .create_invite(
                    identity.stable_node_id(),
                    &identity.verifying_key().to_bytes(),
                    CarrierKind::Peeroxide,
                    &first_transport,
                    "127.0.0.1:31337",
                    "reused-carrier",
                    now + 4,
                    now + 64,
                )
                .is_err(),
            "a revoked StableNode cannot reuse a historical carrier identity"
        );
        let abandoned_invite = store
            .create_invite(
                identity.stable_node_id(),
                &identity.verifying_key().to_bytes(),
                CarrierKind::Peeroxide,
                &abandoned_transport,
                "127.0.0.1:31337",
                "abandoned",
                now + 4,
                now + 64,
            )
            .unwrap();
        let abandoned_attestation = identity
            .attest_endpoint(
                CarrierKind::Peeroxide,
                abandoned_transport.clone(),
                BootId::new(),
                "runtime-abandoned".into(),
                "127.0.0.1:31337".into(),
                abandoned_invite.auth_epoch,
                abandoned_invite.issued_at_membership_epoch,
                Some(abandoned_invite.invitation_digest.clone()),
                now + 34,
            )
            .unwrap();
        assert!(
            store
                .create_invite(
                    identity.stable_node_id(),
                    &identity.verifying_key().to_bytes(),
                    CarrierKind::Peeroxide,
                    &first_transport,
                    "127.0.0.1:31337",
                    "pending-reuse-bypass",
                    now + 5,
                    now + 65,
                )
                .is_err(),
            "Pending state after a revoked node's abandoned invite must not bypass carrier history"
        );
        let second_enrollment = store
            .confirm_invite(
                &abandoned_invite.invite_id,
                &abandoned_attestation,
                CarrierKind::Peeroxide,
                &abandoned_transport,
                "127.0.0.1:31337",
                now + 6,
            )
            .unwrap();
        let second_invite = abandoned_invite;
        assert!(second_invite.auth_epoch > first_enrollment.auth_epoch);
        assert_eq!(second_enrollment.auth_epoch, second_invite.auth_epoch);
        let new_grant = store
            .admit(CarrierKind::Peeroxide, &abandoned_transport, now + 7)
            .unwrap();
        assert_eq!(new_grant.auth_epoch(), second_invite.auth_epoch);

        let second_revoke = store
            .revoke(
                identity.stable_node_id().as_str(),
                "second-cycle",
                now + 8,
                "closed",
            )
            .unwrap()
            .unwrap();
        assert_ne!(second_revoke.receipt_id, first_revoke.receipt_id);
        let repeated = store
            .revoke(
                identity.stable_node_id().as_str(),
                "second-cycle",
                now + 9,
                "closed",
            )
            .unwrap()
            .unwrap();
        assert!(repeated.already_revoked);
        assert_eq!(repeated.receipt_id, second_revoke.receipt_id);
        assert_eq!(
            store
                .connection()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM revocation_tombstones
                     WHERE stable_node_id=?1",
                    [identity.stable_node_id().as_str()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            2
        );
    }

    #[test]
    fn invite_tamper_expiry_replay_wrong_carrier_and_transport_fail_closed() {
        let authority = tempfile::tempdir().unwrap();
        let peer = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let identity = LocalNodeIdentity::load_or_create(peer.path()).unwrap();
        let transport = TransportIdentity::peeroxide(&identity.peeroxide_key_pair().public_key);
        let wrong_transport = TransportIdentity::parse("cd".repeat(32)).unwrap();
        let store = MembershipStore::open(authority.path()).unwrap();
        let invite = store
            .create_invite(
                identity.stable_node_id(),
                &identity.verifying_key().to_bytes(),
                CarrierKind::Peeroxide,
                &transport,
                "127.0.0.1:31337",
                "peer-a",
                now,
                now + 10,
            )
            .unwrap();
        let make = |digest: String, expiry: i64| {
            identity
                .attest_endpoint(
                    CarrierKind::Peeroxide,
                    transport.clone(),
                    BootId::new(),
                    "runtime-a".into(),
                    "127.0.0.1:31337".into(),
                    AuthEpoch::INITIAL,
                    invite.issued_at_membership_epoch,
                    Some(digest),
                    expiry,
                )
                .unwrap()
        };
        let exact = make(invite.invitation_digest.clone(), now + 5);
        let tampered = make(format!("{}x", invite.invitation_digest), now + 5);
        assert!(
            store
                .confirm_invite(
                    &invite.invite_id,
                    &tampered,
                    CarrierKind::Peeroxide,
                    &transport,
                    "127.0.0.1:31337",
                    now + 1,
                )
                .is_err()
        );
        assert!(
            store
                .confirm_invite(
                    &invite.invite_id,
                    &exact,
                    CarrierKind::Iroh,
                    &transport,
                    "127.0.0.1:31337",
                    now + 1,
                )
                .is_err()
        );
        assert!(
            store
                .confirm_invite(
                    &invite.invite_id,
                    &exact,
                    CarrierKind::Peeroxide,
                    &wrong_transport,
                    "127.0.0.1:31337",
                    now + 1,
                )
                .is_err()
        );
        assert!(
            store
                .confirm_invite(
                    &invite.invite_id,
                    &exact,
                    CarrierKind::Peeroxide,
                    &transport,
                    "127.0.0.1:31337",
                    now + 11,
                )
                .is_err()
        );
        store
            .confirm_invite(
                &invite.invite_id,
                &exact,
                CarrierKind::Peeroxide,
                &transport,
                "127.0.0.1:31337",
                now + 2,
            )
            .unwrap();
        assert!(
            store
                .confirm_invite(
                    &invite.invite_id,
                    &exact,
                    CarrierKind::Peeroxide,
                    &transport,
                    "127.0.0.1:31337",
                    now + 3,
                )
                .is_err()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn controller_revoke_waits_for_peeroxide_session_generation_ack() {
        let authority = tempfile::tempdir().unwrap();
        let peer = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let (_, attestation, transport) = identity_and_attestation(peer.path(), now);
        let store = MembershipStore::open(authority.path()).unwrap();
        store
            .confirm_attestation(
                &attestation,
                CarrierKind::Peeroxide,
                &transport,
                "127.0.0.1:1234",
                "peer",
                now,
            )
            .unwrap();

        let live_sessions = Arc::new(LiveSessionRegistry::new());
        let peer_streams = Arc::new(
            crate::cluster::peer_streams::PeerStreamRegistry::with_effect_registry(
                live_sessions.effect_registry(),
            ),
        );
        let live_carrier: Arc<dyn LiveCarrierSessions> = peer_streams.clone();
        live_sessions.register(live_carrier);
        let controller = Arc::new(MembershipController::new(store, Arc::clone(&live_sessions)));
        let grant = controller
            .store()
            .admit(CarrierKind::Peeroxide, &transport, now)
            .unwrap();
        let mut session_effect = grant.begin_effect(now).unwrap();
        let (_generation, outbound, mut route_cancel) =
            peer_streams.register_authorized_session(transport.as_str(), &grant);

        let (cancel_seen_tx, cancel_seen_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let session = tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = session_effect.cancelled() => {}
                _ = route_cancel.changed() => {}
            }
            let _ = cancel_seen_tx.send(());
            let _ = release_rx.await;
            drop(outbound);
            drop(route_cancel);
            drop(session_effect);
        });

        let stable = grant.stable_node_id().clone();
        let revoke_controller = Arc::clone(&controller);
        let mut revoke = tokio::task::spawn_blocking(move || {
            revoke_controller.revoke(stable.as_str(), "operator", now + 1)
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), cancel_seen_rx)
            .await
            .expect("session generation did not observe revoke")
            .expect("session generation cancellation sender dropped");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(300), &mut revoke)
                .await
                .is_err(),
            "revoke receipt returned before the live session dropped its generation lease"
        );
        release_tx.send(()).unwrap();
        session.await.unwrap();
        let receipt = tokio::time::timeout(std::time::Duration::from_secs(2), &mut revoke)
            .await
            .expect("revoke did not finish after the session cancellation ACK")
            .expect("revoke worker panicked")
            .expect("revoke failed")
            .expect("membership vanished during revoke");

        assert_eq!(receipt.live_teardown, "partial");
        assert_eq!(receipt.per_carrier_teardown["peeroxide"].closed_sessions, 0);
        assert_eq!(receipt.per_carrier_teardown["peeroxide"].routes_evicted, 1);
        assert_eq!(receipt.per_carrier_teardown["peeroxide"].status, "partial");
        assert_eq!(receipt.post_state_digest.len(), 64);
        assert!(live_sessions.effect_registry().snapshot().is_empty());
    }

    #[tokio::test]
    async fn controller_replays_outbox_and_reports_per_carrier_teardown() {
        let authority = tempfile::tempdir().unwrap();
        let peer = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let (_, attestation, transport) = identity_and_attestation(peer.path(), now);
        let store = MembershipStore::open(authority.path()).unwrap();
        store
            .confirm_attestation(
                &attestation,
                CarrierKind::Peeroxide,
                &transport,
                "127.0.0.1:1234",
                "peer",
                now,
            )
            .unwrap();
        let sessions = std::sync::Arc::new(LiveSessionRegistry::new());
        sessions.note_session(CarrierKind::Peeroxide, attestation.stable_node_id.clone());
        sessions.note_session(CarrierKind::Iroh, attestation.stable_node_id.clone());
        let (writer, writer_join) =
            crate::wal::writer::spawn(authority.path().join("membership-test.wal")).unwrap();
        let controller = std::sync::Arc::new(MembershipController::with_audit_writer(
            store.clone(),
            sessions,
            writer.clone(),
        ));
        let first_controller = std::sync::Arc::clone(&controller);
        let stable_node_id = attestation.stable_node_id.clone();
        let receipt = tokio::task::spawn_blocking(move || {
            first_controller.revoke(stable_node_id.as_str(), "operator", now + 1)
        })
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert!(receipt.tombstone_committed);
        assert_eq!(receipt.per_carrier_teardown["peeroxide"].closed_sessions, 1);
        assert_eq!(receipt.per_carrier_teardown["iroh"].closed_sessions, 1);
        assert!(!receipt.audit_pending);
        assert_eq!(store.pending_outbox_count().unwrap(), 0);
        let second_controller = std::sync::Arc::clone(&controller);
        let stable_node_id = attestation.stable_node_id.clone();
        let repeated = tokio::task::spawn_blocking(move || {
            second_controller.revoke(stable_node_id.as_str(), "operator", now + 2)
        })
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(repeated.receipt_id, receipt.receipt_id);
        drop(controller);
        drop(writer);
        writer_join.await.unwrap();
    }

    #[tokio::test]
    async fn startup_replay_keeps_audit_pending_until_wal_ack_then_drains_exactly_once() {
        let authority = tempfile::tempdir().unwrap();
        let peer = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let (_, attestation, transport) = identity_and_attestation(peer.path(), now);
        let store = MembershipStore::open(authority.path()).unwrap();
        store
            .confirm_attestation(
                &attestation,
                CarrierKind::Peeroxide,
                &transport,
                "127.0.0.1:1234",
                "peer",
                now,
            )
            .unwrap();

        let (dead_writer, dead_join) =
            crate::wal::writer::spawn(authority.path().join("dead-membership.wal")).unwrap();
        dead_join.abort();
        let _ = dead_join.await;
        let controller = std::sync::Arc::new(MembershipController::with_audit_writer(
            store.clone(),
            std::sync::Arc::new(LiveSessionRegistry::new()),
            dead_writer,
        ));
        let revoke_controller = std::sync::Arc::clone(&controller);
        let stable_node_id = attestation.stable_node_id.clone();
        let receipt = tokio::task::spawn_blocking(move || {
            revoke_controller.revoke(stable_node_id.as_str(), "operator", now + 1)
        })
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert!(receipt.tombstone_committed);
        assert!(receipt.audit_pending);
        assert_eq!(
            receipt.pending_outbox, 1,
            "teardown and membership quarantine must finish even when audit WAL ACK fails"
        );
        assert!(receipt.outbox_error.is_some());
        assert_eq!(
            store
                .connection()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM membership_audit", [], |row| {
                    row.get::<_, u64>(0)
                })
                .unwrap(),
            0,
            "audit projection must not commit before the WAL writer ACK"
        );

        let (writer, writer_join) =
            crate::wal::writer::spawn(authority.path().join("replayed-membership.wal")).unwrap();
        let startup_controller = std::sync::Arc::new(MembershipController::with_audit_writer(
            store.clone(),
            std::sync::Arc::new(LiveSessionRegistry::new()),
            writer.clone(),
        ));
        let replay = std::sync::Arc::clone(&startup_controller);
        let delivered = tokio::task::spawn_blocking(move || replay.drain_outbox(now + 2))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(delivered, 1);
        assert_eq!(store.pending_outbox_count().unwrap(), 0);
        assert_eq!(
            store
                .connection()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM membership_audit", [], |row| {
                    row.get::<_, u64>(0)
                })
                .unwrap(),
            1
        );
        let replay_again = std::sync::Arc::clone(&startup_controller);
        assert_eq!(
            tokio::task::spawn_blocking(move || replay_again.drain_outbox(now + 3))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        drop(startup_controller);
        drop(controller);
        drop(writer);
        writer_join.await.unwrap();
    }
}
