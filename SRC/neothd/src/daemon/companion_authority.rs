//! W2306 R5: recovery-safe v3 companion authority candidate.
//! A persisted delivery marker is written before the daemon may begin status I/O.
use super::companion_protocol::{
    COMPANION_V3_SCHEMA_VERSION, CompanionDeviceId, CompanionScope, CompanionStatusSnapshot,
    EnrollmentProof, ProtocolError, ReconnectDescriptor, ServerFrame, StatusChallenge, StatusProof,
    device_key_fingerprint, encode_server_frame,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ffi::OsStr,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use uuid::Uuid;
const DIR: &str = "companion-devices";
const FILE: &str = "authority-v3.json";
const VER: u8 = 3;
const MAX: usize = 128;
const MAX_BYTES: usize = 256 * 1024;
const AGE: i64 = 60;
const TERMINAL_RECEIPTS: usize = 256;
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    PendingEnroll,
    Active,
    PendingRevoke,
    Revoked,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationKind {
    Enroll,
    Revoke,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingAudit {
    pub mutation_id: Uuid,
    pub device_id: CompanionDeviceId,
    pub revision: u64,
    pub kind: MutationKind,
    pub key_sha256: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceGrant {
    pub schema_version: u8,
    pub device_id: CompanionDeviceId,
    pub signing_key: [u8; 32],
    pub client_noise_key: [u8; 32],
    pub key_sha256: String,
    pub label: String,
    pub scope: CompanionScope,
    pub phase: Phase,
    pub revision: u64,
    pub reconnect: ReconnectDescriptor,
    pub pending: Option<PendingAudit>,
}
impl DeviceGrant {
    pub const fn phase_name(&self) -> &'static str {
        match self.phase {
            Phase::PendingEnroll => "pending_enroll",
            Phase::Active => "active",
            Phase::PendingRevoke => "pending_revoke",
            Phase::Revoked => "revoked",
        }
    }
}
/// Persisted bounded proof that this exact mutation was finalized.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TerminalReceipt {
    mutation_id: Uuid,
    device_id: CompanionDeviceId,
    revision: u64,
    kind: MutationKind,
    key_sha256: String,
}
impl From<&PendingAudit> for TerminalReceipt {
    fn from(a: &PendingAudit) -> Self {
        Self {
            mutation_id: a.mutation_id,
            device_id: a.device_id.clone(),
            revision: a.revision,
            kind: a.kind.clone(),
            key_sha256: a.key_sha256.clone(),
        }
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DeliveryMarker {
    delivery_id: Uuid,
    device_id: CompanionDeviceId,
    revision: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u8,
    devices: BTreeMap<Uuid, DeviceGrant>,
    #[serde(default)]
    terminal_receipts: BTreeMap<Uuid, TerminalReceipt>,
    #[serde(default)]
    delivery_markers: BTreeMap<Uuid, DeliveryMarker>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            version: VER,
            devices: BTreeMap::new(),
            terminal_receipts: BTreeMap::new(),
            delivery_markers: BTreeMap::new(),
        }
    }
}
#[derive(Clone, Debug)]
struct Challenge {
    value: StatusChallenge,
}
#[derive(Debug)]
struct Core {
    state: State,
    reload_required: bool,
    challenges: HashMap<Uuid, Challenge>,
    leases: HashMap<Uuid, usize>,
    owned_deliveries: BTreeSet<Uuid>,
}
#[derive(Debug)]
struct Shared {
    core: Mutex<Core>,
    drained: tokio::sync::Notify,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditObservation {
    NotObserved,
    Observed,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Reconcile {
    Append(PendingAudit),
    Finalized(PendingAudit),
    AlreadyFinalized,
}
pub struct StatusLease {
    store: Store,
    shared: Arc<Shared>,
    id: Uuid,
    delivery_id: Uuid,
    pub revision: u64,
}
impl StatusLease {
    /// Caller must move this lease into the owned carrier task before I/O.
    pub fn status_frame(&self, snapshot: CompanionStatusSnapshot) -> Result<Vec<u8>> {
        snapshot.validate().map_err(pe)?;
        encode_server_frame(&ServerFrame::StatusSnapshot(snapshot)).map_err(pe)
    }
    /// Only the owned delivery task calls this after write completion and checked carrier drain.
    pub fn complete_confirmed(&self) -> Result<()> {
        let mut c = self
            .shared
            .core
            .lock()
            .map_err(|_| anyhow::anyhow!("authority mutex poisoned"))?;
        let mut n = c.state.clone();
        clear_delivery_marker(&mut n, self.delivery_id, self.id, self.revision)?;
        if self.store.replace(&n)? {
            c.state = n;
            Ok(())
        } else {
            c.reload_required = true;
            anyhow::bail!(
                "delivery completion published with uncertain durability; reload required"
            )
        }
    }
}
impl Drop for StatusLease {
    fn drop(&mut self) {
        if let Ok(mut c) = self.shared.core.lock() {
            c.owned_deliveries.remove(&self.delivery_id);
            if let Some(n) = c.leases.get_mut(&self.id) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    c.leases.remove(&self.id);
                    self.shared.drained.notify_waiters();
                }
            }
        }
    }
}
#[derive(Clone, Debug)]
pub struct Store {
    home: PathBuf,
}
impl Store {
    pub fn new(home: impl Into<PathBuf>) -> Self {
        Self { home: home.into() }
    }
    fn read(&self) -> Result<State> {
        let Some(home) = crate::skills::store::open_bound_directory(
            &self.home,
            false,
            "companion authority home",
        )?
        else {
            return Ok(State::default());
        };
        let path = home.physical_display_path.join(DIR);
        let Some(dir) = crate::skills::store::open_real_child_dir_if_present(
            &home.dir,
            OsStr::new(DIR),
            &path,
        )?
        else {
            return Ok(State::default());
        };
        crate::skills::store::ensure_cap_directory_is_owner_private(
            &dir,
            "companion authority",
            &path,
        )?;
        let file = path.join(FILE);
        if matches!(dir.symlink_metadata(OsStr::new(FILE)),Err(ref e)if e.kind()==std::io::ErrorKind::NotFound)
        {
            return Ok(State::default());
        }
        let b = crate::skills::store::read_regular_file_bounded(
            &dir,
            OsStr::new(FILE),
            &file,
            MAX_BYTES,
        )?;
        let s = serde_json::from_slice(&b).context("decode companion authority")?;
        valid(&s)?;
        Ok(s)
    }
    fn replace(&self, s: &State) -> Result<bool> {
        valid(s)?;
        let home = crate::skills::store::open_bound_directory(
            &self.home,
            false,
            "companion authority home",
        )?
        .context("companion authority home absent")?;
        let path = home.physical_display_path.join(DIR);
        let dir = crate::skills::store::open_or_create_private_child_dir(
            &home.dir,
            OsStr::new(DIR),
            &path,
        )?;
        crate::skills::store::ensure_cap_directory_is_owner_private(
            &dir,
            "companion authority",
            &path,
        )?;
        let b = serde_json::to_vec(s)?;
        anyhow::ensure!(b.len() <= MAX_BYTES, "authority bound");
        match crate::skills::store::atomic_write_private_child_reported(
            &dir,
            OsStr::new(FILE),
            &path.join(FILE),
            &b,
        ) {
            Ok(crate::skills::store::PrivateChildCommit::PublishedAndSynced) => Ok(true),
            Ok(crate::skills::store::PrivateChildCommit::PublishedDurabilityUnknown(_)) => {
                Ok(false)
            }
            Err(e) => Err(e.into()),
        }
    }
}
pub struct DeviceAuthority {
    store: Store,
    shared: Arc<Shared>,
}
impl DeviceAuthority {
    pub fn load(home: impl Into<PathBuf>) -> Result<Self> {
        let store = Store::new(home);
        let state = store.read()?;
        Ok(Self {
            store,
            shared: Arc::new(Shared {
                core: Mutex::new(Core {
                    state,
                    reload_required: false,
                    challenges: HashMap::new(),
                    leases: HashMap::new(),
                    owned_deliveries: BTreeSet::new(),
                }),
                drained: tokio::sync::Notify::new(),
            }),
        })
    }
    fn core(&self) -> Result<std::sync::MutexGuard<'_, Core>> {
        let c = self
            .shared
            .core
            .lock()
            .map_err(|_| anyhow::anyhow!("authority mutex poisoned"))?;
        anyhow::ensure!(
            !c.reload_required
                && c.state
                    .delivery_markers
                    .keys()
                    .all(|id| c.owned_deliveries.contains(id)),
            "reload/recovery required"
        );
        Ok(c)
    }
    fn publish(&self, c: &mut Core, next: State) -> Result<()> {
        if self.store.replace(&next)? {
            c.state = next;
            Ok(())
        } else {
            c.reload_required = true;
            anyhow::bail!("published with uncertain durability; reload required")
        }
    }
    pub fn begin_enrollment(
        &self,
        p: EnrollmentProof,
        observed: [u8; 32],
        r: ReconnectDescriptor,
        now: i64,
    ) -> Result<PendingAudit> {
        p.validate().map_err(pe)?;
        p.verify().map_err(pe)?;
        r.validate().map_err(pe)?;
        anyhow::ensure!(
            p.transport_peer_key == observed && now >= 0,
            "invalid enrollment carrier/clock"
        );
        let mut c = self.core()?;
        anyhow::ensure!(
            c.state.devices.len() < MAX
                && !c
                    .state
                    .devices
                    .values()
                    .any(|g| g.signing_key == p.device_signing_public_key
                        || g.client_noise_key == p.client_noise_public_key),
            "duplicate/capacity device"
        );
        let id = CompanionDeviceId(Uuid::now_v7());
        let a = PendingAudit {
            mutation_id: Uuid::now_v7(),
            device_id: id.clone(),
            revision: 1,
            kind: MutationKind::Enroll,
            key_sha256: device_key_fingerprint(&p.device_signing_public_key),
        };
        anyhow::ensure!(
            !c.state.terminal_receipts.contains_key(&a.mutation_id),
            "duplicate mutation id"
        );
        let g = DeviceGrant {
            schema_version: COMPANION_V3_SCHEMA_VERSION,
            device_id: id.clone(),
            signing_key: p.device_signing_public_key,
            client_noise_key: p.client_noise_public_key,
            key_sha256: a.key_sha256.clone(),
            label: p.label,
            scope: CompanionScope::StatusRead,
            phase: Phase::PendingEnroll,
            revision: 1,
            reconnect: r,
            pending: Some(a.clone()),
        };
        let mut n = c.state.clone();
        n.devices.insert(id.0, g);
        self.publish(&mut c, n)?;
        Ok(a)
    }
    /// Persists PendingRevoke first (denying leases), then awaits owned delivery drains without blocking Tokio.
    pub async fn begin_revoke_async(&self, id: &CompanionDeviceId) -> Result<Option<PendingAudit>> {
        let a = {
            let mut c = self.core()?;
            let g = c.state.devices.get(&id.0).context("unknown device")?;
            if matches!(g.phase, Phase::PendingRevoke | Phase::Revoked) {
                return Ok(None);
            }
            anyhow::ensure!(g.phase == Phase::Active, "not active");
            let a = PendingAudit {
                mutation_id: Uuid::now_v7(),
                device_id: id.clone(),
                revision: g.revision.checked_add(1).context("revision exhausted")?,
                kind: MutationKind::Revoke,
                key_sha256: g.key_sha256.clone(),
            };
            anyhow::ensure!(
                !c.state.terminal_receipts.contains_key(&a.mutation_id),
                "duplicate mutation id"
            );
            let mut n = c.state.clone();
            let x = n.devices.get_mut(&id.0).context("missing cloned device")?;
            x.phase = Phase::PendingRevoke;
            x.revision = a.revision;
            x.pending = Some(a.clone());
            self.publish(&mut c, n)?;
            a
        };
        wait_for_lease_drain(&self.shared, id.0).await?;
        Ok(Some(a))
    }
    pub fn pending_audits(&self) -> Result<Vec<PendingAudit>> {
        let c = self.core()?;
        Ok(c.state
            .devices
            .values()
            .filter_map(|g| g.pending.clone())
            .collect())
    }
    /// Unknown ids fail closed; only retained exact receipts return AlreadyFinalized.
    pub fn reconcile_audit(&self, id: Uuid, seen: AuditObservation) -> Result<Reconcile> {
        let mut c = self.core()?;
        anyhow::ensure!(
            c.state.delivery_markers.is_empty(),
            "delivery drain required before audit finalization"
        );
        let Some(a) = audit_for_reconcile(&c.state, id)? else {
            return Ok(Reconcile::AlreadyFinalized);
        };
        if seen == AuditObservation::NotObserved {
            return Ok(Reconcile::Append(a));
        }
        let mut n = c.state.clone();
        let g = n.devices.get_mut(&a.device_id.0).with_context(|| {
            format!(
                "pending audit {} references missing device {}",
                a.mutation_id, a.device_id
            )
        })?;
        g.phase = match &a.kind {
            MutationKind::Enroll => Phase::Active,
            MutationKind::Revoke => Phase::Revoked,
        };
        g.pending = None;
        n.terminal_receipts
            .insert(a.mutation_id, TerminalReceipt::from(&a));
        while n.terminal_receipts.len() > TERMINAL_RECEIPTS {
            let oldest = *n
                .terminal_receipts
                .keys()
                .next()
                .context("terminal receipt eviction")?;
            n.terminal_receipts.remove(&oldest);
        }
        self.publish(&mut c, n)?;
        Ok(Reconcile::Finalized(a))
    }
    pub fn begin_reconnect_for_observed_noise(
        &self,
        noise: [u8; 32],
        generation: u64,
        boot: String,
        nonce: [u8; 32],
        now: i64,
    ) -> Result<StatusChallenge> {
        let mut c = self.core()?;
        anyhow::ensure!(
            generation > 0 && now >= 0,
            "invalid reconnect clock/generation"
        );
        let hits = c
            .state
            .devices
            .values()
            .filter(|g| {
                g.client_noise_key == noise
                    && g.phase == Phase::Active
                    && g.scope == CompanionScope::StatusRead
            })
            .collect::<Vec<_>>();
        anyhow::ensure!(hits.len() == 1, "unauthenticated reconnect");
        let (id, revision) = (hits[0].device_id.clone(), hits[0].revision);
        if let Some(q) = c.challenges.get(&id.0) {
            anyhow::ensure!(now >= q.value.issued_at_unix, "backward challenge clock");
            if now - q.value.issued_at_unix > AGE {
                c.challenges.remove(&id.0);
            }
        }
        anyhow::ensure!(
            !c.challenges.contains_key(&id.0),
            "live challenge already exists"
        );
        let v = StatusChallenge {
            schema_version: COMPANION_V3_SCHEMA_VERSION,
            device_id: id.clone(),
            revision,
            listener_generation: generation,
            daemon_boot_id: boot,
            challenge_nonce: nonce,
            issued_at_unix: now,
        };
        v.validate().map_err(pe)?;
        c.challenges.insert(id.0, Challenge { value: v.clone() });
        Ok(v)
    }
    pub fn authorize_status(&self, p: &StatusProof, now: i64) -> Result<StatusLease> {
        p.validate().map_err(pe)?;
        let mut c = self.core()?;
        anyhow::ensure!(
            c.state.delivery_markers.is_empty(),
            "status delivery already active"
        );
        let g = active(&c.state, &p.device_id)?;
        anyhow::ensure!(g.revision == p.revision, "stale revision");
        p.verify_with(&g.signing_key).map_err(pe)?;
        let q = c
            .challenges
            .get(&p.device_id.0)
            .context("no authenticated challenge")?;
        anyhow::ensure!(
            now >= q.value.issued_at_unix && now - q.value.issued_at_unix <= AGE,
            "expired/backward challenge clock"
        );
        anyhow::ensure!(
            q.value.device_id == p.device_id
                && q.value.revision == p.revision
                && q.value.listener_generation == p.listener_generation
                && q.value.daemon_boot_id == p.daemon_boot_id
                && q.value.challenge_nonce == p.challenge_nonce,
            "challenge mismatch"
        );
        let delivery_id = Uuid::now_v7();
        let mut n = c.state.clone();
        n.delivery_markers.insert(
            delivery_id,
            DeliveryMarker {
                delivery_id,
                device_id: p.device_id.clone(),
                revision: p.revision,
            },
        );
        self.publish(&mut c, n)?;
        c.owned_deliveries.insert(delivery_id);
        c.challenges.remove(&p.device_id.0);
        *c.leases.entry(p.device_id.0).or_insert(0) += 1;
        Ok(StatusLease {
            store: self.store.clone(),
            shared: Arc::clone(&self.shared),
            id: p.device_id.0,
            delivery_id,
            revision: p.revision,
        })
    }
    pub fn device(&self, id: &CompanionDeviceId) -> Result<DeviceGrant> {
        let c = self.core()?;
        Ok(c.state
            .devices
            .get(&id.0)
            .cloned()
            .context("unknown device")?)
    }
    pub fn list(&self) -> Result<Vec<DeviceGrant>> {
        let c = self.core()?;
        Ok(c.state.devices.values().cloned().collect())
    }
}
fn active<'a>(s: &'a State, id: &CompanionDeviceId) -> Result<&'a DeviceGrant> {
    let g = s.devices.get(&id.0).context("unknown device")?;
    anyhow::ensure!(
        g.phase == Phase::Active && g.scope == CompanionScope::StatusRead,
        "device denied"
    );
    Ok(g)
}
async fn wait_for_lease_drain(shared: &Arc<Shared>, id: Uuid) -> Result<()> {
    loop {
        let notified = shared.drained.notified();
        let drained = {
            let c = shared
                .core
                .lock()
                .map_err(|_| anyhow::anyhow!("authority mutex poisoned"))?;
            if c.reload_required {
                anyhow::bail!("reload required")
            }
            c.leases.get(&id).copied().unwrap_or(0) == 0
        };
        if drained {
            return Ok(());
        }
        notified.await
    }
}
fn audit_for_reconcile(s: &State, id: Uuid) -> Result<Option<PendingAudit>> {
    if s.terminal_receipts.contains_key(&id) {
        return Ok(None);
    }
    s.devices
        .values()
        .find_map(|g| g.pending.clone().filter(|a| a.mutation_id == id))
        .map(Some)
        .context("unknown mutation receipt")
}
fn clear_delivery_marker(
    s: &mut State,
    delivery_id: Uuid,
    device_id: Uuid,
    revision: u64,
) -> Result<()> {
    let marker = s
        .delivery_markers
        .get(&delivery_id)
        .context("unknown delivery marker")?;
    anyhow::ensure!(
        marker.device_id.0 == device_id && marker.revision == revision,
        "delivery marker mismatch"
    );
    s.delivery_markers.remove(&delivery_id);
    Ok(())
}
fn valid(s: &State) -> Result<()> {
    anyhow::ensure!(
        s.version == VER
            && s.devices.len() <= MAX
            && s.terminal_receipts.len() <= TERMINAL_RECEIPTS
            && s.delivery_markers.len() <= 1,
        "bad authority state"
    );
    let (mut signing, mut noise, mut pending) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for (id, g) in &s.devices {
        anyhow::ensure!(
            *id == g.device_id.0
                && g.schema_version == COMPANION_V3_SCHEMA_VERSION
                && g.revision > 0
                && g.key_sha256 == device_key_fingerprint(&g.signing_key),
            "bad grant"
        );
        anyhow::ensure!(
            signing.insert(g.signing_key) && noise.insert(g.client_noise_key),
            "duplicate device key"
        );
        g.reconnect.validate().map_err(pe)?;
        match g.phase {
            Phase::PendingEnroll | Phase::PendingRevoke => {
                let a = g.pending.as_ref().context("pending without audit")?;
                anyhow::ensure!(
                    a.device_id == g.device_id
                        && a.revision == g.revision
                        && a.key_sha256 == g.key_sha256
                        && matches!(
                            (&g.phase, &a.kind),
                            (Phase::PendingEnroll, MutationKind::Enroll)
                                | (Phase::PendingRevoke, MutationKind::Revoke)
                        )
                        && pending.insert(a.mutation_id)
                        && !s.terminal_receipts.contains_key(&a.mutation_id),
                    "pending audit does not bind its grant"
                )
            }
            Phase::Active | Phase::Revoked => {
                anyhow::ensure!(g.pending.is_none(), "terminal with audit")
            }
        }
    }
    for (id, r) in &s.terminal_receipts {
        anyhow::ensure!(
            *id == r.mutation_id
                && !pending.contains(id)
                && r.revision > 0
                && !r.key_sha256.is_empty(),
            "bad terminal receipt"
        );
    }
    for (id, m) in &s.delivery_markers {
        anyhow::ensure!(
            *id == m.delivery_id && m.revision > 0 && s.devices.contains_key(&m.device_id.0),
            "bad delivery marker"
        );
    }
    Ok(())
}
fn pe(e: ProtocolError) -> anyhow::Error {
    anyhow::anyhow!(e)
}
#[cfg(test)]
mod real_store_regression {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::{fs, sync::Arc};
    #[tokio::test]
    async fn persistent_marker_allows_live_revoke_drain_but_reload_refuses_orphan() {
        let home = std::env::temp_dir().join(format!("neoth-r6-authority-{}", Uuid::now_v7()));
        fs::create_dir_all(&home).unwrap();
        let authority = Arc::new(DeviceAuthority::load(&home).unwrap());
        let signing = SigningKey::from_bytes(&[7; 32]);
        let descriptor = ReconnectDescriptor {
            schema_version: 3,
            carrier: "peeroxide-hyperswarm-v3".into(),
            rendezvous_topic: [1; 32],
            daemon_noise_public_key: [2; 32],
            descriptor_generation: 1,
        };
        let enrollment =
            EnrollmentProof::signed([3; 32], [4; 32], [5; 32], [6; 32], "phone".into(), &signing)
                .unwrap();
        let enrolled = authority
            .begin_enrollment(enrollment, [4; 32], descriptor, 1)
            .unwrap();
        assert!(matches!(
            authority
                .reconcile_audit(enrolled.mutation_id, AuditObservation::Observed)
                .unwrap(),
            Reconcile::Finalized(_)
        ));
        let challenge = authority
            .begin_reconnect_for_observed_noise([5; 32], 1, "boot".into(), [8; 32], 2)
            .unwrap();
        let proof = StatusProof::signed(&challenge, &signing).unwrap();
        let lease = authority.authorize_status(&proof, 3).unwrap();
        assert!(DeviceAuthority::load(&home).unwrap().list().is_err());
        let revoke_authority = Arc::clone(&authority);
        let device = challenge.device_id.clone();
        let mut revoke = Box::pin(tokio::spawn(async move {
            revoke_authority
                .begin_revoke_async(&device)
                .await
                .unwrap()
                .unwrap()
        }));
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if authority.pending_audits().unwrap().len() == 1 {
                    break;
                }
                tokio::task::yield_now().await
            }
        })
        .await
        .unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), &mut revoke)
                .await
                .is_err()
        );
        lease.complete_confirmed().unwrap();
        drop(lease);
        let _ = revoke.await.unwrap();
        let pending = authority.pending_audits().unwrap().pop().unwrap();
        assert!(matches!(
            authority
                .reconcile_audit(pending.mutation_id, AuditObservation::Observed)
                .unwrap(),
            Reconcile::Finalized(_)
        ));
        let _ = fs::remove_dir_all(home);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::companion_protocol::{CompanionReadiness, decode_server_frame};
    fn shared(state: State, id: Uuid) -> Arc<Shared> {
        Arc::new(Shared {
            core: Mutex::new(Core {
                state,
                reload_required: false,
                challenges: HashMap::new(),
                leases: HashMap::from([(id, 1)]),
                owned_deliveries: BTreeSet::new(),
            }),
            drained: tokio::sync::Notify::new(),
        })
    }
    fn lease(shared: Arc<Shared>, id: Uuid) -> StatusLease {
        StatusLease {
            store: Store::new("unused-test-home"),
            shared,
            id,
            delivery_id: Uuid::now_v7(),
            revision: 1,
        }
    }
    #[test]
    fn decoded_status_frame_retains_prewrite_marker_until_confirmed() {
        let id = Uuid::now_v7();
        let shared = shared(State::default(), id);
        let lease = lease(Arc::clone(&shared), id);
        let frame = lease
            .status_frame(CompanionStatusSnapshot {
                schema_version: 3,
                device_id: CompanionDeviceId(id),
                daemon_boot_id: "boot".into(),
                readiness: CompanionReadiness::Ready,
                observed_at_unix: 1,
                active_turns: None,
            })
            .unwrap();
        assert!(matches!(
            decode_server_frame(&frame).unwrap(),
            ServerFrame::StatusSnapshot(_)
        ));
        assert!(shared.core.lock().unwrap().leases.contains_key(&id));
        drop(lease);
        assert!(!shared.core.lock().unwrap().leases.contains_key(&id));
    }
    #[tokio::test]
    async fn revoke_drain_waits_for_owned_lease_release() {
        let id = Uuid::now_v7();
        let shared = shared(State::default(), id);
        let lease = lease(Arc::clone(&shared), id);
        let mut waiter = Box::pin(wait_for_lease_drain(&shared, id));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), &mut waiter)
                .await
                .is_err()
        );
        drop(lease);
        assert!(waiter.await.is_ok());
    }
    #[test]
    fn persisted_delivery_marker_refuses_serialized_same_store_reconstruction() {
        let device = Uuid::now_v7();
        let delivery = Uuid::now_v7();
        let mut state = State::default();
        state.devices.insert(
            device,
            DeviceGrant {
                schema_version: 3,
                device_id: CompanionDeviceId(device),
                signing_key: [7; 32],
                client_noise_key: [8; 32],
                key_sha256: device_key_fingerprint(&[7; 32]),
                label: "phone".into(),
                scope: CompanionScope::StatusRead,
                phase: Phase::Active,
                revision: 1,
                reconnect: ReconnectDescriptor {
                    schema_version: 3,
                    carrier: "peeroxide-hyperswarm-v3".into(),
                    rendezvous_topic: [1; 32],
                    daemon_noise_public_key: [2; 32],
                    descriptor_generation: 1,
                },
                pending: None,
            },
        );
        state.delivery_markers.insert(
            delivery,
            DeliveryMarker {
                delivery_id: delivery,
                device_id: CompanionDeviceId(device),
                revision: 1,
            },
        );
        assert!(valid(&state).is_ok());
        let reloaded: State = serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        let reconstructed = DeviceAuthority {
            store: Store::new("same-store"),
            shared: Arc::new(Shared {
                core: Mutex::new(Core {
                    state: reloaded,
                    reload_required: false,
                    challenges: HashMap::new(),
                    leases: HashMap::new(),
                    owned_deliveries: BTreeSet::new(),
                }),
                drained: tokio::sync::Notify::new(),
            }),
        };
        assert!(reconstructed.core().is_err());
    }
    #[test]
    fn terminal_receipt_must_be_exact_and_bounded() {
        let mut s = State::default();
        let id = Uuid::now_v7();
        s.terminal_receipts.insert(
            id,
            TerminalReceipt {
                mutation_id: id,
                device_id: CompanionDeviceId(Uuid::now_v7()),
                revision: 1,
                kind: MutationKind::Revoke,
                key_sha256: "x".into(),
            },
        );
        assert!(valid(&s).is_ok());
        assert_eq!(audit_for_reconcile(&s, id).unwrap(), None);
        assert!(audit_for_reconcile(&s, Uuid::now_v7()).is_err());
    }
}
