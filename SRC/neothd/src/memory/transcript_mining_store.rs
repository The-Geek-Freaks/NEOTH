//! Guarded SQLite half of Stage-3b transcript/WAL provenance.
use super::transcript_mining_provenance::{
    FiniteRetention, MiningLifecycle, MiningRevocation, TranscriptMiningBoundV1,
};
use super::transcript_mining_runtime::AuthenticatedLocalIngress;
use crate::wal::events::{EVENT_TYPE_EXTENDED, EVENT_TYPE_RAW_TEXT, ExtendedSubtype};
use crate::wal::{
    HeaderBuilder, PlannedMiningOutboxDescriptor, PlannedRawTextDescriptor,
    TranscriptMiningFrameReceipt,
};
use anyhow::{Context, Result, ensure};
use rusqlite::{
    Connection, OptionalExtension, TransactionBehavior, functions::FunctionFlags, params,
};
use sha2::{Digest as _, Sha256};
use std::sync::{Arc, Mutex};

type ActiveBindingRow = (
    Vec<u8>,
    Vec<u8>,
    String,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

pub(crate) struct PreparedRaw {
    event_id: i64,
    raw_turn_id: i64,
    expires_at_unix: i64,
    frame_plan_id: String,
    provenance_id: String,
    lifecycle_id: String,
    lease_id: String,
    descriptor_sha256: [u8; 32],
    descriptor: PlannedRawTextDescriptor,
}
impl PreparedRaw {
    pub(crate) const fn event_id(&self) -> i64 {
        self.event_id
    }
    pub(crate) const fn raw_turn_id(&self) -> i64 {
        self.raw_turn_id
    }
    pub(crate) const fn expires_at_unix(&self) -> i64 {
        self.expires_at_unix
    }
    pub(crate) fn raw_descriptor(&self) -> Result<PlannedRawTextDescriptor> {
        Ok(self.descriptor.clone())
    }
}
pub(crate) struct PreparedBound {
    outbox_id: String,
    raw_turn_id: i64,
    expires_at_unix: i64,
    provenance_id: String,
    lifecycle_id: String,
    lease_id: String,
    descriptor_sha256: [u8; 32],
    raw_descriptor_sha256: [u8; 32],
    descriptor: PlannedMiningOutboxDescriptor,
}
pub(crate) struct PreparedRevoked {
    outbox_id: String,
    provenance_id: String,
    lifecycle_id: String,
    lease_id: String,
    descriptor_sha256: [u8; 32],
    descriptor: PlannedMiningOutboxDescriptor,
}
impl PreparedRevoked {
    pub(crate) fn revoked_descriptor(&self) -> Result<PlannedMiningOutboxDescriptor> {
        Ok(self.descriptor.clone())
    }
}

/// Recovery returns the exact committed operation; it never synthesizes a new
/// header, event ID, HLC, or lease after a lost acknowledgement.
pub(crate) enum PendingMiningOperation {
    Raw(PreparedRaw),
    Bound(PreparedBound),
}
pub(crate) enum RawReceiptResolution {
    Bound(Box<PreparedBound>),
    ExpiredCancelled,
}
impl PreparedBound {
    pub(crate) fn bound_descriptor(&self) -> Result<PlannedMiningOutboxDescriptor> {
        Ok(self.descriptor.clone())
    }
    pub(crate) const fn raw_turn_id(&self) -> i64 {
        self.raw_turn_id
    }
    pub(crate) const fn expires_at_unix(&self) -> i64 {
        self.expires_at_unix
    }
}

/// Owns the only connection that has the Stage-3b scalar.  It is neither
/// cloneable nor shareable; the scalar is on for one synchronous transaction.
pub(crate) struct TranscriptMiningStore {
    conn: Connection,
    ingress: AuthenticatedLocalIngress,
    authorized: Arc<Mutex<Option<AttestorGrant>>>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum AttestorOperation {
    Prepare,
    RawReceipt,
    BoundReceipt,
    ExpireActive,
    ExpireAbsence,
    RevocationPrepare,
    RevocationReceipt,
}
impl AttestorOperation {
    const fn name(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::RawReceipt => "raw_receipt",
            Self::BoundReceipt => "bound_receipt",
            Self::ExpireActive => "expire_active",
            Self::ExpireAbsence => "expire_absence",
            Self::RevocationPrepare => "revocation_prepare",
            Self::RevocationReceipt => "revocation_receipt",
        }
    }
}
struct AttestorGrant {
    operation: AttestorOperation,
    entries: Vec<(String, [u8; 32])>,
}
struct AuthorizationScope(Arc<Mutex<Option<AttestorGrant>>>);
impl AuthorizationScope {
    fn extend(&self, lease_id: String, descriptor_sha256: [u8; 32]) -> Result<()> {
        let mut guard = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("transcript attestor unavailable"))?;
        let grant = guard
            .as_mut()
            .context("transcript mining authorization missing")?;
        ensure!(
            !grant
                .entries
                .iter()
                .any(|e| e.0 == lease_id && e.1 == descriptor_sha256),
            "duplicate transcript mining authorization entry"
        );
        grant.entries.push((lease_id, descriptor_sha256));
        Ok(())
    }
}
impl Drop for AuthorizationScope {
    fn drop(&mut self) {
        *self
            .0
            .lock()
            .expect("transcript mining attestor mutex poisoned") = None;
    }
}

impl TranscriptMiningStore {
    pub(crate) fn open(conn: Connection, ingress: AuthenticatedLocalIngress) -> Result<Self> {
        ingress.validate()?;
        let authorized = Arc::new(Mutex::<Option<AttestorGrant>>::new(None));
        let gate = Arc::clone(&authorized);
        conn.create_scalar_function(
            "neoth_transcript_mining_attestor",
            3,
            FunctionFlags::SQLITE_UTF8,
            move |context| {
                let operation = context.get::<String>(0)?;
                let lease = context.get::<String>(1)?;
                let digest = context.get::<Vec<u8>>(2)?;
                let Ok(digest) = <[u8; 32]>::try_from(digest) else {
                    return Ok(0_i64);
                };
                let permitted = gate
                    .lock()
                    .expect("transcript mining attestor mutex poisoned")
                    .as_ref()
                    .is_some_and(|grant| {
                        grant.operation.name() == operation
                            && grant
                                .entries
                                .iter()
                                .any(|(expected_lease, expected_digest)| {
                                    expected_lease == &lease && expected_digest == &digest
                                })
                    });
                Ok(i64::from(permitted))
            },
        )
        .context("install transcript mining attestor scalar")?;
        let birth_gate = Arc::clone(&authorized);
        conn.create_scalar_function(
            "neoth_transcript_mining_attestor_birth",
            0,
            FunctionFlags::SQLITE_UTF8,
            move |_| {
                Ok(i64::from(
                    birth_gate
                        .lock()
                        .expect("transcript mining attestor mutex poisoned")
                        .as_ref()
                        .is_some_and(|grant| grant.operation == AttestorOperation::Prepare),
                ))
            },
        )
        .context("install transcript mining birth attestor scalar")?;
        let database_path = conn
            .path()
            .context("transcript mining requires a file-backed views database")?;
        ensure!(
            std::path::Path::new(database_path).canonicalize()?
                == ingress.home().join("views.db").canonicalize()?,
            "transcript mining connection is outside authenticated home"
        );
        conn.pragma_update(None, "synchronous", "FULL")
            .context("make transcript descriptors durable before WAL append")?;
        Ok(Self {
            conn,
            ingress,
            authorized,
        })
    }
    fn authorize(
        &self,
        operation: AttestorOperation,
        entries: Vec<(String, [u8; 32])>,
    ) -> Result<AuthorizationScope> {
        ensure!(
            !entries.is_empty(),
            "transcript mining authorization has no exact descriptor"
        );
        let mut guard = self
            .authorized
            .lock()
            .expect("transcript mining attestor mutex poisoned");
        ensure!(guard.is_none(), "transcript mining authorization re-entry");
        *guard = Some(AttestorGrant { operation, entries });
        Ok(AuthorizationScope(Arc::clone(&self.authorized)))
    }
    fn extend_authorization(&self, lease_id: String, descriptor_sha256: [u8; 32]) -> Result<()> {
        let mut guard = self
            .authorized
            .lock()
            .expect("transcript mining attestor mutex poisoned");
        let grant = guard
            .as_mut()
            .context("transcript mining authorization missing")?;
        ensure!(
            !grant
                .entries
                .iter()
                .any(|entry| entry.0 == lease_id && entry.1 == descriptor_sha256),
            "duplicate transcript mining authorization entry"
        );
        grant.entries.push((lease_id, descriptor_sha256));
        Ok(())
    }
    fn validate(&self) -> Result<()> {
        self.ingress.validate()
    }

    pub(crate) fn prepare_operator_raw_birth(
        &mut self,
        session_id: &str,
        text: &str,
        now: i64,
    ) -> Result<PreparedRaw> {
        self.validate()?;
        ensure!(
            !session_id.is_empty() && session_id.len() <= 4096,
            "invalid transcript session id"
        );
        ensure!(now >= 0, "invalid transcript timestamp");
        let payload = text.as_bytes().to_vec();
        let header = HeaderBuilder::new(EVENT_TYPE_RAW_TEXT, &payload).build();
        let header_bytes = header.to_le_bytes();
        let header_sha: [u8; 32] = Sha256::digest(header_bytes).into();
        let payload_sha: [u8; 32] = Sha256::digest(&payload).into();
        let descriptor = PlannedRawTextDescriptor::from_persisted(
            &header_bytes,
            header_sha,
            payload.clone(),
            payload_sha,
        )?;
        let provenance_id = opaque("provenance");
        let lifecycle_id = opaque("lifecycle");
        let frame_plan_id = opaque("plan");
        let lease_id = opaque("lease");
        let session_sha: [u8; 32] = Sha256::digest(session_id.as_bytes()).into();
        let retention = self.ingress.retention()?;
        let expires_at = now
            .checked_add(retention.lifetime_seconds())
            .context("transcript retention overflow")?;
        let descriptor_sha = descriptor_digest(&header_sha, &payload_sha);
        let _scope = self.authorize(
            AttestorOperation::Prepare,
            vec![(lease_id.clone(), descriptor_sha)],
        )?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("INSERT INTO raw_turns(session_id,role,ts_unix,text,transcript_mining_authority_epoch,transcript_mining_raw_frame_plan_epoch) VALUES(?1,'operator',?2,?3,1,1)",params![session_id,now,text])?;
        let raw_turn_id = tx.last_insert_rowid();
        tx.execute("INSERT INTO transcript_mining_modern_raw_witness(raw_turn_id,subject_sha256,raw_role,source_kind,witnessed_at_unix) VALUES(?1,?2,'operator','operator_raw_text_v1',?3)",params![raw_turn_id,self.ingress.subject_sha256().as_slice(),now])?;
        tx.execute("INSERT INTO transcript_mining_raw_frame_plan(frame_plan_id,provenance_id,lifecycle_id,raw_turn_id,raw_event_type,raw_event_subtype,planned_wal_format_version,planned_event_schema_version,planned_event_id,planned_hlc_physical_ns,planned_hlc_logical,planned_header,planned_header_sha256,state,planned_at_unix,delivery_lease_id,delivery_descriptor_sha256,delivery_lease) VALUES(?1,?2,?3,?4,1,0,2,4,?5,?6,?7,?8,?9,'planned',?10,?11,?12,'raw_pending')",params![frame_plan_id,provenance_id,lifecycle_id,raw_turn_id,header.event_id.0.to_le_bytes().as_slice(),header.hlc.physical_ns().to_le_bytes().as_slice(),i64::from(header.hlc.logical()),header_bytes.as_slice(),header_sha.as_slice(),now,lease_id,descriptor_sha.as_slice()])?;
        tx.execute("INSERT INTO transcript_mining_provenance(provenance_id,lifecycle_id,raw_turn_id,raw_session_sha256,raw_text_sha256,raw_role,source_kind,retention,lifecycle,created_at_unix,expires_at_unix) VALUES(?1,?2,?3,?4,?5,'operator','operator_raw_text_v1',?6,'pending',?7,?8)",params![provenance_id,lifecycle_id,raw_turn_id,session_sha.as_slice(),payload_sha.as_slice(),retention.sql_name(),now,expires_at])?;
        tx.commit()?;
        Ok(PreparedRaw {
            event_id: header.event_id.0 as i64,
            raw_turn_id,
            expires_at_unix: expires_at,
            frame_plan_id,
            provenance_id,
            lifecycle_id,
            lease_id,
            descriptor_sha256: descriptor_sha,
            descriptor,
        })
    }

    pub(crate) fn record_raw_receipt(
        &mut self,
        p: &PreparedRaw,
        r: &TranscriptMiningFrameReceipt,
        now: i64,
    ) -> Result<RawReceiptResolution> {
        self.validate()?;
        ensure!(now >= 0, "invalid receipt timestamp");
        let _scope = self.authorize(
            AttestorOperation::RawReceipt,
            vec![(p.lease_id.clone(), p.descriptor_sha256)],
        )?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (raw_id,text_sha,subject,retention,created,expires):(i64,Vec<u8>,Vec<u8>,String,i64,i64)=tx.query_row("SELECT p.raw_turn_id,p.raw_text_sha256,w.subject_sha256,p.retention,p.created_at_unix,p.expires_at_unix FROM transcript_mining_provenance p JOIN transcript_mining_modern_raw_witness w ON w.raw_turn_id=p.raw_turn_id JOIN transcript_mining_raw_frame_plan f ON f.provenance_id=p.provenance_id WHERE p.provenance_id=?1 AND p.lifecycle_id=?2 AND f.frame_plan_id=?3 AND f.delivery_lease_id=?4 AND f.delivery_lease='raw_pending' AND f.state='planned'",params![p.provenance_id,p.lifecycle_id,p.frame_plan_id,p.lease_id],|x|Ok((x.get(0)?,x.get(1)?,x.get(2)?,x.get(3)?,x.get(4)?,x.get(5)?)))?;
        ensure!(
            raw_id == p.raw_turn_id(),
            "raw receipt raw turn binding mismatch"
        );
        ensure!(
            expires == p.expires_at_unix(),
            "raw receipt expiry binding mismatch"
        );
        ensure!(
            text_sha.len() == 32 && subject.len() == 32,
            "invalid stored transcript digest"
        );
        let changed=tx.execute("UPDATE transcript_mining_raw_frame_plan SET state='verified',raw_frame_sha256=?1,raw_frame_delivered_at_unix=?2,delivery_lease='bound_pending',raw_receipt_location_sha256=?3 WHERE frame_plan_id=?4 AND state='planned' AND delivery_lease='raw_pending' AND planned_header_sha256=?5",params![r.frame_sha256().as_slice(),now,r.location_sha256().as_slice(),p.frame_plan_id,r.header_sha256().as_slice()])?;
        ensure!(changed == 1, "raw receipt CAS rejected");
        let mut frame = [0; 32];
        frame.copy_from_slice(&r.frame_sha256());
        let mut text = [0; 32];
        text.copy_from_slice(&text_sha);
        ensure!(
            r.payload_sha256() == text,
            "raw receipt payload digest mismatch"
        );
        let mut sub = [0; 32];
        sub.copy_from_slice(&subject);
        if now >= expires {
            let changed = tx.execute("UPDATE transcript_mining_provenance SET lifecycle='cancelled',revoked_at_unix=?1,terminal_cause='retention_expired' WHERE provenance_id=?2 AND lifecycle_id=?3 AND lifecycle='pending'", params![now,p.provenance_id,p.lifecycle_id])?;
            ensure!(
                changed == 1,
                "expired raw provenance cancellation CAS rejected"
            );
            insert_expiry_receipt(&tx, &p.provenance_id)?;
            let changed = tx.execute("UPDATE transcript_mining_raw_frame_plan SET delivery_lease='none' WHERE frame_plan_id=?1 AND delivery_lease_id=?2 AND state='verified' AND delivery_lease='bound_pending'",params![p.frame_plan_id,p.lease_id])?;
            ensure!(changed == 1, "expired raw lease release rejected");
            tx.commit()?;
            return Ok(RawReceiptResolution::ExpiredCancelled);
        }
        let payload = TranscriptMiningBoundV1::from_attested_store(
            p.lifecycle_id.clone(),
            p.provenance_id.clone(),
            sub,
            raw_id,
            frame,
            text,
            parse_retention(&retention)?,
            created,
            expires,
        )?
        .encode()?;
        let payload_sha: [u8; 32] = Sha256::digest(&payload).into();
        let header = HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
            .event_subtype(ExtendedSubtype::TranscriptMiningBound as u8)
            .build();
        let header_bytes = header.to_le_bytes();
        let header_sha: [u8; 32] = Sha256::digest(header_bytes).into();
        let descriptor = PlannedMiningOutboxDescriptor::from_persisted(
            &header_bytes,
            header_sha,
            payload.clone(),
            payload_sha,
        )?;
        let outbox_id = opaque("outbox");
        let descriptor_sha = descriptor_digest(&header_sha, &payload_sha);
        _scope.extend(p.lease_id.clone(), descriptor_sha)?;
        tx.execute("INSERT INTO transcript_mining_wal_outbox(outbox_id,provenance_id,lifecycle_id,logical_subtype,event_subtype,payload,payload_sha256,planned_header,planned_header_sha256,state,enqueued_at_unix,delivery_lease_id,delivery_descriptor_sha256,delivery_lease) VALUES(?1,?2,?3,'bound',40,?4,?5,?6,?7,'pending',?8,?9,?10,'bound_pending')",params![outbox_id,p.provenance_id,p.lifecycle_id,payload,payload_sha.as_slice(),header_bytes.as_slice(),header_sha.as_slice(),now,p.lease_id,descriptor_sha.as_slice()])?;
        tx.commit()?;
        Ok(RawReceiptResolution::Bound(Box::new(PreparedBound {
            outbox_id,
            raw_turn_id: raw_id,
            expires_at_unix: expires,
            provenance_id: p.provenance_id.clone(),
            lifecycle_id: p.lifecycle_id.clone(),
            lease_id: p.lease_id.clone(),
            descriptor_sha256: descriptor_sha,
            raw_descriptor_sha256: p.descriptor_sha256,
            descriptor,
        })))
    }

    pub(crate) fn record_bound_receipt(
        &mut self,
        b: &PreparedBound,
        r: &TranscriptMiningFrameReceipt,
        now: i64,
    ) -> Result<()> {
        self.validate()?;
        ensure!(now >= 0, "invalid receipt timestamp");
        let _scope = self.authorize(
            AttestorOperation::BoundReceipt,
            vec![(b.lease_id.clone(), b.descriptor_sha256)],
        )?;
        self.extend_authorization(b.lease_id.clone(), b.raw_descriptor_sha256)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let n=tx.execute("UPDATE transcript_mining_wal_outbox SET state='delivered',delivered_at_unix=?1,delivered_frame_sha256=?2,delivery_lease='none',delivered_receipt_location_sha256=?3 WHERE outbox_id=?4 AND provenance_id=?5 AND lifecycle_id=?6 AND delivery_lease_id=?7 AND logical_subtype='bound' AND state='pending' AND delivery_lease='bound_pending' AND planned_header_sha256=?8 AND payload_sha256=?9",params![now,r.frame_sha256().as_slice(),r.location_sha256().as_slice(),b.outbox_id,b.provenance_id,b.lifecycle_id,b.lease_id,r.header_sha256().as_slice(),r.payload_sha256().as_slice()])?;
        ensure!(n == 1, "bound receipt CAS rejected");
        if now >= b.expires_at_unix {
            let n = tx.execute("UPDATE transcript_mining_provenance SET lifecycle='cancelled',revoked_at_unix=?1,terminal_cause='retention_expired' WHERE provenance_id=?2 AND lifecycle_id=?3 AND lifecycle='pending' AND expires_at_unix<=?1",params![now,b.provenance_id,b.lifecycle_id])?;
            ensure!(n == 1, "late bound expiry CAS rejected");
            insert_expiry_receipt(&tx, &b.provenance_id)?;
            let n=tx.execute("UPDATE transcript_mining_raw_frame_plan SET delivery_lease='none' WHERE provenance_id=?1 AND lifecycle_id=?2 AND delivery_lease_id=?3 AND delivery_lease='bound_pending' AND state='verified'",params![b.provenance_id,b.lifecycle_id,b.lease_id])?;
            ensure!(n == 1, "late bound raw lease release rejected");
            tx.commit()?;
            return Ok(());
        }
        let n=tx.execute("UPDATE transcript_mining_provenance SET lifecycle='active' WHERE provenance_id=?1 AND lifecycle_id=?2 AND lifecycle='pending'",params![b.provenance_id,b.lifecycle_id])?;
        ensure!(n == 1, "binding activation CAS rejected");
        let n=tx.execute("UPDATE transcript_mining_raw_frame_plan SET delivery_lease='none' WHERE provenance_id=?1 AND lifecycle_id=?2 AND delivery_lease_id=?3 AND delivery_lease='bound_pending' AND state='verified'",params![b.provenance_id,b.lifecycle_id,b.lease_id])?;
        ensure!(n == 1, "raw delivery lease release rejected");
        tx.commit()?;
        Ok(())
    }

    /// Commit only the writer-owned proof of complete authenticated absence for
    /// an expired Bound descriptor.  It cannot be invoked with a Boolean
    /// timeout or an untrusted scan result, and it never creates a replacement
    /// binding header.
    pub(crate) fn record_expired_bound_absence(
        &mut self,
        b: &PreparedBound,
        proof: &crate::wal::transcript_mining_once::ExpiredMiningFrameReceipt,
    ) -> Result<()> {
        self.validate()?;
        ensure!(
            proof.operation_descriptor_sha256() == b.descriptor_sha256,
            "expired absence descriptor mismatch"
        );
        let _scope = self.authorize(
            AttestorOperation::ExpireAbsence,
            vec![
                (b.lease_id.clone(), b.descriptor_sha256),
                (b.lease_id.clone(), b.raw_descriptor_sha256),
            ],
        )?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute("UPDATE transcript_mining_wal_outbox SET state='cancelled',delivery_lease='none' WHERE outbox_id=?1 AND provenance_id=?2 AND lifecycle_id=?3 AND delivery_lease_id=?4 AND logical_subtype='bound' AND state='pending' AND delivery_lease='bound_pending' AND planned_header_sha256=?5 AND payload_sha256=?6 AND delivery_descriptor_sha256=?7", params![b.outbox_id,b.provenance_id,b.lifecycle_id,b.lease_id,proof.header_sha256().as_slice(),proof.payload_sha256().as_slice(),proof.operation_descriptor_sha256().as_slice()])?;
        ensure!(changed == 1, "expired bound cancellation CAS rejected");
        let changed = tx.execute("UPDATE transcript_mining_provenance SET lifecycle='cancelled',revoked_at_unix=?1,terminal_cause='retention_expired' WHERE provenance_id=?2 AND lifecycle_id=?3 AND lifecycle='pending' AND expires_at_unix<=?1",params![proof.observed_at_unix(),b.provenance_id,b.lifecycle_id])?;
        ensure!(changed == 1, "expired provenance cancellation CAS rejected");
        insert_expiry_receipt(&tx, &b.provenance_id)?;
        let changed = tx.execute("UPDATE transcript_mining_raw_frame_plan SET delivery_lease='none' WHERE provenance_id=?1 AND lifecycle_id=?2 AND delivery_lease_id=?3 AND delivery_lease='bound_pending' AND state='verified'",params![b.provenance_id,b.lifecycle_id,b.lease_id])?;
        ensure!(changed == 1, "expired raw lease release rejected");
        tx.commit()?;
        Ok(())
    }

    /// Expiry is a monotonic terminal transition. Authenticate the delivered
    /// Bound before creating its local terminal receipt or any revocation.
    fn expire_active_bindings(&mut self, now: i64) -> Result<()> {
        let ids = {
            let mut statement = self.conn.prepare(
                "SELECT provenance_id FROM transcript_mining_provenance
                 WHERE lifecycle='active' AND expires_at_unix<=?1 ORDER BY provenance_id",
            )?;
            statement
                .query_map([now], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        for provenance_id in ids {
            let verified =
                authenticate_bound_projection(&self.conn, &self.ingress, &provenance_id)?;
            let _scope = self.authorize(
                AttestorOperation::ExpireActive,
                vec![(verified.lease_id, verified.descriptor_sha256)],
            )?;
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let changed = tx.execute(
                "UPDATE transcript_mining_provenance SET lifecycle='revoked',
                   terminal_cause='retention_expired',revoked_at_unix=?1
                 WHERE provenance_id=?2 AND lifecycle='active' AND expires_at_unix<=?1",
                params![now, provenance_id],
            )?;
            if changed == 1 {
                insert_expiry_receipt(&tx, &provenance_id)?;
            }
            tx.commit()?;
        }
        Ok(())
    }

    /// Recover existing fixed 0x29 descriptors and prepare missing ones only
    /// from a verified delivered Bound plus its immutable terminal receipt.
    pub(crate) fn prepare_pending_revocations(&mut self, now: i64) -> Result<Vec<PreparedRevoked>> {
        self.validate()?;
        ensure!(now >= 0, "invalid revocation timestamp");
        self.expire_active_bindings(now)?;
        let terminals = {
            let mut statement = self.conn.prepare(
                "SELECT p.provenance_id,p.lifecycle_id,p.lifecycle,p.terminal_cause,
                        p.revoked_at_unix,r.receipt_id
                 FROM transcript_mining_provenance p
                 JOIN transcript_mining_revocation_receipts r ON r.provenance_id=p.provenance_id
                   AND r.lifecycle_id=p.lifecycle_id AND r.raw_turn_id=p.raw_turn_id
                   AND r.revocation=p.terminal_cause AND r.lifecycle=p.lifecycle
                   AND r.occurred_at_unix=p.revoked_at_unix
                 JOIN transcript_mining_wal_outbox b ON b.provenance_id=p.provenance_id
                   AND b.lifecycle_id=p.lifecycle_id AND b.logical_subtype='bound' AND b.state='delivered'
                 WHERE p.lifecycle IN ('revoked','cancelled')
                   AND p.terminal_cause IN ('raw_turn_deleted','retention_expired')
                   AND NOT EXISTS(SELECT 1 FROM transcript_mining_wal_outbox o
                                  WHERE o.provenance_id=p.provenance_id AND o.logical_subtype='revoked'
                                    AND o.state='delivered')
                 ORDER BY p.provenance_id")?;
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut result = Vec::new();
        for (provenance_id, lifecycle_id, lifecycle, cause, revoked_at, receipt_id) in terminals {
            let verified =
                authenticate_bound_projection(&self.conn, &self.ingress, &provenance_id)?;
            let cause = match cause.as_str() {
                "raw_turn_deleted" => MiningRevocation::RawTurnDeleted,
                "retention_expired" => MiningRevocation::RetentionExpired,
                _ => anyhow::bail!("unsupported terminal revocation cause"),
            };
            let lifecycle = match lifecycle.as_str() {
                "revoked" => MiningLifecycle::Revoked,
                "cancelled" => MiningLifecycle::Cancelled,
                _ => anyhow::bail!("invalid terminal revocation lifecycle"),
            };
            let payload = verified
                .payload
                .revocation_payload(cause, lifecycle, revoked_at)?;
            let payload_sha: [u8; 32] = Sha256::digest(&payload).into();
            let existing = self
                .conn
                .query_row(
                    "SELECT outbox_id,delivery_lease_id,planned_header,planned_header_sha256,
                        payload,payload_sha256,delivery_descriptor_sha256
                 FROM transcript_mining_wal_outbox
                 WHERE provenance_id=?1 AND lifecycle_id=?2 AND logical_subtype='revoked'
                   AND state='pending' AND delivery_lease='revocation_pending'
                   AND revocation_receipt_id=?3 AND bound_payload_sha256=?4",
                    params![
                        provenance_id,
                        lifecycle_id,
                        receipt_id,
                        verified.payload_sha256.as_slice()
                    ],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, Vec<u8>>(4)?,
                            row.get::<_, Vec<u8>>(5)?,
                            row.get::<_, Vec<u8>>(6)?,
                        ))
                    },
                )
                .optional()?;
            if let Some((
                outbox_id,
                lease_id,
                header,
                header_sha,
                stored_payload,
                stored_payload_sha,
                stored_descriptor_sha,
            )) = existing
            {
                ensure!(
                    stored_payload == payload && stored_payload_sha == payload_sha,
                    "persisted revocation does not match authenticated terminal binding"
                );
                let header_sha = digest32(&header_sha)?;
                let descriptor_sha256 = descriptor_digest(&header_sha, &payload_sha);
                ensure!(
                    stored_descriptor_sha == descriptor_sha256,
                    "revocation operation digest mismatch"
                );
                let descriptor = PlannedMiningOutboxDescriptor::from_persisted(
                    &header,
                    header_sha,
                    payload,
                    payload_sha,
                )?;
                result.push(PreparedRevoked {
                    outbox_id,
                    provenance_id,
                    lifecycle_id,
                    lease_id,
                    descriptor_sha256,
                    descriptor,
                });
                continue;
            }
            let header = HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
                .event_subtype(ExtendedSubtype::TranscriptMiningRevoked as u8)
                .build();
            let header_bytes = header.to_le_bytes();
            let header_sha: [u8; 32] = Sha256::digest(header_bytes).into();
            let descriptor = PlannedMiningOutboxDescriptor::from_persisted(
                &header_bytes,
                header_sha,
                payload.clone(),
                payload_sha,
            )?;
            let descriptor_sha256 = descriptor_digest(&header_sha, &payload_sha);
            let outbox_id = opaque("outbox");
            let lease_id = opaque("lease");
            let _scope = self.authorize(
                AttestorOperation::RevocationPrepare,
                vec![(lease_id.clone(), descriptor_sha256)],
            )?;
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute(
                "INSERT INTO transcript_mining_wal_outbox(outbox_id,provenance_id,lifecycle_id,
                   logical_subtype,event_subtype,payload,payload_sha256,planned_header,planned_header_sha256,
                   bound_payload_sha256,revocation_receipt_id,state,enqueued_at_unix,delivery_lease_id,
                   delivery_descriptor_sha256,delivery_lease)
                 VALUES(?1,?2,?3,'revoked',41,?4,?5,?6,?7,?8,?9,'pending',?10,?11,?12,'revocation_pending')",
                params![outbox_id,provenance_id,lifecycle_id,payload,payload_sha.as_slice(),
                    header_bytes.as_slice(),header_sha.as_slice(),verified.payload_sha256.as_slice(),
                    receipt_id,now,lease_id,descriptor_sha256.as_slice()])?;
            tx.commit()?;
            result.push(PreparedRevoked {
                outbox_id,
                provenance_id,
                lifecycle_id,
                lease_id,
                descriptor_sha256,
                descriptor,
            });
        }
        Ok(result)
    }

    pub(crate) fn record_revoked_receipt(
        &mut self,
        r: &PreparedRevoked,
        receipt: &TranscriptMiningFrameReceipt,
        now: i64,
    ) -> Result<()> {
        self.validate()?;
        let _scope = self.authorize(
            AttestorOperation::RevocationReceipt,
            vec![(r.lease_id.clone(), r.descriptor_sha256)],
        )?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed=tx.execute("UPDATE transcript_mining_wal_outbox SET state='delivered',delivered_at_unix=?1,delivered_frame_sha256=?2,delivered_receipt_location_sha256=?3,delivery_lease='none' WHERE outbox_id=?4 AND provenance_id=?5 AND lifecycle_id=?6 AND logical_subtype='revoked' AND state='pending' AND delivery_lease='revocation_pending' AND delivery_lease_id=?7 AND planned_header_sha256=?8 AND payload_sha256=?9",params![now,receipt.frame_sha256().as_slice(),receipt.location_sha256().as_slice(),r.outbox_id,r.provenance_id,r.lifecycle_id,r.lease_id,receipt.header_sha256().as_slice(),receipt.payload_sha256().as_slice()])?;
        ensure!(changed == 1, "revocation receipt CAS rejected");
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn resume_pending(&mut self, now: i64) -> Result<Vec<PendingMiningOperation>> {
        self.validate()?;
        ensure!(now >= 0, "invalid reconciliation timestamp");
        let mut pending = Vec::new();
        let mut statement = self.conn.prepare(
            "SELECT f.frame_plan_id,f.provenance_id,f.lifecycle_id,f.delivery_lease_id,
                    f.planned_header,f.planned_header_sha256,f.delivery_descriptor_sha256,r.text,p.raw_text_sha256,w.subject_sha256,p.raw_turn_id,p.expires_at_unix,
                    o.outbox_id,o.planned_header,o.planned_header_sha256,o.payload,o.payload_sha256,o.delivery_descriptor_sha256
             FROM transcript_mining_raw_frame_plan f
             JOIN transcript_mining_provenance p ON p.provenance_id=f.provenance_id
             JOIN transcript_mining_modern_raw_witness w ON w.raw_turn_id=f.raw_turn_id
             JOIN raw_turns r ON r.id=f.raw_turn_id
             LEFT JOIN transcript_mining_wal_outbox o ON o.provenance_id=f.provenance_id AND o.logical_subtype='bound'
             WHERE f.delivery_lease IN ('raw_pending','bound_pending') ORDER BY f.planned_at_unix ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, Vec<u8>>(8)?,
                row.get::<_, Vec<u8>>(9)?,
                row.get::<_, i64>(10)?,
                row.get::<_, i64>(11)?,
                row.get::<_, Option<String>>(12)?,
                row.get::<_, Option<Vec<u8>>>(13)?,
                row.get::<_, Option<Vec<u8>>>(14)?,
                row.get::<_, Option<Vec<u8>>>(15)?,
                row.get::<_, Option<Vec<u8>>>(16)?,
                row.get::<_, Option<Vec<u8>>>(17)?,
            ))
        })?;
        for row in rows {
            let (
                plan_id,
                provenance_id,
                lifecycle_id,
                lease_id,
                raw_header,
                raw_header_sha,
                raw_descriptor_sha,
                text,
                text_sha,
                subject,
                raw_turn_id,
                expires_at_unix,
                outbox_id,
                out_header,
                out_header_sha,
                out_payload,
                out_payload_sha,
                out_descriptor_sha,
            ) = row?;
            let subject: [u8; 32] = subject
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid persisted subject digest"))?;
            ensure!(
                self.ingress.accepts_subject_sha256(&subject)?,
                "persisted transcript subject no longer belongs to this home"
            );
            let raw_header_sha: [u8; 32] = raw_header_sha
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid persisted raw header digest"))?;
            let raw_descriptor_sha: [u8; 32] = raw_descriptor_sha
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid persisted raw descriptor digest"))?;
            let text_sha: [u8; 32] = text_sha
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid persisted raw text digest"))?;
            if let (
                Some(outbox_id),
                Some(header),
                Some(header_sha),
                Some(payload),
                Some(payload_sha),
                Some(descriptor_sha),
            ) = (
                outbox_id,
                out_header,
                out_header_sha,
                out_payload,
                out_payload_sha,
                out_descriptor_sha,
            ) {
                let header_sha: [u8; 32] = header_sha
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid persisted bound header digest"))?;
                let payload_sha: [u8; 32] = payload_sha
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid persisted bound payload digest"))?;
                let descriptor_sha: [u8; 32] = descriptor_sha
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid persisted bound descriptor digest"))?;
                pending.push(PendingMiningOperation::Bound(PreparedBound {
                    outbox_id,
                    raw_turn_id,
                    expires_at_unix,
                    provenance_id,
                    lifecycle_id,
                    lease_id,
                    descriptor_sha256: descriptor_sha,
                    raw_descriptor_sha256: raw_descriptor_sha,
                    descriptor: PlannedMiningOutboxDescriptor::from_persisted(
                        &header,
                        header_sha,
                        payload,
                        payload_sha,
                    )?,
                }));
            } else {
                let header: [u8; 96] = raw_header
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid persisted raw header length"))?;
                let event_id = crate::wal::EventHeaderV2::from_le_bytes(&header)?
                    .event_id
                    .0 as i64;
                let raw = PlannedRawTextDescriptor::from_persisted(
                    &raw_header,
                    raw_header_sha,
                    text.into_bytes(),
                    text_sha,
                )?;
                pending.push(PendingMiningOperation::Raw(PreparedRaw {
                    event_id,
                    raw_turn_id,
                    expires_at_unix,
                    frame_plan_id: plan_id,
                    provenance_id,
                    lifecycle_id,
                    lease_id,
                    descriptor_sha256: raw_descriptor_sha,
                    descriptor: raw,
                }));
            }
        }
        Ok(pending)
    }

    /// A SQLite active flag is insufficient.  Consumers must call this before
    /// mining: both exact physical frames are re-read through the authenticated
    /// WAL prefix and compared with the persisted receipts and lifecycle.
    pub(crate) fn active_binding_is_usable(&self, raw_turn_id: i64, now: i64) -> Result<bool> {
        let row: Result<ActiveBindingRow> = self.conn.query_row(
            "SELECT f.planned_header,f.planned_header_sha256,r.text,p.raw_text_sha256,f.raw_frame_sha256,
                    o.planned_header,o.planned_header_sha256,o.payload,o.payload_sha256,o.delivered_frame_sha256
             FROM transcript_mining_provenance p JOIN transcript_mining_raw_frame_plan f ON f.provenance_id=p.provenance_id
             JOIN raw_turns r ON r.id=p.raw_turn_id JOIN transcript_mining_wal_outbox o ON o.provenance_id=p.provenance_id AND o.logical_subtype='bound'
             WHERE p.raw_turn_id=?1 AND p.lifecycle='active' AND p.expires_at_unix>?2 AND p.terminal_cause IS NULL
               AND f.state='verified' AND f.delivery_lease='none' AND o.state='delivered' AND o.delivery_lease='none'", params![raw_turn_id,now], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?))).map_err(Into::into);
        let Ok((
            raw_header,
            raw_header_sha,
            text,
            text_sha,
            raw_frame_sha,
            bound_header,
            bound_header_sha,
            bound_payload,
            bound_payload_sha,
            bound_frame_sha,
        )) = row
        else {
            return Ok(false);
        };
        let raw_header_sha: [u8; 32] = match raw_header_sha.try_into() {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        let text_sha: [u8; 32] = match text_sha.try_into() {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        let raw_frame_sha: [u8; 32] = match raw_frame_sha.try_into() {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        let bound_header_sha: [u8; 32] = match bound_header_sha.try_into() {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        let bound_payload_sha: [u8; 32] = match bound_payload_sha.try_into() {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        let bound_frame_sha: [u8; 32] = match bound_frame_sha.try_into() {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        let subject: Result<Vec<u8>> = self.conn.query_row(
            "SELECT subject_sha256 FROM transcript_mining_modern_raw_witness WHERE raw_turn_id=?1",
            [raw_turn_id], |row| row.get(0),
        ).map_err(Into::into);
        let Ok(subject) = subject else {
            return Ok(false);
        };
        let Ok(subject) = <[u8; 32]>::try_from(subject) else {
            return Ok(false);
        };
        if !self.ingress.accepts_subject_sha256(&subject)? {
            return Ok(false);
        }
        // Rebuild the only canonical bound payload that this exact DB row may
        // authorize.  Merely finding two authentic frames is insufficient:
        // a corrupted SQLite projection must not be able to point row B at a
        // valid binding frame that belongs to row A.
        let canonical: Result<Vec<u8>> = self.conn.query_row(
            "SELECT p.lifecycle_id,p.provenance_id,w.subject_sha256,p.raw_turn_id,f.raw_frame_sha256,p.raw_text_sha256,p.retention,p.created_at_unix,p.expires_at_unix
             FROM transcript_mining_provenance p JOIN transcript_mining_modern_raw_witness w ON w.raw_turn_id=p.raw_turn_id
             JOIN transcript_mining_raw_frame_plan f ON f.provenance_id=p.provenance_id AND f.lifecycle_id=p.lifecycle_id AND f.raw_turn_id=p.raw_turn_id
             JOIN raw_turns r ON r.id=p.raw_turn_id
             WHERE p.raw_turn_id=?1 AND p.raw_role='operator' AND p.source_kind='operator_raw_text_v1'
               AND r.role='operator' AND r.transcript_mining_authority_epoch=1 AND r.transcript_mining_raw_frame_plan_epoch=1
               AND w.raw_role='operator' AND w.source_kind='operator_raw_text_v1'", [raw_turn_id], |row| {
                let lifecycle: String=row.get(0)?; let provenance: String=row.get(1)?;
                let subject: Vec<u8>=row.get(2)?; let raw_id:i64=row.get(3)?; let frame:Vec<u8>=row.get(4)?; let text:Vec<u8>=row.get(5)?; let retention:String=row.get(6)?; let created:i64=row.get(7)?; let expires:i64=row.get(8)?;
                let subject:[u8;32]=subject.try_into().map_err(|_|rusqlite::Error::InvalidQuery)?;
                let frame:[u8;32]=frame.try_into().map_err(|_|rusqlite::Error::InvalidQuery)?;
                let text:[u8;32]=text.try_into().map_err(|_|rusqlite::Error::InvalidQuery)?;
                TranscriptMiningBoundV1::from_attested_store(lifecycle,provenance,subject,raw_id,frame,text,parse_retention(&retention).map_err(|_|rusqlite::Error::InvalidQuery)?,created,expires).and_then(|v|v.encode()).map_err(|_|rusqlite::Error::InvalidQuery)
            }).map_err(Into::into);
        let Ok(canonical) = canonical else {
            return Ok(false);
        };
        if canonical != bound_payload {
            return Ok(false);
        }
        let raw = match PlannedRawTextDescriptor::from_persisted(
            &raw_header,
            raw_header_sha,
            text.into_bytes(),
            text_sha,
        ) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        let bound = match PlannedMiningOutboxDescriptor::from_persisted(
            &bound_header,
            bound_header_sha,
            bound_payload,
            bound_payload_sha,
        ) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        let raw_receipt = match crate::wal::transcript_mining_once::verify_exact_at_home(
            self.ingress.home(),
            &crate::wal::transcript_mining_once::TranscriptMiningDescriptor::raw(raw),
        ) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        let bound_receipt = match crate::wal::transcript_mining_once::verify_exact_at_home(
            self.ingress.home(),
            &crate::wal::transcript_mining_once::TranscriptMiningDescriptor::outbox(bound),
        ) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        let locations = self.conn.query_row(
            "SELECT f.raw_receipt_location_sha256,f.delivery_descriptor_sha256,
                    o.delivered_receipt_location_sha256,o.delivery_descriptor_sha256
             FROM transcript_mining_provenance p
             JOIN transcript_mining_raw_frame_plan f ON f.provenance_id=p.provenance_id
               AND f.lifecycle_id=p.lifecycle_id AND f.raw_turn_id=p.raw_turn_id
             JOIN transcript_mining_wal_outbox o ON o.provenance_id=p.provenance_id
               AND o.lifecycle_id=p.lifecycle_id AND o.logical_subtype='bound'
             WHERE p.raw_turn_id=?1",
            [raw_turn_id],
            |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                ))
            },
        );
        let Ok((raw_location, raw_descriptor, bound_location, bound_descriptor)) = locations else {
            return Ok(false);
        };
        Ok(raw_receipt.frame_sha256() == raw_frame_sha
            && raw_receipt.payload_sha256() == text_sha
            && bound_receipt.frame_sha256() == bound_frame_sha
            && bound_receipt.payload_sha256() == bound_payload_sha
            && raw_receipt.location_sha256().as_slice() == raw_location
            && bound_receipt.location_sha256().as_slice() == bound_location
            && descriptor_digest(&raw_header_sha, &text_sha).as_slice() == raw_descriptor
            && descriptor_digest(&bound_header_sha, &bound_payload_sha).as_slice()
                == bound_descriptor)
    }
}
struct VerifiedStoredBound {
    payload: TranscriptMiningBoundV1,
    payload_sha256: [u8; 32],
    lease_id: String,
    descriptor_sha256: [u8; 32],
}

/// Verify the immutable Bound independently of mutable raw-plan bookkeeping.
/// This remains usable after raw deletion or a degraded raw-plan projection.
fn authenticate_bound_projection(
    conn: &Connection,
    ingress: &AuthenticatedLocalIngress,
    provenance_id: &str,
) -> Result<VerifiedStoredBound> {
    ingress.validate()?;
    struct Stored {
        header: Vec<u8>,
        header_sha: Vec<u8>,
        payload: Vec<u8>,
        payload_sha: Vec<u8>,
        frame_sha: Vec<u8>,
        location_sha: Vec<u8>,
        lease_id: String,
        descriptor_sha: Vec<u8>,
        lifecycle_id: String,
        raw_id: i64,
        subject: Vec<u8>,
        text_sha: Vec<u8>,
        retention: String,
        created: i64,
        expires: i64,
    }
    let row = conn.query_row(
        "SELECT b.planned_header,b.planned_header_sha256,b.payload,b.payload_sha256,
                b.delivered_frame_sha256,b.delivered_receipt_location_sha256,
                b.delivery_lease_id,b.delivery_descriptor_sha256,
                p.lifecycle_id,p.raw_turn_id,w.subject_sha256,p.raw_text_sha256,
                p.retention,p.created_at_unix,p.expires_at_unix
         FROM transcript_mining_provenance p
         JOIN transcript_mining_modern_raw_witness w ON w.raw_turn_id=p.raw_turn_id
         JOIN transcript_mining_wal_outbox b ON b.provenance_id=p.provenance_id
           AND b.lifecycle_id=p.lifecycle_id AND b.logical_subtype='bound'
         WHERE p.provenance_id=?1 AND b.state='delivered' AND b.delivery_lease='none'
           AND p.raw_role='operator' AND p.source_kind='operator_raw_text_v1'
           AND w.raw_role='operator' AND w.source_kind='operator_raw_text_v1'",
        [provenance_id],
        |r| {
            Ok(Stored {
                header: r.get(0)?,
                header_sha: r.get(1)?,
                payload: r.get(2)?,
                payload_sha: r.get(3)?,
                frame_sha: r.get(4)?,
                location_sha: r.get(5)?,
                lease_id: r.get(6)?,
                descriptor_sha: r.get(7)?,
                lifecycle_id: r.get(8)?,
                raw_id: r.get(9)?,
                subject: r.get(10)?,
                text_sha: r.get(11)?,
                retention: r.get(12)?,
                created: r.get(13)?,
                expires: r.get(14)?,
            })
        },
    )?;
    let subject = digest32(&row.subject)?;
    ensure!(
        ingress.accepts_subject_sha256(&subject)?,
        "bound subject does not belong to this home"
    );
    let header_sha = digest32(&row.header_sha)?;
    let payload_sha256 = digest32(&row.payload_sha)?;
    let descriptor_sha256 = descriptor_digest(&header_sha, &payload_sha256);
    ensure!(
        row.descriptor_sha == descriptor_sha256,
        "bound operation digest mismatch"
    );
    let payload = TranscriptMiningBoundV1::decode(&row.payload)?;
    let canonical = TranscriptMiningBoundV1::from_attested_store(
        row.lifecycle_id,
        provenance_id.to_owned(),
        subject,
        row.raw_id,
        payload.raw_frame_sha256(),
        digest32(&row.text_sha)?,
        parse_retention(&row.retention)?,
        row.created,
        row.expires,
    )?
    .encode()?;
    ensure!(
        canonical == row.payload,
        "bound payload does not match this provenance"
    );
    let descriptor = PlannedMiningOutboxDescriptor::from_persisted(
        &row.header,
        header_sha,
        row.payload,
        payload_sha256,
    )?;
    let receipt = crate::wal::transcript_mining_once::verify_exact_at_home(
        ingress.home(),
        &crate::wal::transcript_mining_once::TranscriptMiningDescriptor::outbox(descriptor),
    )?;
    ensure!(
        receipt.frame_sha256() == digest32(&row.frame_sha)?
            && receipt.location_sha256() == digest32(&row.location_sha)?,
        "bound physical receipt does not match authenticated WAL"
    );
    Ok(VerifiedStoredBound {
        payload,
        payload_sha256,
        lease_id: row.lease_id,
        descriptor_sha256,
    })
}

fn insert_expiry_receipt(conn: &Connection, provenance_id: &str) -> Result<()> {
    let changed = conn.execute(
        "INSERT INTO transcript_mining_revocation_receipts(receipt_id,provenance_id,lifecycle_id,
             raw_turn_id,revocation,lifecycle,occurred_at_unix)
         SELECT 'retention-expired-'||provenance_id,provenance_id,lifecycle_id,raw_turn_id,
                terminal_cause,lifecycle,revoked_at_unix
         FROM transcript_mining_provenance WHERE provenance_id=?1
           AND terminal_cause='retention_expired' AND lifecycle IN ('revoked','cancelled')",
        [provenance_id],
    )?;
    ensure!(changed == 1, "retention terminal receipt missing");
    Ok(())
}

fn digest32(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid transcript SHA-256 length"))
}

fn opaque(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::now_v7().simple())
}
fn descriptor_digest(header: &[u8; 32], payload: &[u8; 32]) -> [u8; 32] {
    crate::wal::transcript_mining_once::descriptor_sha256(*header, *payload)
}
fn parse_retention(v: &str) -> Result<FiniteRetention> {
    match v {
        "minutes15" => Ok(FiniteRetention::Minutes15),
        "hours24" => Ok(FiniteRetention::Hours24),
        "days30" => Ok(FiniteRetention::Days30),
        _ => anyhow::bail!("invalid persisted transcript retention"),
    }
}

#[cfg(test)]
#[path = "transcript_mining_store_tests.rs"]
mod tests;
