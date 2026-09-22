//! W209 — verified counterparty consent ceremony.
//!
//! This module deliberately owns no channel adapter and exposes no operator
//! grant.  The serving ingress recognizes the reserved command namespace before
//! RAW_TEXT, transcript, profile, or provider work.  It may construct an
//! [`AuthenticatedInboundProof`] only after its dedicated content-free
//! `CounterpartyConsentInput` receipt is durable.  A counterparty then proves
//! control of that same authenticated sender by echoing a short-lived challenge
//! on the same conversation.
//!
//! The API is split at the WAL boundary.  SQLite transactions are always
//! completed before an awaited WAL append; the later commit accepts only the
//! exact reservation and the durable audit receipt returned by that append.
//! Thus a grant is never eligible before its proof audit is durable.  Revoke
//! deliberately has the opposite fail-closed order: denial and quarantine are
//! committed first and a content-free pending-audit record survives any failed
//! or ambiguous append for later exact replay repair.

use anyhow::{Context, Result, anyhow, bail, ensure};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::memory::counterparty_consent::{
    ConsentStatus, CounterpartyKey, RevocationResult, revoke_and_quarantine, status,
};

pub const COMMAND_REQUEST: &str = "/neoth consent clustering request";
pub const COMMAND_REVOKE: &str = "/neoth consent clustering revoke";
pub const COMMAND_GRANT_PREFIX: &str = "/neoth consent clustering grant ";
const RESERVED_PREFIX: &str = "/neoth consent clustering";

pub const CHALLENGE_TTL_NS: i64 = 10 * 60 * 1_000_000_000;
const TOKEN_BYTES: usize = 32;
const TOKEN_HEX_LEN: usize = TOKEN_BYTES * 2;
const OPERATION_BYTES: usize = 16;
const OPERATION_HEX_LEN: usize = OPERATION_BYTES * 2;
const SHA256_LEN: usize = 32;
const CHALLENGE_DOMAIN: &[u8] = b"neoth/w209/counterparty-consent/challenge/v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"neoth/w209/counterparty-consent/evidence/v1\0";
const AUDIT_DOMAIN: &[u8] = b"neoth/w209/counterparty-consent/audit/v1\0";
const GRANT_PROOF_KIND: &str = "authenticated_channel_echo_v1";

/// Required additive v43 table.  The parent migration owns applying this SQL;
/// this module never initialises schemas opportunistically at runtime.
pub const CHALLENGE_SCHEMA_SQL: &str = r#"
CREATE TABLE idx_counterparty_consent_challenge_v1 (
    channel_id              TEXT NOT NULL,
    account_id              TEXT NOT NULL,
    scoped_sender_hash      TEXT NOT NULL,
    conversation_sha256     BLOB NOT NULL CHECK(length(conversation_sha256)=32),
    token_sha256            BLOB NOT NULL CHECK(length(token_sha256)=32),
    issued_input_receipt_event_id INTEGER NOT NULL CHECK(issued_input_receipt_event_id>0),
    issued_consent_state    TEXT NOT NULL CHECK(issued_consent_state IN ('absent','verified_granted','revoked')),
    issued_consent_revision INTEGER NOT NULL CHECK(issued_consent_revision>=0),
    expires_at_ns           INTEGER NOT NULL,
    state                   TEXT NOT NULL CHECK(state IN ('pending','grant_audit_pending','revoke_audit_pending','revoked_audited','consumed','cancelled')),
    operation_id            TEXT,
    audit_event_id          INTEGER,
    reservation_evidence_sha256 BLOB CHECK(reservation_evidence_sha256 IS NULL OR length(reservation_evidence_sha256)=32),
    reservation_input_receipt_event_id INTEGER,
    reservation_input_sha256 BLOB CHECK(reservation_input_sha256 IS NULL OR length(reservation_input_sha256)=32),
    reservation_payload_sha256 BLOB CHECK(reservation_payload_sha256 IS NULL OR length(reservation_payload_sha256)=32),
    baseline_consent_state  TEXT CHECK(baseline_consent_state IS NULL OR baseline_consent_state IN ('absent','verified_granted','revoked')),
    baseline_consent_revision INTEGER,
    PRIMARY KEY(channel_id, account_id, scoped_sender_hash)
) STRICT;

-- A revoke may terminally supersede an in-flight grant audit, but never erase
-- its custody. This table is audit/readback evidence only; recovery does not
-- retry a superseded grant because denial has already won.
CREATE TABLE idx_counterparty_consent_audit_terminal_v1 (
    operation_id            TEXT PRIMARY KEY,
    channel_id              TEXT NOT NULL,
    account_id              TEXT NOT NULL,
    scoped_sender_hash      TEXT NOT NULL,
    action                  TEXT NOT NULL CHECK(action='verified_grant'),
    evidence_sha256         BLOB NOT NULL CHECK(length(evidence_sha256)=32),
    input_receipt_event_id  INTEGER NOT NULL CHECK(input_receipt_event_id>0),
    input_sha256            BLOB NOT NULL CHECK(length(input_sha256)=32),
    payload_sha256          BLOB NOT NULL CHECK(length(payload_sha256)=32),
    baseline_consent_state  TEXT NOT NULL CHECK(baseline_consent_state IN ('absent','verified_granted','revoked')),
    baseline_consent_revision INTEGER NOT NULL CHECK(baseline_consent_revision>=0),
    terminal_state          TEXT NOT NULL CHECK(terminal_state='superseded_by_revoke'),
    terminal_by_operation_id TEXT NOT NULL
) STRICT;
"#;

#[derive(Clone, PartialEq, Eq)]
pub enum CounterpartyConsentCommand {
    Request,
    Grant { token: String },
    Revoke,
}

impl std::fmt::Debug for CounterpartyConsentCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Request => formatter.write_str("CounterpartyConsentCommand::Request"),
            Self::Grant { .. } => {
                formatter.write_str("CounterpartyConsentCommand::Grant([REDACTED])")
            }
            Self::Revoke => formatter.write_str("CounterpartyConsentCommand::Revoke"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CeremonyCommandParse {
    NotCeremony,
    Command(CounterpartyConsentCommand),
    /// A reserved namespace attempt that must receive a controlled error and
    /// must never fall through to ordinary chat, RAW_TEXT, or a provider.
    MalformedReserved,
}

/// Deliberately strict.  Commands must be the whole sanitized message; quoted,
/// embedded, Unicode-lookalike, and whitespace-normalised text stays ordinary
/// conversation content and cannot mutate consent.
pub fn parse_command(text: &str) -> CeremonyCommandParse {
    if text == COMMAND_REQUEST {
        CeremonyCommandParse::Command(CounterpartyConsentCommand::Request)
    } else if text == COMMAND_REVOKE {
        CeremonyCommandParse::Command(CounterpartyConsentCommand::Revoke)
    } else if let Some(token) = text.strip_prefix(COMMAND_GRANT_PREFIX) {
        match validate_token(token) {
            Ok(()) => CeremonyCommandParse::Command(CounterpartyConsentCommand::Grant {
                token: token.to_owned(),
            }),
            Err(_) => CeremonyCommandParse::MalformedReserved,
        }
    } else if text.contains(RESERVED_PREFIX) {
        CeremonyCommandParse::MalformedReserved
    } else {
        CeremonyCommandParse::NotCeremony
    }
}

/// Trusted witness supplied only by the real accepted-channel ingress after a
/// content-free `CounterpartyConsentInput` receipt is durable. It intentionally
/// has no public constructor: a CLI, GUI, adapter payload, or operator action
/// cannot mint a proof object.
#[derive(Clone, Debug)]
pub(crate) struct AuthenticatedInboundProof {
    key: CounterpartyKey,
    conversation_sha256: [u8; SHA256_LEN],
    input_receipt_event_id: i64,
    wal_session_id: [u8; 16],
    input_sha256: [u8; SHA256_LEN],
}

impl AuthenticatedInboundProof {
    /// This bridge accepts only a capability minted by the closed WAL writer
    /// after durable append of the dedicated content-free input receipt. The
    /// writer type has private fields and no generic-frame constructor; a CLI,
    /// GUI, adapter, or arbitrary crate-private caller cannot forge it.
    pub(crate) fn from_writer_issued_receipt(
        receipt: &crate::wal::writer::CounterpartyConsentInputReceipt,
    ) -> Result<Self> {
        let key = CounterpartyKey::from_authenticated(
            receipt.channel_ref(),
            receipt.scoped_sender_hash(),
        )?;
        Ok(Self {
            key,
            conversation_sha256: receipt.conversation_sha256(),
            input_receipt_event_id: receipt.event_id(),
            wal_session_id: receipt.wal_session_id(),
            input_sha256: receipt.input_sha256(),
        })
    }

    fn evidence_sha256(&self) -> [u8; SHA256_LEN] {
        sha256_tagged(
            EVIDENCE_DOMAIN,
            &[
                self.key.channel_id().as_bytes(),
                self.key.account_id().as_bytes(),
                self.key.scoped_sender_hash().as_bytes(),
                &self.conversation_sha256,
                &self.input_receipt_event_id.to_be_bytes(),
                &self.wal_session_id,
                &self.input_sha256,
            ],
        )
    }
}

/// One response returned only once to the authenticated counterparty.  The
/// plaintext token must not be logged, placed in WAL payloads, or rendered in
/// a status surface; only its SHA-256 commitment is persistent.
#[derive(Clone, PartialEq, Eq)]
pub struct ChallengeReply {
    pub command: String,
    pub expires_at_ns: i64,
}

impl std::fmt::Debug for ChallengeReply {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ChallengeReply")
            .field("command", &"[REDACTED]")
            .field("expires_at_ns", &self.expires_at_ns)
            .finish()
    }
}

/// Opaque reservation used across the no-SQLite-borrow WAL await.  It names
/// neither an operator nor a user-selectable scope.
#[derive(Clone, Debug)]
pub(crate) struct AuditReservation {
    operation_id: String,
    kind: ReservationKind,
    key: CounterpartyKey,
    evidence_sha256: [u8; SHA256_LEN],
    input_receipt_event_id: i64,
    input_sha256: [u8; SHA256_LEN],
    payload_sha256: [u8; SHA256_LEN],
    baseline: ConsentBaseline,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ConsentBaseline {
    state: &'static str,
    revision: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReservationKind {
    Grant,
    Revoke,
}

type PendingAuditRow = (String, String, Vec<u8>, i64, Vec<u8>, Vec<u8>, String, i64);

/// Immutable description of the event that the integration must append using
/// its closed WAL writer API.  Its payload excludes token plaintext and raw
/// text.  The writer's durable acknowledgement is converted to
/// [`DurableCeremonyAudit`] by the ingress-owned adapter.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct CeremonyAuditPayload {
    schema_version: u8,
    operation_id: String,
    action: String,
    channel_id: String,
    account_id: String,
    scoped_sender_hash: String,
    evidence_sha256: String,
    input_receipt_event_id: i64,
    input_sha256: String,
    baseline_consent_state: String,
    baseline_consent_revision: i64,
}

impl CeremonyAuditPayload {
    /// Closed writer entrypoints receive this non-forgeable plan and serialize
    /// it verbatim.  It is not an argv/GUI/adapter payload type.
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("serialize W209 closed audit payload")
    }
}

impl AuditReservation {
    pub(crate) fn audit_payload(&self, proof: &AuthenticatedInboundProof) -> CeremonyAuditPayload {
        CeremonyAuditPayload {
            schema_version: 1,
            operation_id: self.operation_id.clone(),
            action: match self.kind {
                ReservationKind::Grant => "verified_grant",
                ReservationKind::Revoke => "counterparty_revoke",
            }
            .to_owned(),
            channel_id: self.key.channel_id().to_owned(),
            account_id: self.key.account_id().to_owned(),
            scoped_sender_hash: self.key.scoped_sender_hash().to_owned(),
            evidence_sha256: hex::encode(self.evidence_sha256),
            input_receipt_event_id: proof.input_receipt_event_id,
            input_sha256: hex::encode(proof.input_sha256),
            baseline_consent_state: self.baseline.state.to_owned(),
            baseline_consent_revision: self.baseline.revision,
        }
    }
}

fn audit_payload_sha256(payload: &CeremonyAuditPayload) -> Result<[u8; SHA256_LEN]> {
    let bytes = payload.canonical_bytes()?;
    Ok(sha256_tagged(AUDIT_DOMAIN, &[&bytes]))
}

fn baseline_from_status(value: ConsentStatus) -> ConsentBaseline {
    match value {
        ConsentStatus::Absent => ConsentBaseline {
            state: "absent",
            revision: 0,
        },
        ConsentStatus::VerifiedGranted { revision, .. } => ConsentBaseline {
            state: "verified_granted",
            revision,
        },
        ConsentStatus::Revoked { revision, .. } => ConsentBaseline {
            state: "revoked",
            revision,
        },
    }
}

fn decode_baseline(state: &str, revision: i64) -> Result<ConsentBaseline> {
    match state {
        "absent" if revision == 0 => Ok(ConsentBaseline {
            state: "absent",
            revision: 0,
        }),
        "verified_granted" if revision > 0 => Ok(ConsentBaseline {
            state: "verified_granted",
            revision,
        }),
        "revoked" if revision > 0 => Ok(ConsentBaseline {
            state: "revoked",
            revision,
        }),
        _ => bail!("W209 persisted consent baseline is malformed"),
    }
}

fn make_reservation(
    operation_id: String,
    kind: ReservationKind,
    proof: &AuthenticatedInboundProof,
    baseline: ConsentBaseline,
) -> Result<AuditReservation> {
    let mut reservation = AuditReservation {
        operation_id,
        kind,
        key: proof.key.clone(),
        evidence_sha256: proof.evidence_sha256(),
        input_receipt_event_id: proof.input_receipt_event_id,
        input_sha256: proof.input_sha256,
        payload_sha256: [0; SHA256_LEN],
        baseline,
    };
    reservation.payload_sha256 = audit_payload_sha256(&reservation.audit_payload(proof))?;
    Ok(reservation)
}

/// Created by the ingress immediately after its closed writer reports a
/// durable ceremony audit frame.  It is crate-private so local controls cannot
/// claim an arbitrary audit event id as a counterparty proof.
#[derive(Clone, Debug)]
pub(crate) struct DurableCeremonyAudit {
    operation_id: String,
    audit_event_id: i64,
    payload_sha256: [u8; SHA256_LEN],
}

impl DurableCeremonyAudit {
    pub(crate) fn from_writer_issued_receipt(
        reservation: &AuditReservation,
        proof: &AuthenticatedInboundProof,
        receipt: crate::wal::writer::CounterpartyConsentAuditReceipt,
    ) -> Result<Self> {
        ensure!(
            receipt.operation_id() == reservation.operation_id
                && receipt.action()
                    == match reservation.kind {
                        ReservationKind::Grant => "verified_grant",
                        ReservationKind::Revoke => "counterparty_revoke",
                    }
                && receipt.event_id() > 0
                && receipt.payload_sha256() == reservation.payload_sha256
                && reservation.input_receipt_event_id == proof.input_receipt_event_id
                && reservation.input_sha256 == proof.input_sha256,
            "W209 writer receipt does not bind the exact ceremony reservation"
        );
        Ok(Self {
            operation_id: reservation.operation_id.clone(),
            audit_event_id: receipt.event_id(),
            payload_sha256: receipt.payload_sha256(),
        })
    }
}

/// A content-free locator returned to the recovery worker.  The worker scans
/// only the corresponding closed input receipt from WAL and passes that sealed
/// receipt to [`rehydrate_pending_audit`]; neither token nor command plaintext
/// is persisted in this table or exposed by this type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PendingAuditLocator {
    input_receipt_event_id: i64,
    input_sha256: [u8; SHA256_LEN],
    action: &'static str,
}

impl PendingAuditLocator {
    pub(crate) fn input_receipt_event_id(&self) -> i64 {
        self.input_receipt_event_id
    }

    pub(crate) fn input_sha256(&self) -> [u8; SHA256_LEN] {
        self.input_sha256
    }

    #[cfg(test)]
    pub(crate) fn action(&self) -> &'static str {
        self.action
    }
}

/// Rehydrated exact reservation.  It is produced exclusively after matching a
/// sealed writer-issued input receipt to the persisted scope/evidence/payload
/// fence.  Callers can obtain the closed audit plan and later complete it with
/// a sealed writer-issued audit receipt; they cannot forge either capability.
#[derive(Clone, Debug)]
pub(crate) struct PendingAuditRecovery {
    proof: AuthenticatedInboundProof,
    reservation: AuditReservation,
}

impl PendingAuditRecovery {
    pub(crate) fn audit_payload(&self) -> CeremonyAuditPayload {
        self.reservation.audit_payload(&self.proof)
    }

    pub(crate) fn complete_after_writer_ack(
        &self,
        conn: &mut Connection,
        receipt: crate::wal::writer::CounterpartyConsentAuditReceipt,
        now_ns: i64,
    ) -> Result<()> {
        let audit = DurableCeremonyAudit::from_writer_issued_receipt(
            &self.reservation,
            &self.proof,
            receipt,
        )?;
        match self.reservation.kind {
            ReservationKind::Grant => {
                commit_verified_grant_after_audit(
                    conn,
                    &self.proof,
                    &self.reservation,
                    &audit,
                    now_ns,
                )?;
                Ok(())
            }
            ReservationKind::Revoke => {
                acknowledge_revocation_audit(conn, &self.proof, &self.reservation, &audit)
            }
        }
    }
}

/// Enumerate exact durable-audit work left by a crash or an ambiguous writer
/// acknowledgement.  The caller must treat each locator as a WAL lookup key,
/// never as authority on its own.
pub(crate) fn pending_audit_locators(conn: &Connection) -> Result<Vec<PendingAuditLocator>> {
    let mut statement = conn.prepare(
        "SELECT reservation_input_receipt_event_id,reservation_input_sha256,state \
         FROM idx_counterparty_consent_challenge_v1 \
         WHERE state IN ('grant_audit_pending','revoke_audit_pending') \
         ORDER BY reservation_input_receipt_event_id",
    )?;
    statement
        .query_map([], |row| {
            let input_receipt_event_id: i64 = row.get(0)?;
            let input_sha256: Vec<u8> = row.get(1)?;
            let state: String = row.get(2)?;
            let input_sha256 = as_sha256(&input_sha256)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?;
            let action = match state.as_str() {
                "grant_audit_pending" => "verified_grant",
                "revoke_audit_pending" => "counterparty_revoke",
                _ => unreachable!("query restricts pending audit states"),
            };
            Ok(PendingAuditLocator {
                input_receipt_event_id,
                input_sha256,
                action,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("W209 enumerate pending durable-audit recovery")
}

/// Rebuild the exact pending reservation after the recovery worker has loaded
/// a matching writer-issued input receipt from WAL.  This cannot reconstruct a
/// grant from a token because no token is stored; it merely completes an
/// already-reserved operation whose full evidence/payload fence is durable.
pub(crate) fn rehydrate_pending_audit(
    conn: &Connection,
    receipt: &crate::wal::writer::CounterpartyConsentInputReceipt,
) -> Result<Option<PendingAuditRecovery>> {
    let proof = AuthenticatedInboundProof::from_writer_issued_receipt(receipt)?;
    let row: Option<PendingAuditRow> = conn
        .query_row(
            "SELECT state,operation_id,reservation_evidence_sha256,reservation_input_receipt_event_id, \
                    reservation_input_sha256,reservation_payload_sha256,baseline_consent_state,baseline_consent_revision \
             FROM idx_counterparty_consent_challenge_v1 \
             WHERE channel_id=?1 AND account_id=?2 AND scoped_sender_hash=?3 \
               AND state IN ('grant_audit_pending','revoke_audit_pending') \
               AND reservation_input_receipt_event_id=?4 AND reservation_input_sha256=?5",
            params![proof.key.channel_id(), proof.key.account_id(), proof.key.scoped_sender_hash(),
                    proof.input_receipt_event_id, proof.input_sha256.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?)),
        )
        .optional()?;
    let Some((
        state,
        operation_id,
        evidence,
        input_receipt_event_id,
        input_sha256,
        payload_sha256,
        baseline_state,
        baseline_revision,
    )) = row
    else {
        return Ok(None);
    };
    validate_operation_id(&operation_id)?;
    let kind = match state.as_str() {
        "grant_audit_pending" => ReservationKind::Grant,
        "revoke_audit_pending" => ReservationKind::Revoke,
        _ => bail!("W209 persisted recovery state is not pending audit"),
    };
    let baseline = decode_baseline(&baseline_state, baseline_revision)?;
    let reservation = AuditReservation {
        operation_id,
        kind,
        key: proof.key.clone(),
        evidence_sha256: as_sha256(&evidence)?,
        input_receipt_event_id,
        input_sha256: as_sha256(&input_sha256)?,
        payload_sha256: as_sha256(&payload_sha256)?,
        baseline,
    };
    ensure!(
        reservation.evidence_sha256 == proof.evidence_sha256()
            && reservation.input_receipt_event_id == proof.input_receipt_event_id
            && reservation.input_sha256 == proof.input_sha256,
        "W209 pending recovery evidence does not match its sealed input receipt"
    );
    ensure!(
        reservation.payload_sha256 == audit_payload_sha256(&reservation.audit_payload(&proof))?,
        "W209 pending recovery payload binding is inconsistent"
    );
    Ok(Some(PendingAuditRecovery { proof, reservation }))
}

fn as_sha256(value: &[u8]) -> Result<[u8; SHA256_LEN]> {
    ensure!(
        value.len() == SHA256_LEN,
        "W209 stored SHA-256 has invalid length"
    );
    let mut result = [0; SHA256_LEN];
    result.copy_from_slice(value);
    Ok(result)
}

/// Generate and persist one short-lived challenge.  A fresh request replaces
/// an expired, consumed, or cancelled request for this exact sender only.  An
/// active reservation cannot be replaced, so an audit in flight cannot lose
/// its replay fence.
pub(crate) fn request_challenge(
    conn: &mut Connection,
    proof: &AuthenticatedInboundProof,
    now_ns: i64,
) -> Result<ChallengeReply> {
    ensure_exact_command_proof(proof, COMMAND_REQUEST)?;
    let expires_at_ns = now_ns
        .checked_add(CHALLENGE_TTL_NS)
        .ok_or_else(|| anyhow!("W209 challenge expiry overflow"))?;
    let token = random_hex(TOKEN_BYTES)?;
    let token_sha256 = token_commitment(proof, &token);
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let issued_baseline = baseline_from_status(status(&tx, &proof.key)?);
    let prior: Option<String> = tx
        .query_row(
            "SELECT state,expires_at_ns FROM idx_counterparty_consent_challenge_v1 \
             WHERE channel_id=?1 AND account_id=?2 AND scoped_sender_hash=?3",
            params![
                proof.key.channel_id(),
                proof.key.account_id(),
                proof.key.scoped_sender_hash()
            ],
            |row| row.get(0),
        )
        .optional()
        .context("W209 load prior challenge")?;
    if let Some(state) = prior {
        ensure!(
            !matches!(
                state.as_str(),
                "grant_audit_pending" | "revoke_audit_pending"
            ),
            "W209 consent ceremony already has a durable-audit reservation"
        );
    }
    tx.execute(
        "INSERT INTO idx_counterparty_consent_challenge_v1 \
         (channel_id,account_id,scoped_sender_hash,conversation_sha256,token_sha256,issued_input_receipt_event_id,issued_consent_state,issued_consent_revision,expires_at_ns,state,operation_id,audit_event_id,reservation_evidence_sha256,reservation_input_receipt_event_id,reservation_input_sha256,reservation_payload_sha256,baseline_consent_state,baseline_consent_revision) \
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,'pending',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL) \
         ON CONFLICT(channel_id,account_id,scoped_sender_hash) DO UPDATE SET \
            conversation_sha256=excluded.conversation_sha256,token_sha256=excluded.token_sha256, \
            issued_input_receipt_event_id=excluded.issued_input_receipt_event_id, \
            issued_consent_state=excluded.issued_consent_state,issued_consent_revision=excluded.issued_consent_revision, \
            expires_at_ns=excluded.expires_at_ns,state='pending',operation_id=NULL,audit_event_id=NULL, \
            reservation_evidence_sha256=NULL,reservation_input_receipt_event_id=NULL,reservation_input_sha256=NULL, \
            reservation_payload_sha256=NULL,baseline_consent_state=NULL,baseline_consent_revision=NULL",
        params![
            proof.key.channel_id(), proof.key.account_id(), proof.key.scoped_sender_hash(),
            proof.conversation_sha256.as_slice(), token_sha256.as_slice(), proof.input_receipt_event_id,
            issued_baseline.state, issued_baseline.revision, expires_at_ns,
        ],
    )?;
    tx.commit()?;
    Ok(ChallengeReply {
        command: format!("{COMMAND_GRANT_PREFIX}{token}"),
        expires_at_ns,
    })
}

/// Reserve an exact authenticated echo for a later durable audit append.
/// This function mutates only the pending replay fence; it cannot make any
/// episode eligible.  On WAL failure the integration must call
/// [`cancel_reservation`] and return an unavailable/failed reply.
pub(crate) fn reserve_verified_grant(
    conn: &mut Connection,
    proof: &AuthenticatedInboundProof,
    token: &str,
    now_ns: i64,
) -> Result<AuditReservation> {
    validate_token(token)?;
    ensure_exact_command_proof(proof, &format!("{COMMAND_GRANT_PREFIX}{token}"))?;
    reserve(conn, proof, Some(token), ReservationKind::Grant, now_ns)
}

/// Fail-closed authenticated counterparty revoke.  It first commits the exact
/// W208 denial and quarantine with a `revoke_audit_pending` replay record,
/// then returns the audit reservation.  WAL append failure must leave that
/// pending record and the denial intact; it never restores positive consent.
pub(crate) fn commit_counterparty_revoke_before_audit(
    conn: &mut Connection,
    proof: &AuthenticatedInboundProof,
    now_ns: i64,
) -> Result<(AuditReservation, RevocationResult)> {
    ensure_exact_command_proof(proof, COMMAND_REVOKE)?;
    let operation_id = random_hex(OPERATION_BYTES)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let prior: Option<String> = tx
        .query_row(
            "SELECT state FROM idx_counterparty_consent_challenge_v1 \
             WHERE channel_id=?1 AND account_id=?2 AND scoped_sender_hash=?3",
            params![
                proof.key.channel_id(),
                proof.key.account_id(),
                proof.key.scoped_sender_hash()
            ],
            |row| row.get(0),
        )
        .optional()?;
    ensure!(
        !matches!(prior.as_deref(), Some("revoke_audit_pending")),
        "W209 consent ceremony already has a nonreplaceable durable-audit reservation"
    );
    let baseline = baseline_from_status(status(&tx, &proof.key)?);
    let reservation = make_reservation(operation_id, ReservationKind::Revoke, proof, baseline)?;
    // A revoke wins over a pending grant immediately.  Retain the exact grant
    // reservation in a terminal custody record before replacing the challenge
    // row, so audit/readback can explain the fenced operation without ever
    // retrying it into a positive state.
    tx.execute(
        "INSERT INTO idx_counterparty_consent_audit_terminal_v1 \
         (operation_id,channel_id,account_id,scoped_sender_hash,action,evidence_sha256,input_receipt_event_id,input_sha256,payload_sha256,baseline_consent_state,baseline_consent_revision,terminal_state,terminal_by_operation_id) \
         SELECT operation_id,channel_id,account_id,scoped_sender_hash,'verified_grant',reservation_evidence_sha256,reservation_input_receipt_event_id,reservation_input_sha256,reservation_payload_sha256,baseline_consent_state,baseline_consent_revision,'superseded_by_revoke',?1 \
         FROM idx_counterparty_consent_challenge_v1 \
         WHERE channel_id=?2 AND account_id=?3 AND scoped_sender_hash=?4 AND state='grant_audit_pending' \
         ON CONFLICT(operation_id) DO NOTHING",
        params![reservation.operation_id, proof.key.channel_id(), proof.key.account_id(), proof.key.scoped_sender_hash()],
    )?;
    // A revoke fences every outstanding grant challenge for this exact sender.
    // Its operation id stays durable until a matching audit acknowledgement.
    tx.execute(
        "INSERT INTO idx_counterparty_consent_challenge_v1 \
         (channel_id,account_id,scoped_sender_hash,conversation_sha256,token_sha256,issued_input_receipt_event_id,issued_consent_state,issued_consent_revision,expires_at_ns,state,operation_id,audit_event_id,reservation_evidence_sha256,reservation_input_receipt_event_id,reservation_input_sha256,reservation_payload_sha256,baseline_consent_state,baseline_consent_revision) \
         VALUES(?1,?2,?3,?4,zeroblob(32),?5,?6,?7,?8,'revoke_audit_pending',?9,NULL,?10,?11,?12,?13,?14,?15) \
         ON CONFLICT(channel_id,account_id,scoped_sender_hash) DO UPDATE SET \
            conversation_sha256=excluded.conversation_sha256,issued_input_receipt_event_id=excluded.issued_input_receipt_event_id, \
            issued_consent_state=excluded.issued_consent_state,issued_consent_revision=excluded.issued_consent_revision, \
            expires_at_ns=excluded.expires_at_ns, \
            state='revoke_audit_pending',operation_id=excluded.operation_id,audit_event_id=NULL, \
            reservation_evidence_sha256=excluded.reservation_evidence_sha256, \
            reservation_input_receipt_event_id=excluded.reservation_input_receipt_event_id, \
            reservation_input_sha256=excluded.reservation_input_sha256, \
            reservation_payload_sha256=excluded.reservation_payload_sha256, \
            baseline_consent_state=excluded.baseline_consent_state,baseline_consent_revision=excluded.baseline_consent_revision",
        params![proof.key.channel_id(), proof.key.account_id(), proof.key.scoped_sender_hash(),
                proof.conversation_sha256.as_slice(), proof.input_receipt_event_id,
                reservation.baseline.state, reservation.baseline.revision, now_ns, reservation.operation_id, reservation.evidence_sha256.as_slice(),
                reservation.input_receipt_event_id, reservation.input_sha256.as_slice(),
                reservation.payload_sha256.as_slice(), reservation.baseline.state, reservation.baseline.revision],
    )?;
    let result = revoke_and_quarantine(&tx, &proof.key, now_ns)?;
    tx.commit()?;
    Ok((reservation, result))
}

fn reserve(
    conn: &mut Connection,
    proof: &AuthenticatedInboundProof,
    token: Option<&str>,
    kind: ReservationKind,
    now_ns: i64,
) -> Result<AuditReservation> {
    let operation_id = random_hex(OPERATION_BYTES)?;
    let state = match kind {
        ReservationKind::Grant => "grant_audit_pending",
        ReservationKind::Revoke => unreachable!("revoke commits fail-closed before audit"),
    };
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    match kind {
        ReservationKind::Grant => {
            let token = token.expect("grant always carries a validated token");
            let expected = token_commitment(proof, token);
            let issued: Option<(String, i64)> = tx.query_row(
                "SELECT issued_consent_state,issued_consent_revision \
                 FROM idx_counterparty_consent_challenge_v1 \
                 WHERE channel_id=?1 AND account_id=?2 AND scoped_sender_hash=?3 \
                   AND conversation_sha256=?4 AND token_sha256=?5 AND state='pending' AND expires_at_ns>=?6",
                params![proof.key.channel_id(), proof.key.account_id(), proof.key.scoped_sender_hash(),
                        proof.conversation_sha256.as_slice(), expected.as_slice(), now_ns],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).optional()?;
            let (issued_state, issued_revision) = issued.ok_or_else(|| {
                anyhow!("W209 grant echo is absent, expired, wrong-scope, or already consumed")
            })?;
            let issued_baseline = decode_baseline(&issued_state, issued_revision)?;
            ensure!(
                baseline_from_status(status(&tx, &proof.key)?) == issued_baseline,
                "W209 challenge baseline changed; pre-revoke token is stale"
            );
            let reservation =
                make_reservation(operation_id, ReservationKind::Grant, proof, issued_baseline)?;
            let changed = tx.execute(
                "UPDATE idx_counterparty_consent_challenge_v1 \
                 SET state=?1,operation_id=?2,reservation_evidence_sha256=?3,reservation_input_receipt_event_id=?4, \
                     reservation_input_sha256=?5,reservation_payload_sha256=?6,baseline_consent_state=?7,baseline_consent_revision=?8 \
                 WHERE channel_id=?9 AND account_id=?10 AND scoped_sender_hash=?11 \
                   AND conversation_sha256=?12 AND token_sha256=?13 AND state='pending' AND expires_at_ns>=?14 \
                   AND issued_consent_state=?15 AND issued_consent_revision=?16",
                params![state, reservation.operation_id, reservation.evidence_sha256.as_slice(),
                        reservation.input_receipt_event_id, reservation.input_sha256.as_slice(),
                        reservation.payload_sha256.as_slice(), reservation.baseline.state, reservation.baseline.revision,
                        proof.key.channel_id(), proof.key.account_id(),
                        proof.key.scoped_sender_hash(), proof.conversation_sha256.as_slice(),
                        expected.as_slice(), now_ns, issued_baseline.state, issued_baseline.revision],
            )?;
            ensure!(
                changed == 1,
                "W209 grant echo is absent, expired, wrong-scope, or already consumed"
            );
            tx.commit()?;
            Ok(reservation)
        }
        ReservationKind::Revoke => unreachable!("revoke commits fail-closed before audit"),
    }
}

/// Commit the already audited, exact grant.  This is intentionally synchronous
/// and starts a new immediate transaction after WAL acknowledgement.  Its
/// state predicate prevents a replay, another sender, a revoke reservation,
/// or a stale audit from turning a row positive.
pub(crate) fn commit_verified_grant_after_audit(
    conn: &mut Connection,
    proof: &AuthenticatedInboundProof,
    reservation: &AuditReservation,
    audit: &DurableCeremonyAudit,
    now_ns: i64,
) -> Result<ConsentStatus> {
    ensure!(
        reservation.kind == ReservationKind::Grant,
        "W209 reservation is not a grant"
    );
    verify_audit_binding(reservation, audit)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = baseline_from_status(status(&tx, &proof.key)?);
    ensure!(
        current == reservation.baseline,
        "W209 grant baseline changed; a stale pre-revoke proof cannot resurrect consent"
    );
    let changed = tx.execute(
        "UPDATE idx_counterparty_consent_challenge_v1 SET state='consumed',audit_event_id=?1 \
         WHERE channel_id=?2 AND account_id=?3 AND scoped_sender_hash=?4 AND state='grant_audit_pending' AND operation_id=?5 \
           AND conversation_sha256=?6 AND reservation_evidence_sha256=?7 AND reservation_input_receipt_event_id=?8 \
           AND reservation_input_sha256=?9 AND reservation_payload_sha256=?10 \
           AND baseline_consent_state=?11 AND baseline_consent_revision=?12",
        params![audit.audit_event_id, proof.key.channel_id(), proof.key.account_id(),
                proof.key.scoped_sender_hash(), reservation.operation_id,
                proof.conversation_sha256.as_slice(), reservation.evidence_sha256.as_slice(),
                reservation.input_receipt_event_id, reservation.input_sha256.as_slice(),
                reservation.payload_sha256.as_slice(), reservation.baseline.state, reservation.baseline.revision],
    )?;
    ensure!(
        changed == 1,
        "W209 grant reservation was superseded or already consumed"
    );
    let revision = reservation
        .baseline
        .revision
        .checked_add(1)
        .ok_or_else(|| anyhow!("W209 consent revision overflow"))?;
    let proof_sha256 = grant_proof_sha256(proof, reservation, audit);
    tx.execute(
        "INSERT INTO idx_counterparty_clustering_consent_v1 \
         (channel_id,account_id,scoped_sender_hash,state,proof_kind,proof_sha256,proof_verified_at_ns,revision,revoked_at_ns) \
         VALUES(?1,?2,?3,'verified_granted',?4,?5,?6,?7,NULL) \
         ON CONFLICT(channel_id,account_id,scoped_sender_hash) DO UPDATE SET \
            state='verified_granted',proof_kind=excluded.proof_kind,proof_sha256=excluded.proof_sha256, \
            proof_verified_at_ns=excluded.proof_verified_at_ns,revision=excluded.revision,revoked_at_ns=NULL",
        params![proof.key.channel_id(), proof.key.account_id(), proof.key.scoped_sender_hash(),
                GRANT_PROOF_KIND, proof_sha256.as_slice(), now_ns, revision],
    )?;
    tx.commit()?;
    Ok(ConsentStatus::VerifiedGranted {
        revision,
        verified_at_ns: now_ns,
    })
}

/// Acknowledge a durable audit for a revoke that was already committed
/// fail-closed.  This changes only audit bookkeeping; denial and quarantine
/// remain in force when the WAL append failed, was interrupted, or is unknown.
pub(crate) fn acknowledge_revocation_audit(
    conn: &mut Connection,
    proof: &AuthenticatedInboundProof,
    reservation: &AuditReservation,
    audit: &DurableCeremonyAudit,
) -> Result<()> {
    ensure!(
        reservation.kind == ReservationKind::Revoke,
        "W209 reservation is not a revoke"
    );
    verify_audit_binding(reservation, audit)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let changed = tx.execute(
        "UPDATE idx_counterparty_consent_challenge_v1 SET state='revoked_audited',audit_event_id=?1 \
         WHERE channel_id=?2 AND account_id=?3 AND scoped_sender_hash=?4 AND state='revoke_audit_pending' AND operation_id=?5 \
           AND conversation_sha256=?6 AND reservation_evidence_sha256=?7 AND reservation_input_receipt_event_id=?8 \
           AND reservation_input_sha256=?9 AND reservation_payload_sha256=?10 \
           AND baseline_consent_state=?11 AND baseline_consent_revision=?12",
        params![audit.audit_event_id, proof.key.channel_id(), proof.key.account_id(),
                proof.key.scoped_sender_hash(), reservation.operation_id,
                proof.conversation_sha256.as_slice(), reservation.evidence_sha256.as_slice(),
                reservation.input_receipt_event_id, reservation.input_sha256.as_slice(),
                reservation.payload_sha256.as_slice(), reservation.baseline.state, reservation.baseline.revision],
    )?;
    ensure!(
        changed == 1,
        "W209 revoke audit acknowledgement was superseded or already recorded"
    );
    tx.commit()?;
    Ok(())
}

/// WAL append failure is non-authoritative for grants only.  A revoke has
/// already committed its denial and must retain its replay-repair record;
/// cancelling it would silently resurrect an unaudited positive state.
pub(crate) fn cancel_reservation(
    conn: &mut Connection,
    reservation: &AuditReservation,
) -> Result<()> {
    let restored = match reservation.kind {
        ReservationKind::Grant => "pending",
        ReservationKind::Revoke => return Ok(()),
    };
    conn.execute(
        "UPDATE idx_counterparty_consent_challenge_v1 SET state=?1,operation_id=NULL \
         WHERE channel_id=?2 AND account_id=?3 AND scoped_sender_hash=?4 AND operation_id=?5 \
           AND state='grant_audit_pending'",
        params![
            restored,
            reservation.key.channel_id(),
            reservation.key.account_id(),
            reservation.key.scoped_sender_hash(),
            reservation.operation_id
        ],
    )?;
    Ok(())
}

fn verify_audit_binding(
    reservation: &AuditReservation,
    audit: &DurableCeremonyAudit,
) -> Result<()> {
    ensure!(
        audit.operation_id == reservation.operation_id,
        "W209 audit belongs to another ceremony"
    );
    ensure!(
        audit.audit_event_id > 0,
        "W209 audit receipt is not durable"
    );
    ensure!(
        audit.payload_sha256 == reservation.payload_sha256,
        "W209 audit payload digest is not the reserved exact payload"
    );
    Ok(())
}

fn token_commitment(proof: &AuthenticatedInboundProof, token: &str) -> [u8; SHA256_LEN] {
    sha256_tagged(
        CHALLENGE_DOMAIN,
        &[
            proof.key.channel_id().as_bytes(),
            proof.key.account_id().as_bytes(),
            proof.key.scoped_sender_hash().as_bytes(),
            &proof.conversation_sha256,
            token.as_bytes(),
        ],
    )
}

/// The writer-issued input receipt commits SHA-256 over the exact UTF-8 bytes
/// of the already strict parsed command. Recompute the same digest before each
/// mutation so a request, revoke, malformed text, or different token receipt
/// cannot be substituted for the command currently being processed.
fn ensure_exact_command_proof(proof: &AuthenticatedInboundProof, command: &str) -> Result<()> {
    let expected: [u8; SHA256_LEN] = Sha256::digest(command.as_bytes()).into();
    ensure!(
        proof.input_sha256 == expected,
        "W209 sealed input receipt does not match the exact ceremony command"
    );
    Ok(())
}

fn grant_proof_sha256(
    proof: &AuthenticatedInboundProof,
    reservation: &AuditReservation,
    audit: &DurableCeremonyAudit,
) -> [u8; SHA256_LEN] {
    sha256_tagged(
        b"neoth/w209/counterparty-consent/grant-proof/v1\0",
        &[
            &proof.evidence_sha256(),
            reservation.operation_id.as_bytes(),
            &audit.audit_event_id.to_be_bytes(),
            &audit.payload_sha256,
        ],
    )
}

fn sha256_tagged(domain: &[u8], fields: &[&[u8]]) -> [u8; SHA256_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

fn random_hex(bytes: usize) -> Result<String> {
    let mut value = vec![0_u8; bytes];
    getrandom::getrandom(&mut value).context("W209 OS CSPRNG")?;
    Ok(hex::encode(value))
}

fn validate_token(token: &str) -> Result<()> {
    ensure!(
        token.len() == TOKEN_HEX_LEN
            && token
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "W209 consent token is malformed"
    );
    Ok(())
}

#[allow(dead_code)]
fn validate_operation_id(operation_id: &str) -> Result<()> {
    ensure!(
        operation_id.len() == OPERATION_HEX_LEN
            && operation_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "W209 ceremony operation id is malformed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(CHALLENGE_SCHEMA_SQL).unwrap();
        conn.execute_batch(
            "CREATE TABLE idx_counterparty_clustering_consent_v1(\
                channel_id TEXT NOT NULL,account_id TEXT NOT NULL,scoped_sender_hash TEXT NOT NULL,\
                state TEXT NOT NULL,proof_kind TEXT NOT NULL,proof_sha256 BLOB NOT NULL,\
                proof_verified_at_ns INTEGER NOT NULL,revision INTEGER NOT NULL,revoked_at_ns INTEGER,\
                PRIMARY KEY(channel_id,account_id,scoped_sender_hash));\
             CREATE TABLE idx_episode_origin_v2(raw_event_id INTEGER,origin_kind TEXT,channel_id TEXT,account_id TEXT,scoped_sender_hash TEXT);\
             CREATE TABLE idx_embedding(source_kind TEXT,source_ref TEXT);\
             CREATE TABLE idx_groundtruth(id INTEGER PRIMARY KEY,evidence TEXT,source TEXT,scope TEXT,revoked_at INTEGER);",
        ).unwrap();
        conn
    }

    fn proof(
        sender: &str,
        receipt_id: i64,
        marker: u8,
        command: &str,
    ) -> AuthenticatedInboundProof {
        AuthenticatedInboundProof {
            key: CounterpartyKey::from_authenticated(
                &crate::channels::registry::ChannelRef::default_account(
                    crate::channels::registry::ChannelId::Telegram,
                ),
                sender,
            )
            .unwrap(),
            conversation_sha256: [marker; SHA256_LEN],
            input_receipt_event_id: receipt_id,
            wal_session_id: [marker; 16],
            input_sha256: Sha256::digest(command.as_bytes()).into(),
        }
    }

    fn echoed_token(reply: &ChallengeReply) -> String {
        reply
            .command
            .strip_prefix(COMMAND_GRANT_PREFIX)
            .unwrap()
            .to_owned()
    }

    fn audit_for(reservation: &AuditReservation) -> DurableCeremonyAudit {
        DurableCeremonyAudit {
            operation_id: reservation.operation_id.clone(),
            audit_event_id: 9_000 + reservation.baseline.revision,
            payload_sha256: reservation.payload_sha256,
        }
    }

    #[test]
    fn parser_accepts_only_whole_ascii_ceremony_commands() {
        let token = "a".repeat(TOKEN_HEX_LEN);
        assert_eq!(
            parse_command(COMMAND_REQUEST),
            CeremonyCommandParse::Command(CounterpartyConsentCommand::Request)
        );
        assert_eq!(
            parse_command(COMMAND_REVOKE),
            CeremonyCommandParse::Command(CounterpartyConsentCommand::Revoke)
        );
        assert_eq!(
            parse_command(&format!("{COMMAND_GRANT_PREFIX}{token}")),
            CeremonyCommandParse::Command(CounterpartyConsentCommand::Grant { token })
        );
        for invalid in [
            "/neoth consent clustering request ",
            "/neoth consent clustering grant abc",
            "/neoth consent clustering grant AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "/neoth consent clustering revoke\nignored",
        ] {
            assert_eq!(
                parse_command(invalid),
                CeremonyCommandParse::MalformedReserved,
                "unexpected command: {invalid:?}"
            );
        }
        assert_eq!(
            parse_command("please /neoth consent clustering request"),
            CeremonyCommandParse::MalformedReserved
        );
        assert_eq!(
            parse_command(" /neoth consent clustering request"),
            CeremonyCommandParse::MalformedReserved
        );
    }

    #[test]
    fn token_and_operation_ids_are_lowercase_fixed_width_hex() {
        assert!(validate_token(&"0".repeat(TOKEN_HEX_LEN)).is_ok());
        assert!(validate_token(&"f".repeat(TOKEN_HEX_LEN)).is_ok());
        assert!(validate_token(&"F".repeat(TOKEN_HEX_LEN)).is_err());
        assert!(validate_token(&"0".repeat(TOKEN_HEX_LEN - 1)).is_err());
        assert!(validate_operation_id(&"a".repeat(OPERATION_HEX_LEN)).is_ok());
    }

    #[test]
    fn pending_audit_enumeration_is_content_free_and_ignores_terminal_rows() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(CHALLENGE_SCHEMA_SQL).unwrap();
        for (sender, state, receipt_id) in [
            ("0123456789abcdef", "grant_audit_pending", 71_i64),
            ("fedcba9876543210", "revoke_audit_pending", 72_i64),
            ("0011223344556677", "revoked_audited", 73_i64),
        ] {
            conn.execute(
                "INSERT INTO idx_counterparty_consent_challenge_v1 \
                 (channel_id,account_id,scoped_sender_hash,conversation_sha256,token_sha256,issued_input_receipt_event_id,issued_consent_state,issued_consent_revision,expires_at_ns,state,operation_id,audit_event_id,reservation_evidence_sha256,reservation_input_receipt_event_id,reservation_input_sha256,reservation_payload_sha256,baseline_consent_state,baseline_consent_revision) \
                 VALUES('telegram','default',?1,zeroblob(32),zeroblob(32),?2,'revoked',42,0,?3,?4,NULL,zeroblob(32),?2,zeroblob(32),zeroblob(32),'revoked',42)",
                params![sender, receipt_id, state, "a".repeat(OPERATION_HEX_LEN)],
            )
            .unwrap();
        }
        let locators = pending_audit_locators(&conn).unwrap();
        assert_eq!(locators.len(), 2);
        assert_eq!(locators[0].input_receipt_event_id(), 71);
        assert_eq!(locators[0].action(), "verified_grant");
        assert_eq!(locators[1].input_receipt_event_id(), 72);
        assert_eq!(locators[1].action(), "counterparty_revoke");
        assert!(
            locators
                .iter()
                .all(|locator| locator.input_sha256() == [0; SHA256_LEN])
        );
    }

    #[test]
    fn expired_pending_audit_is_still_nonreplaceable() {
        let mut conn = core_conn();
        let request = proof("0123456789abcdef", 61, 41, COMMAND_REQUEST);
        let reply = request_challenge(&mut conn, &request, 100).unwrap();
        let grant = proof("0123456789abcdef", 62, 41, &reply.command);
        let reservation =
            reserve_verified_grant(&mut conn, &grant, &echoed_token(&reply), 101).unwrap();
        let before: (String, i64, Vec<u8>) = conn.query_row(
            "SELECT state,reservation_input_receipt_event_id,reservation_payload_sha256 \
             FROM idx_counterparty_consent_challenge_v1 WHERE scoped_sender_hash='0123456789abcdef'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).unwrap();
        let later_request = proof("0123456789abcdef", 63, 41, COMMAND_REQUEST);
        assert!(
            request_challenge(&mut conn, &later_request, 100 + CHALLENGE_TTL_NS + 1).is_err(),
            "a pending durable-audit reservation must block a later request after TTL"
        );
        let after: (String, i64, Vec<u8>) = conn.query_row(
            "SELECT state,reservation_input_receipt_event_id,reservation_payload_sha256 \
             FROM idx_counterparty_consent_challenge_v1 WHERE scoped_sender_hash='0123456789abcdef'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).unwrap();
        assert_eq!(
            before, after,
            "later request must preserve the exact pending audit custody"
        );
        assert_eq!(after.0, "grant_audit_pending");
        assert_eq!(after.1, reservation.input_receipt_event_id);
    }

    #[test]
    fn old_challenge_echo_cannot_adopt_a_post_revoke_baseline_but_fresh_echo_can() {
        let mut conn = core_conn();
        let first_request = proof("0123456789abcdef", 11, 1, COMMAND_REQUEST);
        let first_reply = request_challenge(&mut conn, &first_request, 10).unwrap();
        let first_grant = proof("0123456789abcdef", 12, 1, &first_reply.command);
        let first_reservation =
            reserve_verified_grant(&mut conn, &first_grant, &echoed_token(&first_reply), 11)
                .unwrap();
        let first_audit = audit_for(&first_reservation);
        assert!(matches!(
            commit_verified_grant_after_audit(
                &mut conn,
                &first_grant,
                &first_reservation,
                &first_audit,
                12
            )
            .unwrap(),
            ConsentStatus::VerifiedGranted { revision: 1, .. }
        ));

        let stale_request = proof("0123456789abcdef", 13, 2, COMMAND_REQUEST);
        let stale_reply = request_challenge(&mut conn, &stale_request, 20).unwrap();
        let revoke_proof = proof("0123456789abcdef", 14, 3, COMMAND_REVOKE);
        let (revoke_reservation, _) =
            commit_counterparty_revoke_before_audit(&mut conn, &revoke_proof, 21).unwrap();
        assert!(
            reserve_verified_grant(
                &mut conn,
                &proof("0123456789abcdef", 15, 2, &stale_reply.command),
                &echoed_token(&stale_reply),
                22
            )
            .is_err(),
            "a token issued before revoke must not adopt the later revoked baseline"
        );
        acknowledge_revocation_audit(
            &mut conn,
            &revoke_proof,
            &revoke_reservation,
            &audit_for(&revoke_reservation),
        )
        .unwrap();

        let fresh_request = proof("0123456789abcdef", 16, 4, COMMAND_REQUEST);
        let fresh_reply = request_challenge(&mut conn, &fresh_request, 23).unwrap();
        let fresh_grant = proof("0123456789abcdef", 17, 4, &fresh_reply.command);
        let fresh_reservation =
            reserve_verified_grant(&mut conn, &fresh_grant, &echoed_token(&fresh_reply), 24)
                .unwrap();
        let fresh_audit = audit_for(&fresh_reservation);
        assert!(matches!(
            commit_verified_grant_after_audit(
                &mut conn,
                &fresh_grant,
                &fresh_reservation,
                &fresh_audit,
                25
            )
            .unwrap(),
            ConsentStatus::VerifiedGranted { revision: 3, .. }
        ));
    }

    #[test]
    fn revoke_wins_over_pending_regrant_without_erasing_its_terminal_custody() {
        let mut conn = core_conn();
        let initial_request = proof("fedcba9876543210", 21, 11, COMMAND_REQUEST);
        let initial_reply = request_challenge(&mut conn, &initial_request, 10).unwrap();
        let initial_grant = proof("fedcba9876543210", 22, 11, &initial_reply.command);
        let initial_reservation =
            reserve_verified_grant(&mut conn, &initial_grant, &echoed_token(&initial_reply), 11)
                .unwrap();
        commit_verified_grant_after_audit(
            &mut conn,
            &initial_grant,
            &initial_reservation,
            &audit_for(&initial_reservation),
            12,
        )
        .unwrap();

        let pending_request = proof("fedcba9876543210", 23, 12, COMMAND_REQUEST);
        let pending_reply = request_challenge(&mut conn, &pending_request, 20).unwrap();
        let pending = proof("fedcba9876543210", 24, 12, &pending_reply.command);
        let pending_reservation =
            reserve_verified_grant(&mut conn, &pending, &echoed_token(&pending_reply), 21).unwrap();
        let revoke = proof("fedcba9876543210", 25, 13, COMMAND_REVOKE);
        let (_, outcome) = commit_counterparty_revoke_before_audit(&mut conn, &revoke, 22).unwrap();
        assert_eq!(outcome.revision, 2);
        assert!(matches!(
            status(&conn, &revoke.key).unwrap(),
            ConsentStatus::Revoked { revision: 2, .. }
        ));
        let terminal: i64 = conn.query_row(
            "SELECT COUNT(*) FROM idx_counterparty_consent_audit_terminal_v1 WHERE operation_id=?1",
            [&pending_reservation.operation_id],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(
            terminal, 1,
            "pending grant custody must survive the revocation fence"
        );
        assert!(
            commit_verified_grant_after_audit(
                &mut conn,
                &pending,
                &pending_reservation,
                &audit_for(&pending_reservation),
                23
            )
            .is_err(),
            "a terminally fenced regrant must never turn consent positive"
        );
    }

    #[test]
    fn reserve_rejects_wrong_command_sender_conversation_expiry_and_replay() {
        let mut conn = core_conn();
        let request = proof("0123456789abcdef", 31, 21, COMMAND_REQUEST);
        let reply = request_challenge(&mut conn, &request, 100).unwrap();
        let token = echoed_token(&reply);
        assert!(
            reserve_verified_grant(
                &mut conn,
                &proof("0123456789abcdef", 32, 21, COMMAND_REQUEST),
                &token,
                101
            )
            .is_err(),
            "a request receipt cannot be substituted for its grant echo"
        );
        assert!(
            reserve_verified_grant(
                &mut conn,
                &proof("fedcba9876543210", 32, 21, &reply.command),
                &token,
                101
            )
            .is_err(),
            "another sender cannot consume the token"
        );
        assert!(
            reserve_verified_grant(
                &mut conn,
                &proof("0123456789abcdef", 32, 22, &reply.command),
                &token,
                101
            )
            .is_err(),
            "another conversation cannot consume the token"
        );
        assert!(
            reserve_verified_grant(
                &mut conn,
                &proof("0123456789abcdef", 32, 21, &reply.command),
                &token,
                100 + CHALLENGE_TTL_NS + 1
            )
            .is_err(),
            "expired token must fail"
        );

        let fresh_request = proof("0123456789abcdef", 33, 21, COMMAND_REQUEST);
        let fresh_reply = request_challenge(&mut conn, &fresh_request, 200).unwrap();
        let fresh_grant = proof("0123456789abcdef", 34, 21, &fresh_reply.command);
        let reservation =
            reserve_verified_grant(&mut conn, &fresh_grant, &echoed_token(&fresh_reply), 201)
                .unwrap();
        assert!(
            reserve_verified_grant(&mut conn, &fresh_grant, &echoed_token(&fresh_reply), 202)
                .is_err(),
            "one token cannot create a second reservation"
        );
        assert!(
            commit_verified_grant_after_audit(
                &mut conn,
                &fresh_grant,
                &reservation,
                &audit_for(&reservation),
                203
            )
            .is_ok(),
            "the exact authenticated echo remains usable once"
        );
    }
}
