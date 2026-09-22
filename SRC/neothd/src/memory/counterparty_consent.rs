//! W208 counterparty-clustering provenance and consent boundary.
//!
//! This is deliberately a positive-authority design.  An episode becomes
//! eligible only through an immutable local receipt, or through an immutable
//! channel receipt plus a future *verified* counterparty grant.  A legacy raw
//! row, malformed receipt, missing receipt, or revoked/absent consent remains
//! unknown.  Nothing in this module derives authority from `idx_episode`
//! display fields, identity aliases, routing state, or WAL adjacency.

use std::collections::HashSet;

use anyhow::{Context, Result, anyhow, bail, ensure};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::channels::registry::ChannelRef;
use crate::wal::events::{EVENT_TYPE_EXTENDED, EVENT_TYPE_RAW_TEXT, ExtendedSubtype};

const ORIGIN_LOCAL: &str = "local_attested";
const ORIGIN_CHANNEL: &str = "channel_bound";
const CONSENT_VERIFIED_GRANTED: &str = "verified_granted";
const CONSENT_REVOKED: &str = "revoked";
const REVOCATION_WITHOUT_PROOF_KIND: &str = "revocation_without_verified_grant_v1";

/// A scope key may only be made from an already authenticated, typed channel
/// reference and the existing scoped sender digest.  It deliberately has no
/// string/CLI constructor, so display channel names, aliases, raw senders and
/// account-wide keys cannot enter the consent table through this API.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CounterpartyKey {
    channel_id: String,
    account_id: String,
    scoped_sender_hash: String,
}

impl CounterpartyKey {
    pub fn from_authenticated(
        channel_ref: &ChannelRef,
        scoped_sender_hash: impl AsRef<str>,
    ) -> Result<Self> {
        let scoped_sender_hash = scoped_sender_hash.as_ref();
        ensure!(
            scoped_sender_hash.len() == 16
                && scoped_sender_hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "W208 scoped sender hash must be the canonical 16-character lowercase hex digest"
        );
        Ok(Self {
            channel_id: channel_ref.channel_id.as_str().to_owned(),
            account_id: channel_ref.account_id.as_str().to_owned(),
            scoped_sender_hash: scoped_sender_hash.to_owned(),
        })
    }

    pub fn channel_id(&self) -> &str {
        &self.channel_id
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn scoped_sender_hash(&self) -> &str {
        &self.scoped_sender_hash
    }
}

/// Serialize the only local-origin wire shape from the actual RAW header.
/// The caller must append this metadata receipt only after that RAW append has
/// succeeded; this helper grants no fallback authority when the receipt write
/// fails.
pub(crate) fn serialize_local_origin_receipt(
    raw_header: &crate::wal::header::EventHeaderV2,
) -> Result<Vec<u8>> {
    validate_raw_header_for_receipt(raw_header)?;
    serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "raw_event_id": raw_header.event_id.0,
        "raw_payload_hash": format!("{:016x}", raw_header.payload_hash),
        "origin": ORIGIN_LOCAL,
    }))
    .context("serialize W208 local raw-origin receipt")
}

/// Serialize one authenticated channel-origin wire shape.  Scope is emitted
/// from the caller's typed binding and canonical scoped sender hash only.
pub(crate) fn serialize_channel_origin_receipt(
    raw_header: &crate::wal::header::EventHeaderV2,
    channel_ref: &ChannelRef,
    scoped_sender_hash: impl AsRef<str>,
) -> Result<Vec<u8>> {
    validate_raw_header_for_receipt(raw_header)?;
    let key = CounterpartyKey::from_authenticated(channel_ref, scoped_sender_hash)?;
    serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "raw_event_id": raw_header.event_id.0,
        "raw_payload_hash": format!("{:016x}", raw_header.payload_hash),
        "origin": ORIGIN_CHANNEL,
        "channel_ref": channel_ref,
        "sender_id_hash": key.scoped_sender_hash(),
    }))
    .context("serialize W208 channel raw-origin receipt")
}

fn validate_raw_header_for_receipt(raw_header: &crate::wal::header::EventHeaderV2) -> Result<()> {
    ensure!(
        raw_header.event_type == EVENT_TYPE_RAW_TEXT && raw_header.event_id.0 > 0,
        "W208 receipt requires a positive RAW_TEXT header"
    );
    Ok(())
}

/// Fixed header values copied from a decoded, integrity-checked WAL frame.
/// This witness must come from the decoder, never from JSON payload fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OriginFrameWitness {
    event_id: i64,
    event_type: u8,
    event_subtype: u8,
    payload_hash: u64,
    wal_session_id: [u8; 16],
    occurred_at_ns: i64,
}

impl OriginFrameWitness {
    pub(crate) fn from_header(header: &crate::wal::header::EventHeaderV2) -> Result<Self> {
        let event_id = header.event_id.0 as i64;
        ensure!(event_id > 0, "W208 origin frame id must be positive");
        Ok(Self {
            event_id,
            event_type: header.event_type,
            event_subtype: header.event_subtype,
            payload_hash: header.payload_hash,
            wal_session_id: *header.session_id.as_bytes(),
            occurred_at_ns: header.hlc.physical_ns() as i64,
        })
    }
}

/// A parsed receipt.  Fields remain private so projection callers cannot
/// manufacture a raw link from unverified JSON; use one of the parsing
/// functions with an authoritative [`OriginFrameWitness`].
#[derive(Clone, Debug)]
pub struct OriginReceipt {
    raw_event_id: i64,
    raw_payload_hash: u64,
    raw_wal_session_id: [u8; 16],
    origin: ParsedOrigin,
    origin_frame: OriginFrameWitness,
}

#[derive(Clone, Debug)]
enum ParsedOrigin {
    LocalAttested,
    ChannelBound(CounterpartyKey),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireOriginReceipt {
    version: u8,
    raw_event_id: i64,
    raw_payload_hash: String,
    origin: String,
    #[serde(default)]
    channel_ref: Option<ChannelRef>,
    #[serde(default)]
    sender_id_hash: Option<String>,
}

/// Strictly parse a metadata-only local receipt and bind it to the actual WAL
/// header that carried it. The canonical RawTextOrigin subtype is checked
/// internally, so an arbitrary extended subtype cannot impersonate it.
pub(crate) fn parse_local_origin_receipt(
    payload: &[u8],
    origin_frame: OriginFrameWitness,
) -> Result<OriginReceipt> {
    let wire = parse_wire_receipt(payload, &origin_frame)?;
    parse_local_wire_receipt(wire, origin_frame)
}

fn parse_local_wire_receipt(
    wire: WireOriginReceipt,
    origin_frame: OriginFrameWitness,
) -> Result<OriginReceipt> {
    ensure!(wire.origin == ORIGIN_LOCAL, "W208 local receipt has wrong origin kind");
    ensure!(
        wire.channel_ref.is_none() && wire.sender_id_hash.is_none(),
        "W208 local receipt must not carry channel or sender fields"
    );
    Ok(OriginReceipt {
        raw_event_id: wire.raw_event_id,
        raw_payload_hash: parse_payload_hash(&wire.raw_payload_hash)?,
        raw_wal_session_id: origin_frame.wal_session_id,
        origin: ParsedOrigin::LocalAttested,
        origin_frame,
    })
}

/// Strictly parse a channel receipt and bind its exact typed channel/account
/// scope plus existing scoped sender digest.  `channel` display fields are not
/// accepted at all, so they cannot become a consent key.
pub(crate) fn parse_channel_origin_receipt(
    payload: &[u8],
    origin_frame: OriginFrameWitness,
) -> Result<OriginReceipt> {
    let wire = parse_wire_receipt(payload, &origin_frame)?;
    parse_channel_wire_receipt(wire, origin_frame)
}

fn parse_channel_wire_receipt(
    wire: WireOriginReceipt,
    origin_frame: OriginFrameWitness,
) -> Result<OriginReceipt> {
    ensure!(wire.origin == ORIGIN_CHANNEL, "W208 channel receipt has wrong origin kind");
    let channel_ref = wire
        .channel_ref
        .ok_or_else(|| anyhow!("W208 channel receipt lacks typed channel_ref"))?;
    let sender_hash = wire
        .sender_id_hash
        .ok_or_else(|| anyhow!("W208 channel receipt lacks scoped sender hash"))?;
    Ok(OriginReceipt {
        raw_event_id: wire.raw_event_id,
        raw_payload_hash: parse_payload_hash(&wire.raw_payload_hash)?,
        raw_wal_session_id: origin_frame.wal_session_id,
        origin: ParsedOrigin::ChannelBound(CounterpartyKey::from_authenticated(
            &channel_ref,
            sender_hash,
        )?),
        origin_frame,
    })
}

/// Strictly deserialize one canonical W208 receipt and dispatch only after the
/// decoded-header checks have passed.  Indexer callers use this single entry
/// point, so an untrusted shallow JSON discriminator cannot select a looser
/// parser.
pub(crate) fn parse_origin_receipt(
    payload: &[u8],
    origin_frame: OriginFrameWitness,
) -> Result<OriginReceipt> {
    let wire = parse_wire_receipt(payload, &origin_frame)?;
    match wire.origin.as_str() {
        ORIGIN_LOCAL => parse_local_wire_receipt(wire, origin_frame),
        ORIGIN_CHANNEL => parse_channel_wire_receipt(wire, origin_frame),
        _ => bail!("W208 origin receipt has an unknown origin kind"),
    }
}

fn parse_wire_receipt(
    payload: &[u8],
    origin_frame: &OriginFrameWitness,
) -> Result<WireOriginReceipt> {
    ensure!(
        origin_frame.event_type == EVENT_TYPE_EXTENDED
            && origin_frame.event_subtype == ExtendedSubtype::RawTextOrigin as u8,
        "W208 origin receipt header is not the canonical RawTextOrigin subtype"
    );
    ensure!(
        xxhash_rust::xxh3::xxh3_64(payload) == origin_frame.payload_hash,
        "W208 origin receipt payload does not match authoritative frame hash"
    );
    let wire: WireOriginReceipt = serde_json::from_slice(payload)
        .context("W208 parse origin receipt JSON")?;
    ensure!(wire.version == 1, "W208 origin receipt version must be 1");
    ensure!(wire.raw_event_id > 0, "W208 raw event id must be positive");
    ensure!(
        wire.raw_event_id < origin_frame.event_id,
        "W208 origin receipt must follow the referenced raw event"
    );
    Ok(wire)
}

fn parse_payload_hash(value: &str) -> Result<u64> {
    ensure!(
        value.len() == 16
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "W208 raw payload hash must be canonical lowercase 16-character hex"
    );
    u64::from_str_radix(value, 16).context("parse W208 raw payload hash")
}

/// Result of projecting a receipt.  A byte-for-byte repeat is idempotent;
/// anything else for either raw event or origin event is a hard conflict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginProjection {
    Inserted,
    AlreadyProjected,
    /// The receipt is well-formed but cannot establish a positive origin
    /// (missing/non-RAW/hash/session/order mismatch). No database mutation was
    /// attempted, so index replay may safely advance.
    Rejected,
    /// A conflicting receipt quarantined the previously positive origin.
    Conflicted,
}

/// Project an already parsed receipt in the indexer's caller-owned
/// transaction.  The referenced raw event must already be an indexed
/// `RAW_TEXT` row whose payload hash and session exactly match the receipt.
/// A receipt arriving before its raw row fails closed and is never buffered.
pub fn project_origin(
    tx: &Transaction<'_>,
    receipt: &OriginReceipt,
) -> Result<OriginProjection> {
    if !validate_raw_witness(tx, receipt)? {
        return Ok(OriginProjection::Rejected);
    }
    let already_conflicted: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM idx_episode_origin_conflict_v1 WHERE raw_event_id=?1)",
        [receipt.raw_event_id],
        |row| row.get(0),
    )?;
    if already_conflicted {
        return Ok(OriginProjection::Conflicted);
    }

    let (origin_kind, key) = match &receipt.origin {
        ParsedOrigin::LocalAttested => (ORIGIN_LOCAL, None),
        ParsedOrigin::ChannelBound(key) => (ORIGIN_CHANNEL, Some(key)),
    };
    let prior: Option<(String, i64, String, Option<String>, Option<String>, Option<String>)> = tx
        .query_row(
            "SELECT origin_kind, origin_event_id, raw_payload_hash, channel_id, account_id, scoped_sender_hash \
             FROM idx_episode_origin_v2 WHERE raw_event_id=?1",
            [receipt.raw_event_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )
        .optional()
        .context("W208 inspect existing raw origin")?;
    let expected_hash = format!("{:016x}", receipt.raw_payload_hash);
    let expected = (
        origin_kind.to_owned(),
        receipt.origin_frame.event_id,
        expected_hash.clone(),
        key.map(|value| value.channel_id.clone()),
        key.map(|value| value.account_id.clone()),
        key.map(|value| value.scoped_sender_hash.clone()),
    );
    if let Some(prior) = prior {
        if prior == expected {
            return Ok(OriginProjection::AlreadyProjected);
        }
        let prior_origin_event_id = prior.1;
        let prior_raw_payload_hash = prior.2;
        quarantine_conflicted_raw(
            tx,
            receipt.raw_event_id,
            prior_origin_event_id,
            receipt.origin_frame.event_id,
            &prior_raw_payload_hash,
            receipt.origin_frame.occurred_at_ns,
        )?;
        return Ok(OriginProjection::Conflicted);
    }

    // An origin receipt frame is itself immutable and may bind at most one raw
    // event.  Quarantine both sides instead of relying on the UNIQUE error,
    // which would otherwise leave the earlier positive projection eligible.
    let origin_already_bound_to: Option<i64> = tx
        .query_row(
            "SELECT raw_event_id FROM idx_episode_origin_v2 WHERE origin_event_id=?1",
            [receipt.origin_frame.event_id],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(other_raw_event_id) = origin_already_bound_to {
        let other_raw_payload_hash: String = tx.query_row(
            "SELECT raw_payload_hash FROM idx_episode_origin_v2 WHERE raw_event_id=?1",
            [other_raw_event_id],
            |row| row.get(0),
        )?;
        quarantine_conflicted_raw(
            tx,
            other_raw_event_id,
            receipt.origin_frame.event_id,
            receipt.origin_frame.event_id,
            &other_raw_payload_hash,
            receipt.origin_frame.occurred_at_ns,
        )?;
        quarantine_conflicted_raw(
            tx,
            receipt.raw_event_id,
            receipt.origin_frame.event_id,
            receipt.origin_frame.event_id,
            &expected_hash,
            receipt.origin_frame.occurred_at_ns,
        )?;
        return Ok(OriginProjection::Conflicted);
    }

    let changed = tx
        .execute(
            "INSERT INTO idx_episode_origin_v2 \
             (raw_event_id,origin_kind,origin_event_id,raw_payload_hash,channel_id,account_id,scoped_sender_hash) \
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                receipt.raw_event_id,
                origin_kind,
                receipt.origin_frame.event_id,
                expected_hash,
                key.map(|value| value.channel_id.as_str()),
                key.map(|value| value.account_id.as_str()),
                key.map(|value| value.scoped_sender_hash.as_str()),
            ],
        )
        .context("W208 insert immutable raw origin")?;
    ensure!(changed == 1, "W208 origin insert did not affect exactly one row");
    Ok(OriginProjection::Inserted)
}

/// Remove any previously positive projection before retaining a durable
/// conflict tombstone.  It also fences vectors and synthesis facts which had
/// already been derived from the formerly eligible raw event.
fn quarantine_conflicted_raw(
    tx: &Transaction<'_>,
    raw_event_id: i64,
    first_origin_event_id: i64,
    conflicting_origin_event_id: i64,
    raw_payload_hash: &str,
    detected_at_ns: i64,
) -> Result<()> {
    tx.execute(
        "INSERT OR IGNORE INTO idx_episode_origin_conflict_v1 \
         (raw_event_id,first_origin_event_id,conflicting_origin_event_id,raw_payload_hash,detected_at_ns) \
         VALUES(?1,?2,?3,?4,?5)",
        params![raw_event_id, first_origin_event_id, conflicting_origin_event_id, raw_payload_hash, detected_at_ns],
    )?;
    tx.execute("DELETE FROM idx_episode_origin_v2 WHERE raw_event_id=?1", [raw_event_id])?;
    tx.execute(
        "DELETE FROM idx_embedding WHERE source_kind='episode' AND source_ref=CAST(?1 AS TEXT)",
        [raw_event_id],
    )?;
    let mut facts = tx.prepare(
        "SELECT id,evidence FROM idx_groundtruth \
         WHERE source='synthesis-cron' AND scope='meta' AND revoked_at IS NULL",
    )?;
    let active = facts
        .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(facts);
    for (fact_id, evidence) in active {
        let evidence_ids: Option<Vec<i64>> = serde_json::from_str(&evidence).ok();
        // A malformed historical evidence field cannot prove that this raw id
        // is absent.  Retain audit text but revoke the active synthesis fact
        // instead of aborting the conflict quarantine transaction.
        if evidence_ids
            .as_ref()
            .map_or(true, |ids| ids.contains(&raw_event_id))
        {
            tx.execute(
                "UPDATE idx_groundtruth SET revoked_at=?1 WHERE id=?2 AND revoked_at IS NULL",
                params![detected_at_ns, fact_id],
            )?;
        }
    }
    Ok(())
}

fn validate_raw_witness(tx: &Transaction<'_>, receipt: &OriginReceipt) -> Result<bool> {
    let raw: Option<(i64, String, Vec<u8>)> = tx
        .query_row(
            "SELECT event_type,text_hash,wal_session_id FROM idx_episode WHERE event_id=?1",
            [receipt.raw_event_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .context("W208 load referenced raw episode")?;
    let Some((event_type, text_hash, session)) = raw else {
        return Ok(false);
    };
    Ok(
        receipt.raw_event_id < receipt.origin_frame.event_id
            && event_type == EVENT_TYPE_RAW_TEXT as i64
            && text_hash == format!("{:016x}", receipt.raw_payload_hash)
            && session.as_slice() == receipt.raw_wal_session_id,
    )
}

/// Current exact consent state.  W208 exposes no mutation which can produce
/// `VerifiedGranted`; a future ceremony must add that verifier-owned path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsentStatus {
    Absent,
    VerifiedGranted { revision: i64, verified_at_ns: i64 },
    Revoked { revision: i64, revoked_at_ns: i64 },
}

pub fn status(conn: &Connection, key: &CounterpartyKey) -> Result<ConsentStatus> {
    let row: Option<(String, i64, i64, Option<i64>)> = conn
        .query_row(
            "SELECT state,revision,proof_verified_at_ns,revoked_at_ns \
             FROM idx_counterparty_clustering_consent_v1 \
             WHERE channel_id=?1 AND account_id=?2 AND scoped_sender_hash=?3",
            params![key.channel_id, key.account_id, key.scoped_sender_hash],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .context("W208 read exact consent status")?;
    match row {
        None => Ok(ConsentStatus::Absent),
        Some((state, revision, verified_at_ns, revoked_at_ns)) if state == CONSENT_VERIFIED_GRANTED => {
            ensure!(revoked_at_ns.is_none(), "W208 granted row has a revoke timestamp");
            Ok(ConsentStatus::VerifiedGranted {
                revision,
                verified_at_ns,
            })
        }
        Some((state, revision, _, Some(revoked_at_ns))) if state == CONSENT_REVOKED => {
            Ok(ConsentStatus::Revoked {
                revision,
                revoked_at_ns,
            })
        }
        Some(_) => bail!("W208 consent row violates its state invariant"),
    }
}

/// Select only positively eligible text.  The embedding integration must first
/// establish that its concrete backend is local before it calls this API;
/// W208 does not create any remote-embedding authority.  Channel rows require
/// `verified_granted`; W208 has no grant constructor, so they stay denied until
/// the future ceremony exists.
pub(crate) fn claim_local_embedding_candidates(
    conn: &Connection,
    cap: usize,
) -> Result<Vec<(i64, String)>> {
    if cap == 0 {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare(
        "SELECT e.event_id,e.text FROM idx_episode e \
         WHERE e.text<>'' AND NOT EXISTS ( \
             SELECT 1 FROM idx_embedding x WHERE x.source_kind='episode' \
             AND x.source_ref=CAST(e.event_id AS TEXT)) \
           AND (EXISTS (SELECT 1 FROM idx_episode_origin_v2 o \
                        WHERE o.raw_event_id=e.event_id AND o.origin_kind='local_attested') \
             OR EXISTS (SELECT 1 FROM idx_episode_origin_v2 o \
                        JOIN idx_counterparty_clustering_consent_v1 c \
                          ON c.channel_id=o.channel_id AND c.account_id=o.account_id \
                         AND c.scoped_sender_hash=o.scoped_sender_hash \
                        WHERE o.raw_event_id=e.event_id AND o.origin_kind='channel_bound' \
                          AND c.state='verified_granted')) \
         ORDER BY e.event_id DESC LIMIT ?1",
    )?;
    stmt.query_map([cap as i64], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("W208 select local embedding candidates")
}

/// Store a vector only after repeating the positive eligibility check inside
/// the caller-owned SQLite writer transaction.  A result arriving after revoke
/// therefore cannot regain a vector.  The caller must already have proven its
/// concrete embedding backend local; this function grants no egress authority.
pub(crate) fn store_local_episode_vector_if_eligible(
    tx: &Transaction<'_>,
    event_id: i64,
    model: &str,
    vector: &[f32],
) -> Result<bool> {
    let eligible: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM idx_episode_origin_v2 o WHERE o.raw_event_id=?1 AND o.origin_kind='local_attested') \
         OR EXISTS(SELECT 1 FROM idx_episode_origin_v2 o \
                   JOIN idx_counterparty_clustering_consent_v1 c \
                     ON c.channel_id=o.channel_id AND c.account_id=o.account_id AND c.scoped_sender_hash=o.scoped_sender_hash \
                   WHERE o.raw_event_id=?1 AND o.origin_kind='channel_bound' AND c.state='verified_granted')",
        [event_id],
        |row| row.get(0),
    )?;
    if !eligible {
        return Ok(false);
    }
    crate::memory::embeddings::upsert(tx, "episode", &event_id.to_string(), model, vector)
        .context("W208 store eligible local episode vector")?;
    Ok(true)
}

/// Exact revocation result, useful to the caller's durable audit layer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RevocationResult {
    pub revision: i64,
    pub vectors_deleted: usize,
    pub synthesis_facts_revoked: usize,
}

/// Revoke one exact key and quarantine only its bound vectors and active
/// synthesis/meta facts whose JSON evidence contains a bound raw event.  This
/// must run in the caller's existing `BEGIN IMMEDIATE` transaction; it neither
/// deletes source rows nor changes ordinary recall/unbound embeddings.
pub fn revoke_and_quarantine(
    tx: &Transaction<'_>,
    key: &CounterpartyKey,
    now_ns: i64,
) -> Result<RevocationResult> {
    let current = status(tx, key)?;
    let revision = match current {
        ConsentStatus::Absent => {
            let mut hasher = Sha256::new();
            hasher.update(b"neoth/w208/revocation-without-proof/v1\0");
            hasher.update(key.channel_id.as_bytes());
            hasher.update([0]);
            hasher.update(key.account_id.as_bytes());
            hasher.update([0]);
            hasher.update(key.scoped_sender_hash.as_bytes());
            let digest = hasher.finalize().to_vec();
            tx.execute(
                "INSERT INTO idx_counterparty_clustering_consent_v1 \
                 (channel_id,account_id,scoped_sender_hash,state,proof_kind,proof_sha256,proof_verified_at_ns,revision,revoked_at_ns) \
                 VALUES (?1,?2,?3,'revoked',?4,?5,?6,1,?6)",
                params![key.channel_id, key.account_id, key.scoped_sender_hash,
                        REVOCATION_WITHOUT_PROOF_KIND, digest, now_ns],
            )?;
            1
        }
        ConsentStatus::VerifiedGranted { revision, .. } => {
            let next = revision.checked_add(1).ok_or_else(|| anyhow!("W208 revision overflow"))?;
            let changed = tx.execute(
                "UPDATE idx_counterparty_clustering_consent_v1 \
                 SET state='revoked',revision=?1,revoked_at_ns=?2 \
                 WHERE channel_id=?3 AND account_id=?4 AND scoped_sender_hash=?5 AND state='verified_granted'",
                params![next, now_ns, key.channel_id, key.account_id, key.scoped_sender_hash],
            )?;
            ensure!(changed == 1, "W208 verified grant changed during exact revoke");
            next
        }
        ConsentStatus::Revoked { revision, .. } => revision,
    };

    let bound_ids: HashSet<i64> = {
        let mut stmt = tx.prepare(
            "SELECT raw_event_id FROM idx_episode_origin_v2 \
             WHERE origin_kind='channel_bound' AND channel_id=?1 AND account_id=?2 AND scoped_sender_hash=?3",
        )?;
        stmt.query_map(params![key.channel_id, key.account_id, key.scoped_sender_hash], |row| row.get(0))?
            .collect::<rusqlite::Result<HashSet<_>>>()?
    };
    let vectors_deleted = tx.execute(
        "DELETE FROM idx_embedding WHERE source_kind='episode' AND source_ref IN ( \
             SELECT CAST(raw_event_id AS TEXT) FROM idx_episode_origin_v2 \
             WHERE origin_kind='channel_bound' AND channel_id=?1 AND account_id=?2 AND scoped_sender_hash=?3)",
        params![key.channel_id, key.account_id, key.scoped_sender_hash],
    )?;

    let mut facts = tx.prepare(
        "SELECT id,evidence FROM idx_groundtruth \
         WHERE source='synthesis-cron' AND scope='meta' AND revoked_at IS NULL",
    )?;
    let candidates = facts
        .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(facts);
    let mut synthesis_facts_revoked = 0;
    for (fact_id, evidence) in candidates {
        let evidence_ids: Option<Vec<i64>> = serde_json::from_str(&evidence).ok();
        // Unknown evidence is conservatively quarantined; returning an error
        // here would roll back the exact consent denial and retain the fact.
        if evidence_ids.as_ref().map_or(true, |ids| {
            ids.iter().any(|id| bound_ids.contains(id))
        }) {
            synthesis_facts_revoked += tx.execute(
                "UPDATE idx_groundtruth SET revoked_at=?1 WHERE id=?2 AND revoked_at IS NULL",
                params![now_ns, fact_id],
            )?;
        }
    }
    Ok(RevocationResult {
        revision,
        vectors_deleted,
        synthesis_facts_revoked,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{migrations, store};

    const ZERO_SESSION: [u8; 16] = [0; 16];

    fn local_payload(raw_event_id: i64) -> Vec<u8> {
        format!(
            r#"{{"version":1,"raw_event_id":{raw_event_id},"raw_payload_hash":"0000000000000001","origin":"local_attested"}}"#
        )
        .into_bytes()
    }

    fn local_receipt(raw_event_id: i64, origin_event_id: i64) -> OriginReceipt {
        let payload = local_payload(raw_event_id);
        let mut header = crate::wal::builder::HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
            .event_subtype(ExtendedSubtype::RawTextOrigin as u8)
            .build();
        header.event_id = crate::wal::types::EventId(origin_event_id as u64);
        header.session_id = crate::wal::types::SessionId::from_bytes(ZERO_SESSION);
        parse_local_origin_receipt(&payload, OriginFrameWitness::from_header(&header).unwrap())
            .unwrap()
    }

    fn insert_raw(conn: &Connection, event_id: i64) {
        conn.execute(
            "INSERT INTO idx_episode(event_id,event_type,ts_ns,text,text_hash,wal_session_id) \
             VALUES(?1,?2,1,'raw','0000000000000001',X'00000000000000000000000000000000')",
            params![event_id, EVENT_TYPE_RAW_TEXT as i64],
        )
        .unwrap();
    }

    fn telegram_key(sender_hash: &str) -> CounterpartyKey {
        CounterpartyKey::from_authenticated(
            &ChannelRef::default_account(crate::channels::registry::ChannelId::Telegram),
            sender_hash,
        )
        .unwrap()
    }

    #[test]
    fn v42_registry_and_fresh_schema_have_only_additive_default_deny_state() {
        assert_eq!(store::SCHEMA_VERSION, 42);
        let last = migrations::MIGRATIONS.last().unwrap();
        assert_eq!((last.from, last.to), (41, 42));
        let dir = tempfile::tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        for table in [
            "idx_episode_origin_v2",
            "idx_counterparty_clustering_consent_v1",
        ] {
            let _: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))
                .unwrap();
        }
    }

    #[test]
    fn v41_to_v42_migration_preserves_history_and_default_denies_without_backfill() {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("views.db");
        let mut conn = store::open(&database).unwrap();
        conn.execute(
            "INSERT INTO idx_episode \
             (event_id,event_type,ts_ns,text,text_hash,wal_session_id) \
             VALUES(77,?1,7,'pre-v42 retained text','000000000000004d',X'11111111111111111111111111111111')",
            [EVENT_TYPE_RAW_TEXT as i64],
        )
        .unwrap();
        crate::memory::embeddings::upsert(&conn, "episode", "77", "pre-v42-local", &[1.0])
            .unwrap();

        // Build a faithful v41 fixture from the otherwise fresh schema: the
        // historic episode/vector survive, while all v42-only state is absent.
        conn.execute_batch(
            "DROP TABLE idx_episode_origin_conflict_v1; \
             DROP TABLE idx_counterparty_clustering_consent_v1; \
             DROP TABLE idx_episode_origin_v2; \
             UPDATE meta SET value='41' WHERE key='schema_version';",
        )
        .unwrap();
        assert_eq!(migrations::migrate(&mut conn, 41, 42).unwrap(), 42);

        let retained: (String, String, i64) = conn
            .query_row(
                "SELECT text,text_hash,event_type FROM idx_episode WHERE event_id=77",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(retained, ("pre-v42 retained text".to_owned(), "000000000000004d".to_owned(), EVENT_TYPE_RAW_TEXT as i64));
        let vectors: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM idx_embedding WHERE source_kind='episode' AND source_ref='77'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(vectors, 1);
        for table in [
            "idx_episode_origin_v2",
            "idx_episode_origin_conflict_v1",
            "idx_counterparty_clustering_consent_v1",
        ] {
            let rows: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))
                .unwrap();
            assert_eq!(rows, 0, "v42 migration must not backfill {table}");
        }
        drop(conn);

        // Normal open observes the v42 stamp and remains idempotent while
        // preserving the legacy recall/vector state unchanged.
        let reopened = store::open(&database).unwrap();
        let version: String = reopened
            .query_row("SELECT value FROM meta WHERE key='schema_version'", [], |row| row.get(0))
            .unwrap();
        let retained_count: i64 = reopened
            .query_row("SELECT COUNT(*) FROM idx_episode WHERE event_id=77", [], |row| row.get(0))
            .unwrap();
        assert_eq!((version, retained_count), ("42".to_owned(), 1));
    }

    #[test]
    fn legacy_raw_is_default_denied_but_valid_local_receipt_is_eligible() {
        let dir = tempfile::tempdir().unwrap();
        let mut conn = store::open(&dir.path().join("views.db")).unwrap();
        insert_raw(&conn, 1);
        assert!(claim_local_embedding_candidates(&conn, 10).unwrap().is_empty());

        let tx = conn.transaction().unwrap();
        assert_eq!(project_origin(&tx, &local_receipt(1, 101)).unwrap(), OriginProjection::Inserted);
        tx.commit().unwrap();
        assert_eq!(claim_local_embedding_candidates(&conn, 10).unwrap(), vec![(1, "raw".to_owned())]);
    }

    #[test]
    fn conflicting_or_wrong_session_origin_never_retargets_raw() {
        let dir = tempfile::tempdir().unwrap();
        let mut conn = store::open(&dir.path().join("views.db")).unwrap();
        insert_raw(&conn, 1);
        let tx = conn.transaction().unwrap();
        project_origin(&tx, &local_receipt(1, 101)).unwrap();
        tx.commit().unwrap();

        let tx = conn.transaction().unwrap();
        assert_eq!(project_origin(&tx, &local_receipt(1, 102)).unwrap(), OriginProjection::Conflicted);
        tx.commit().unwrap();
        let retained: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM idx_episode_origin_v2 WHERE raw_event_id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retained, 0);
        let conflicts: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM idx_episode_origin_conflict_v1 WHERE raw_event_id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(conflicts, 1);
    }

    #[test]
    fn exact_revoke_deletes_only_bound_vectors_and_synthesis_facts() {
        let dir = tempfile::tempdir().unwrap();
        let mut conn = store::open(&dir.path().join("views.db")).unwrap();
        let key = telegram_key("0123456789abcdef");
        conn.execute(
            "INSERT INTO idx_episode_origin_v2 \
             (raw_event_id,origin_kind,origin_event_id,raw_payload_hash,channel_id,account_id,scoped_sender_hash) \
             VALUES(2,'channel_bound',202,'0000000000000002',?1,?2,?3)",
            params![key.channel_id, key.account_id, key.scoped_sender_hash],
        )
        .unwrap();
        crate::memory::embeddings::upsert(&conn, "episode", "2", "local-test", &[1.0]).unwrap();
        crate::memory::embeddings::upsert(&conn, "episode", "3", "local-test", &[1.0]).unwrap();
        for (statement, evidence) in [
            ("bound", "[2]"),
            ("unbound", "[3]"),
            ("malformed", "{}"),
        ] {
            conn.execute(
                "INSERT INTO idx_groundtruth(statement,source,scope,asserted_at,evidence) \
                 VALUES(?1,'synthesis-cron','meta',1,?2)",
                params![statement, evidence],
            )
            .unwrap();
        }

        let tx = conn.transaction().unwrap();
        let result = revoke_and_quarantine(&tx, &key, 10).unwrap();
        assert_eq!(result.revision, 1);
        assert_eq!(result.vectors_deleted, 1);
        assert_eq!(result.synthesis_facts_revoked, 2);
        assert_eq!(status(&tx, &key).unwrap(), ConsentStatus::Revoked { revision: 1, revoked_at_ns: 10 });
        tx.commit().unwrap();
        let remaining: i64 = conn
            .query_row("SELECT COUNT(*) FROM idx_embedding WHERE source_kind='episode'", [], |row| row.get(0))
            .unwrap();
        assert_eq!(remaining, 1);
        let active: Vec<String> = conn
            .prepare("SELECT statement FROM idx_groundtruth WHERE revoked_at IS NULL ORDER BY statement")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(active, vec!["unbound"]);
    }
}
