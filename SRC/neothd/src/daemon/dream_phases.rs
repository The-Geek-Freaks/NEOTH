//! W331 — receipt-bound Light/REM/Repair effects for the existing Dream task.
//!
//! `views.db` is the sole phase authority.  The cron sidecar admits calendar
//! boundaries only; it never decides whether a phase effect completed.

use std::path::Path;

use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

const REM_MIN_DISTINCT_RUNS: i64 = 2;
const MAX_HOT_INPUTS: usize = 32;

/// Fresh-store schema and the v44→v45 migration share this exact additive SQL.
pub const DREAM_PHASE_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS dream_phase_run (
    run_id TEXT PRIMARY KEY NOT NULL,
    local_day TEXT NOT NULL,
    input_sha256 TEXT NOT NULL,
    accepted_generation TEXT NOT NULL,
    created_at_ns INTEGER NOT NULL,
    UNIQUE(local_day, input_sha256)
) STRICT;
CREATE TABLE IF NOT EXISTS dream_phase_input (
    run_id TEXT NOT NULL REFERENCES dream_phase_run(run_id),
    event_id INTEGER NOT NULL CHECK(event_id > 0),
    event_text_sha256 TEXT NOT NULL,
    origin_binding_sha256 TEXT NOT NULL,
    source_tier TEXT NOT NULL CHECK(source_tier IN ('hot','warm')),
    source_trust INTEGER NOT NULL CHECK(source_trust BETWEEN 0 AND 2),
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    PRIMARY KEY(run_id, event_id), UNIQUE(run_id, ordinal)
) STRICT;
CREATE TABLE IF NOT EXISTS dream_phase_receipt (
    run_id TEXT NOT NULL REFERENCES dream_phase_run(run_id),
    phase TEXT NOT NULL CHECK(phase IN ('light','rem','repair')),
    state TEXT NOT NULL CHECK(state IN ('prepared','completed')),
    transition_id TEXT NOT NULL UNIQUE,
    result_sha256 TEXT,
    audit_state TEXT NOT NULL CHECK(audit_state IN ('pending','delivered')),
    audit_payload_sha256 TEXT,
    completed_at_ns INTEGER,
    delivered_frame_sha256 TEXT,
    PRIMARY KEY(run_id, phase)
) STRICT;
CREATE TABLE IF NOT EXISTS dream_rem_pair (
    run_id TEXT NOT NULL REFERENCES dream_phase_run(run_id),
    lo_event_id INTEGER NOT NULL CHECK(lo_event_id > 0),
    hi_event_id INTEGER NOT NULL CHECK(hi_event_id > lo_event_id),
    observed_at_ns INTEGER NOT NULL,
    PRIMARY KEY(run_id, lo_event_id, hi_event_id)
) STRICT;
"#;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Input {
    event_id: i64,
    text_hash: String,
    origin_hash: String,
    source_tier: String,
    source_trust: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditOutbox {
    pub transition_id: String,
    pub run_id: String,
    pub phase: String,
    pub result_sha256: String,
}

fn hex(bytes: impl AsRef<[u8]>) -> String { hex::encode(bytes) }
fn digest(parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for part in parts { hasher.update(part); hasher.update([0]); }
    hex(hasher.finalize())
}

fn phase_transition(run_id: &str, phase: &str) -> String {
    digest(&[b"dream-phase-transition-v1", run_id.as_bytes(), phase.as_bytes()])
}

/// Bind channel inputs to the specific verified-consent revision that admitted
/// them. Local origins deliberately use a stable, distinct sentinel: they do
/// not have a channel-consent row to reprove.
fn origin_binding_hash(
    kind: &str,
    channel: Option<&str>,
    account: Option<&str>,
    sender: Option<&str>,
    consent: &str,
    revision: Option<i64>,
) -> Result<String> {
    match kind {
        "local_attested" => Ok(digest(&[
            b"dream-origin-binding-v2",
            b"local_attested",
            b"no-channel-consent",
        ])),
        "channel_bound" => {
            ensure!(consent == "verified_granted", "Dream channel input lacks verified consent");
            let revision = revision.filter(|value| *value >= 1).context("Dream channel input lacks consent revision")?;
            let revision = revision.to_string();
            Ok(digest(&[
                b"dream-origin-binding-v2",
                b"channel_bound",
                channel.unwrap_or("").as_bytes(),
                account.unwrap_or("").as_bytes(),
                sender.unwrap_or("").as_bytes(),
                revision.as_bytes(),
            ]))
        }
        _ => anyhow::bail!("invalid Dream origin kind"),
    }
}

/// Persist immutable phase input before the legacy Dream composer is admitted.
/// This does not mutate tiers or graph edges.
pub fn prepare_for_day(home: &Path, local_day: &str, accepted_generation: &str) -> Result<bool> {
    let db=home.join("views.db"); if !db.exists() { return Ok(false); }
    let mut conn=crate::memory::store::open(&db)?;
    Ok(prepare_or_load(&mut conn,home,local_day,accepted_generation)?.is_some())
}

/// Resume only a run prepared before the legacy calendar claim. A claimed day
/// must never create a fresh phase input or replay outer Dream effects.
pub fn resume_existing_for_day(home: &Path, local_day: &str, accepted_generation: &str) -> Result<Vec<AuditOutbox>> {
    let db=home.join("views.db"); if !db.exists() { return Ok(Vec::new()); }
    let mut conn=crate::memory::store::open(&db)?;
    let row: Option<(String,String)> = conn.query_row("SELECT run_id,accepted_generation FROM dream_phase_run WHERE local_day=?1 ORDER BY created_at_ns ASC LIMIT 1",[local_day],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    let Some((run_id,generation))=row else { return Ok(Vec::new()); };
    ensure!(generation==accepted_generation,"claimed Dream phase belongs to retired generation");
    complete_light(&mut conn,&run_id,local_day)?; complete_rem(&mut conn,&run_id)?; complete_repair(&mut conn,&run_id)?; pending_audits(&conn,&run_id)
}

pub fn pending_audits_for_day(home: &Path, local_day: &str) -> Result<Vec<AuditOutbox>> {
    let conn=crate::memory::store::open(&home.join("views.db"))?;
    conn.prepare("SELECT r.transition_id,r.run_id,r.phase,r.result_sha256 FROM dream_phase_receipt r JOIN dream_phase_run run ON run.run_id=r.run_id WHERE run.local_day=?1 AND r.state='completed' AND r.audit_state='pending' ORDER BY r.phase")?
        .query_map([local_day],|r|Ok(AuditOutbox{transition_id:r.get(0)?,run_id:r.get(1)?,phase:r.get(2)?,result_sha256:r.get(3)?}))?
        .collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
}

fn prepare_or_load(conn: &mut Connection, home: &Path, day: &str, generation: &str) -> Result<Option<String>> {
    if let Some((run_id, stored_generation)) = conn.query_row("SELECT run_id,accepted_generation FROM dream_phase_run WHERE local_day=?1 ORDER BY created_at_ns ASC LIMIT 1", [day], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))).optional()? {
        ensure!(stored_generation == generation, "Dream phase run for {day} belongs to retired generation {stored_generation}");
        return Ok(Some(run_id));
    }
    let mut ids: Vec<i64> = crate::daemon::dreaming::load_dreams_for_day(home, day)
        .into_iter().flat_map(|dream| dream.event_ids).filter(|id| *id > 0).collect();
    ids.sort_unstable(); ids.dedup();
    // A JSONL Dream may contain an unbounded historical or malformed id list.
    // Freeze the deterministic lowest positive ids before opening the phase tx;
    // adding the bounded warm anchors below keeps REM at at most 64 inputs.
    ids.truncate(MAX_HOT_INPUTS);
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if ids.is_empty() {
        ids = tx.prepare("SELECT ep.event_id FROM idx_episode ep JOIN idx_episode_origin_v2 o ON o.raw_event_id=ep.event_id LEFT JOIN idx_counterparty_clustering_consent_v1 c ON c.channel_id=o.channel_id AND c.account_id=o.account_id AND c.scoped_sender_hash=o.scoped_sender_hash WHERE ep.pinned=0 AND (o.origin_kind='local_attested' OR (o.origin_kind='channel_bound' AND c.state='verified_granted')) ORDER BY ep.ts_ns ASC,ep.event_id ASC LIMIT 32")?.query_map([],|r|r.get(0))?.collect::<rusqlite::Result<_>>()?;
    }
    let mut inputs = Vec::new();
    for id in ids {
        let row: Option<(String, i64, String, Option<String>, Option<String>, Option<String>, String, Option<i64>)> = tx.query_row(
            "SELECT ep.text_hash, ep.trust, o.origin_kind, o.channel_id, o.account_id, o.scoped_sender_hash, \
             COALESCE(c.state, ''), c.revision FROM idx_episode ep JOIN idx_episode_origin_v2 o ON o.raw_event_id=ep.event_id \
             LEFT JOIN idx_counterparty_clustering_consent_v1 c ON c.channel_id=o.channel_id AND c.account_id=o.account_id AND c.scoped_sender_hash=o.scoped_sender_hash \
             WHERE ep.event_id=?1 AND ep.pinned=0 AND (o.origin_kind='local_attested' OR (o.origin_kind='channel_bound' AND c.state='verified_granted'))",
            [id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?))
        ).optional()?;
        if let Some((text_hash, trust, kind, channel, account, sender, consent, revision)) = row {
            let origin_hash = origin_binding_hash(&kind, channel.as_deref(), account.as_deref(), sender.as_deref(), &consent, revision)?;
            inputs.push(Input { event_id: id, text_hash, origin_hash, source_tier: "hot".into(), source_trust: trust });
        }
    }
    // Retained warm anchors are deliberately repeatable REM evidence. The
    // bounded stable order lets two distinct Dream runs observe a real pair
    // even after Light moved its original hot sources out of the hot tier.
    let mut warm = tx.prepare(
        "SELECT warm.event_id, warm.text_hash, warm.trust, o.origin_kind, o.channel_id, o.account_id, o.scoped_sender_hash, COALESCE(c.state, ''), c.revision \
         FROM idx_consolidated warm JOIN idx_episode_origin_v2 o ON o.raw_event_id=warm.event_id \
         LEFT JOIN idx_counterparty_clustering_consent_v1 c ON c.channel_id=o.channel_id AND c.account_id=o.account_id AND c.scoped_sender_hash=o.scoped_sender_hash \
         WHERE warm.kind='retained' AND warm.event_id IS NOT NULL AND (o.origin_kind='local_attested' OR (o.origin_kind='channel_bound' AND c.state='verified_granted')) \
         ORDER BY warm.importance DESC, warm.consolidated_ts DESC, warm.event_id ASC LIMIT 32"
    )?;
    let warm_rows: Vec<(i64,String,i64,String,Option<String>,Option<String>,Option<String>,String,Option<i64>)> = warm.query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?)))?.collect::<rusqlite::Result<_>>()?;
    for (event_id,text_hash,trust,kind,channel,account,sender,consent,revision) in warm_rows {
        if inputs.iter().any(|input| input.event_id==event_id) { continue; }
        let origin_hash=origin_binding_hash(&kind,channel.as_deref(),account.as_deref(),sender.as_deref(),&consent,revision)?;
        inputs.push(Input{event_id,text_hash,origin_hash,source_tier:"warm".into(),source_trust:trust});
    }
    if inputs.is_empty() { tx.commit()?; return Ok(None); }
    let canonical = inputs.iter().flat_map(|i| [i.event_id.to_string(), i.text_hash.clone(), i.origin_hash.clone(), i.source_tier.clone(), i.source_trust.to_string()]).collect::<Vec<_>>().join("\x1f");
    let input_sha = digest(&[b"dream-phase-input-v1", day.as_bytes(), generation.as_bytes(), canonical.as_bytes()]);
    let run_id = digest(&[b"dream-phase-run-v1", day.as_bytes(), generation.as_bytes(), input_sha.as_bytes()]);
    tx.execute("INSERT INTO dream_phase_run(run_id,local_day,input_sha256,accepted_generation,created_at_ns) VALUES(?1,?2,?3,?4,?5)", params![run_id, day, input_sha, generation, crate::time::now_unix_ns_i64()])?;
    for (ordinal, input) in inputs.iter().enumerate() {
        tx.execute("INSERT INTO dream_phase_input(run_id,event_id,event_text_sha256,origin_binding_sha256,source_tier,source_trust,ordinal) VALUES(?1,?2,?3,?4,?5,?6,?7)", params![run_id, input.event_id, input.text_hash, input.origin_hash, input.source_tier, input.source_trust, ordinal as i64])?;
    }
    prepare_receipt(&tx, &run_id, "light")?;
    tx.commit()?;
    Ok(Some(run_id))
}

fn prepare_receipt(tx: &rusqlite::Transaction<'_>, run_id: &str, phase: &str) -> Result<()> {
    tx.execute("INSERT OR IGNORE INTO dream_phase_receipt(run_id,phase,state,transition_id,audit_state) VALUES(?1,?2,'prepared',?3,'pending')", params![run_id, phase, phase_transition(run_id, phase)])?;
    Ok(())
}

fn inputs(tx: &rusqlite::Transaction<'_>, run_id: &str) -> Result<Vec<Input>> {
    tx.prepare("SELECT event_id,event_text_sha256,origin_binding_sha256,source_tier,source_trust FROM dream_phase_input WHERE run_id=?1 ORDER BY ordinal ASC")?
        .query_map([run_id], |r| Ok(Input { event_id:r.get(0)?, text_hash:r.get(1)?, origin_hash:r.get(2)?, source_tier:r.get(3)?, source_trust:r.get(4)? }))?
        .collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
}

/// Reprove the positive origin/consent decision while holding the effect tx.
/// A prepared receipt is evidence of prior selection, never permission to
/// mutate after a revocation or source replacement.
fn revalidate_input_at(tx: &rusqlite::Transaction<'_>, input: &Input, location: &str) -> Result<()> {
    let table = match location { "hot" => "idx_episode", "warm" => "idx_consolidated", _ => anyhow::bail!("invalid Dream input location") };
    let sql = format!("SELECT source.text_hash, source.trust, o.origin_kind, o.channel_id, o.account_id, o.scoped_sender_hash, COALESCE(c.state, ''), c.revision FROM {table} source JOIN idx_episode_origin_v2 o ON o.raw_event_id=source.event_id LEFT JOIN idx_counterparty_clustering_consent_v1 c ON c.channel_id=o.channel_id AND c.account_id=o.account_id AND c.scoped_sender_hash=o.scoped_sender_hash WHERE source.event_id=?1 AND (o.origin_kind='local_attested' OR (o.origin_kind='channel_bound' AND c.state='verified_granted'))");
    let row: Option<(String,i64,String,Option<String>,Option<String>,Option<String>,String,Option<i64>)> = tx.query_row(&sql,[input.event_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).optional()?;
    let Some((text_hash,trust,kind,channel,account,sender,consent,revision))=row else { anyhow::bail!("Dream bound input {} is no longer positively eligible",input.event_id); };
    let origin=origin_binding_hash(&kind,channel.as_deref(),account.as_deref(),sender.as_deref(),&consent,revision)?;
    ensure!(text_hash==input.text_hash && trust==input.source_trust && origin==input.origin_hash,"Dream bound input {} changed",input.event_id); Ok(())
}

fn completed(tx: &rusqlite::Transaction<'_>, run_id: &str, phase: &str) -> Result<bool> {
    Ok(tx.query_row("SELECT state FROM dream_phase_receipt WHERE run_id=?1 AND phase=?2", params![run_id,phase], |r| r.get::<_,String>(0)).optional()?.as_deref() == Some("completed"))
}

fn complete_light(conn: &mut Connection, run_id: &str, day: &str) -> Result<()> {
    let tx=conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if completed(&tx,run_id,"light")? { tx.commit()?; return Ok(()); }
    let bound=inputs(&tx,run_id)?; ensure!(!bound.is_empty(), "Dream Light has no bound input");
    for input in &bound { if input.source_tier=="hot" { revalidate_input_at(&tx,input,"hot")?; } }
    let selected=bound.iter().filter(|i| i.source_tier=="hot").map(|i|(i.event_id,i.text_hash.clone())).collect::<Vec<_>>();
    let moved=crate::memory::consolidate::promote_selected_hot_to_warm(&tx,day,&selected,crate::time::now_unix_ns_i64())?;
    let moved_text=moved.to_string();
    let result=digest(&[b"light-v1",run_id.as_bytes(),moved_text.as_bytes()]);
    tx.execute("UPDATE dream_phase_receipt SET state='completed',result_sha256=?2,audit_state='pending',completed_at_ns=?3 WHERE run_id=?1 AND phase='light' AND state='prepared'", params![run_id,result,crate::time::now_unix_ns_i64()])?;
    tx.commit()?; Ok(())
}

fn complete_rem(conn: &mut Connection, run_id: &str) -> Result<()> {
    let tx=conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    prepare_receipt(&tx,run_id,"rem")?;
    if completed(&tx,run_id,"rem")? { tx.commit()?; return Ok(()); }
    let bound=inputs(&tx,run_id)?; for input in &bound { revalidate_input_at(&tx,input,"warm")?; }
    let ids=bound.into_iter().map(|i|i.event_id).collect::<Vec<_>>();
    let now=crate::time::now_unix_i64(); let mut qualified=Vec::new();
    for (n,&a) in ids.iter().enumerate() { for &b in &ids[n+1..] { let (lo,hi)=if a<b{(a,b)}else{(b,a)};
        tx.execute("INSERT OR IGNORE INTO dream_rem_pair(run_id,lo_event_id,hi_event_id,observed_at_ns) VALUES(?1,?2,?3,?4)",params![run_id,lo,hi,now])?;
        let runs:i64=tx.query_row("SELECT COUNT(DISTINCT run_id) FROM dream_rem_pair WHERE lo_event_id=?1 AND hi_event_id=?2",params![lo,hi],|r|r.get(0))?;
        if runs>=REM_MIN_DISTINCT_RUNS { qualified.push((lo,hi)); }
    }}
    let reinforced=crate::memory::assoc_graph::reinforce_pairs_in_transaction(&tx,&qualified,now)?;
    let reinforced_text=reinforced.to_string();
    let result=digest(&[b"rem-v1",run_id.as_bytes(),reinforced_text.as_bytes()]);
    tx.execute("UPDATE dream_phase_receipt SET state='completed',result_sha256=?2,audit_state='pending',completed_at_ns=?3 WHERE run_id=?1 AND phase='rem' AND state='prepared'",params![run_id,result,crate::time::now_unix_ns_i64()])?;
    tx.commit()?; Ok(())
}

fn complete_repair(conn:&mut Connection,run_id:&str)->Result<()> {
    let tx=conn.transaction_with_behavior(TransactionBehavior::Immediate)?; prepare_receipt(&tx,run_id,"repair")?;
    if completed(&tx,run_id,"repair")? { tx.commit()?; return Ok(()); }
    // Repair proves Light's declared output exists. It never reselects/replays it.
    for input in inputs(&tx,run_id)? {
        revalidate_input_at(&tx,&input,"warm")?;
        let count:i64=tx.query_row("SELECT COUNT(*) FROM idx_consolidated WHERE event_id=?1 AND kind='retained' AND text_hash=?2",params![input.event_id,input.text_hash],|r|r.get(0))?;
        ensure!(count==1,"Dream Repair cannot prove Light output for {}",input.event_id);
    }
    let mut missing=Vec::new();
    let pairs: Vec<(i64, i64)> = tx.prepare("SELECT p.lo_event_id,p.hi_event_id FROM dream_rem_pair p WHERE p.run_id=?1 AND (SELECT COUNT(DISTINCT all_runs.run_id) FROM dream_rem_pair all_runs WHERE all_runs.lo_event_id=p.lo_event_id AND all_runs.hi_event_id=p.hi_event_id)>=?2")?.query_map(params![run_id,REM_MIN_DISTINCT_RUNS],|r|Ok((r.get(0)?,r.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
    for (lo,hi) in pairs { let present:i64=tx.query_row("SELECT COUNT(*) FROM idx_memory_links WHERE lo_id=?1 AND hi_id=?2",params![lo,hi],|r|r.get(0))?; if present==0 { missing.push((lo,hi)); } }
    crate::memory::assoc_graph::reinforce_pairs_in_transaction(&tx,&missing,crate::time::now_unix_i64())?;
    let result=digest(&[b"repair-v1",run_id.as_bytes()]);
    tx.execute("UPDATE dream_phase_receipt SET state='completed',result_sha256=?2,audit_state='pending',completed_at_ns=?3 WHERE run_id=?1 AND phase='repair' AND state='prepared'",params![run_id,result,crate::time::now_unix_ns_i64()])?;
    tx.commit()?; Ok(())
}

fn pending_audits(conn:&Connection,run_id:&str)->Result<Vec<AuditOutbox>> {
    conn.prepare("SELECT transition_id,run_id,phase,result_sha256 FROM dream_phase_receipt WHERE run_id=?1 AND state='completed' AND audit_state='pending' ORDER BY phase")?
        .query_map([run_id],|r|Ok(AuditOutbox{transition_id:r.get(0)?,run_id:r.get(1)?,phase:r.get(2)?,result_sha256:r.get(3)?}))?
        .collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
}

/// Mark an append-once WAL receipt delivered only after the writer returned an
/// exact authenticated frame hash. A mismatched/missing outbox is fail-closed.
pub fn mark_audit_delivered(home: &Path, transition_id: &str, frame_sha256: &str) -> Result<()> {
    let mut conn=crate::memory::store::open(&home.join("views.db"))?;
    let tx=conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let changed=tx.execute("UPDATE dream_phase_receipt SET audit_state='delivered',delivered_frame_sha256=?2 WHERE transition_id=?1 AND state='completed' AND audit_state='pending'",params![transition_id,frame_sha256])?;
    ensure!(changed==1,"Dream audit outbox is not pending for transition {transition_id}");
    tx.commit()?; Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    fn home() -> tempfile::TempDir {
        let home = tempfile::tempdir().unwrap();
        let conn = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        for id in [1_i64,2] {
            insert_local_episode(&conn, id, false, 0);
        }
        drop(conn);
        home
    }

    fn insert_local_episode(conn: &rusqlite::Connection, id: i64, pinned: bool, trust: i64) {
        conn.execute(
            "INSERT INTO idx_episode(event_id,event_type,ts_ns,text,text_hash,importance,last_access_ts,pinned,trust) \
             VALUES(?1,1,?1,?2,?3,.5,1,?4,?5)",
            params![id, format!("event-{id}"), format!("hash-{id}"), pinned as i64, trust],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_episode_origin_v2(raw_event_id,origin_kind,origin_event_id,raw_payload_hash) \
             VALUES(?1,'local_attested',?1,?2)",
            params![id, format!("origin-{id}")],
        )
        .unwrap();
    }

    fn dreams(home: &Path, day: &str, event_ids: Vec<i64>) {
        crate::daemon::dreaming::append_dream(
            home,
            &crate::daemon::dreaming::Dream {
                day: day.into(),
                event_ids,
                ..Default::default()
            },
        )
        .unwrap();
    }

    fn run_prepared(home: &Path, day: &str, generation: &str) {
        assert!(prepare_for_day(home, day, generation).unwrap());
        resume_existing_for_day(home, day, generation).unwrap();
    }

    #[test]
    fn light_promotes_only_selected_hot_inputs_and_real_warm_reader_retains_trust_zero() {
        let home = home();
        let conn = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        insert_local_episode(&conn, 3, false, 2);
        insert_local_episode(&conn, 4, true, 2);
        drop(conn);
        dreams(home.path(), "2040-01-01", vec![1, 2]);

        run_prepared(home.path(), "2040-01-01", "7");
        let conn = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM idx_episode WHERE event_id IN (1,2)", [], |r| r.get::<_, i64>(0)).unwrap(),
            0
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM idx_episode WHERE event_id IN (3,4)", [], |r| r.get::<_, i64>(0)).unwrap(),
            2
        );
        let recalled = crate::memory::region_router::recall_warm_like_with_source(&conn, "event-1", 8, None).unwrap();
        assert_eq!(recalled.len(), 1);
        assert_eq!(recalled[0].hit.event_id, 1);
        assert_eq!(recalled[0].hit.tier, "warm");
        assert_eq!(recalled[0].hit.trust, 0);
    }

    #[test]
    fn second_day_with_no_fresh_hot_rows_creates_one_canonical_rem_edge_and_duplicate_ticks_do_not_reinforce() {
        let home = home();
        dreams(home.path(), "2040-01-01", vec![1, 2]);
        run_prepared(home.path(), "2040-01-01", "7");
        dreams(home.path(), "2040-01-02", Vec::new());
        run_prepared(home.path(), "2040-01-02", "7");

        let conn = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        let edge: (f64, i64) = conn.query_row(
            "SELECT weight,last_co_access FROM idx_memory_links WHERE lo_id=1 AND hi_id=2",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(edge.0, 1.0);
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM idx_memory_links", [], |r| r.get::<_, i64>(0)).unwrap(),
            1
        );
        drop(conn);
        resume_existing_for_day(home.path(), "2040-01-02", "7").unwrap();
        let conn = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        assert_eq!(conn.query_row("SELECT weight FROM idx_memory_links WHERE lo_id=1 AND hi_id=2", [], |r| r.get::<_, f64>(0)).unwrap(), edge.0);
    }

    #[test]
    fn oversized_dream_ids_bind_the_deterministic_first_32_and_leave_the_rest_hot() {
        let home = home();
        let conn = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        for id in 3..=34 {
            insert_local_episode(&conn, id, false, 1);
        }
        drop(conn);
        let mut ids = (1..=34).rev().collect::<Vec<_>>();
        ids.extend([34, 1, 0, -1]);
        dreams(home.path(), "2040-01-01", ids);
        assert!(prepare_for_day(home.path(), "2040-01-01", "7").unwrap());
        let conn = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        let selected = conn.prepare("SELECT event_id FROM dream_phase_input ORDER BY ordinal")
            .unwrap()
            .query_map([], |row| row.get::<_, i64>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(selected, (1..=32).collect::<Vec<_>>());
        drop(conn);
        resume_existing_for_day(home.path(), "2040-01-01", "7").unwrap();
        let conn = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM idx_episode WHERE event_id BETWEEN 1 AND 32", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM idx_episode WHERE event_id IN (33,34)", [], |r| r.get::<_, i64>(0)).unwrap(), 2);
    }

    #[test]
    fn channel_consent_revocation_after_prepare_blocks_all_dream_effects() {
        let home = home();
        let conn = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        conn.execute("DELETE FROM idx_episode_origin_v2 WHERE raw_event_id=1", []).unwrap();
        conn.execute(
            "INSERT INTO idx_episode_origin_v2(raw_event_id,origin_kind,origin_event_id,raw_payload_hash,channel_id,account_id,scoped_sender_hash) \
             VALUES(1,'channel_bound',101,'channel-origin','channel','account','sender')", [],
        ).unwrap();
        conn.execute(
            "INSERT INTO idx_counterparty_clustering_consent_v1(channel_id,account_id,scoped_sender_hash,state,proof_kind,proof_sha256,proof_verified_at_ns,revision,revoked_at_ns) \
             VALUES('channel','account','sender','verified_granted','test',zeroblob(32),1,1,NULL)", [],
        ).unwrap();
        drop(conn);
        dreams(home.path(), "2040-01-01", vec![1, 2]);
        assert!(prepare_for_day(home.path(), "2040-01-01", "7").unwrap());

        let conn = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        conn.execute(
            "UPDATE idx_counterparty_clustering_consent_v1 SET state='revoked',revoked_at_ns=2 WHERE channel_id='channel' AND account_id='account' AND scoped_sender_hash='sender'", [],
        ).unwrap();
        drop(conn);

        assert!(resume_existing_for_day(home.path(), "2040-01-01", "7").is_err());
        let conn = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM idx_episode", [], |r| r.get::<_, i64>(0)).unwrap(), 2);
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM idx_consolidated", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM dream_phase_receipt WHERE state='completed'", [], |r| r.get::<_, i64>(0)).unwrap(), 0, "revocation before effects must leave all phase receipts uncompleted");
    }
    #[test]
    fn channel_consent_regrant_with_a_new_revision_denies_the_prepared_binding() {
        let home = home();
        let conn = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        conn.execute("DELETE FROM idx_episode_origin_v2 WHERE raw_event_id=1", []).unwrap();
        conn.execute(
            "INSERT INTO idx_episode_origin_v2(raw_event_id,origin_kind,origin_event_id,raw_payload_hash,channel_id,account_id,scoped_sender_hash) \
             VALUES(1,'channel_bound',101,'channel-origin','channel','account','sender')", [],
        ).unwrap();
        conn.execute(
            "INSERT INTO idx_counterparty_clustering_consent_v1(channel_id,account_id,scoped_sender_hash,state,proof_kind,proof_sha256,proof_verified_at_ns,revision,revoked_at_ns) \
             VALUES('channel','account','sender','verified_granted','test',zeroblob(32),1,1,NULL)", [],
        ).unwrap();
        drop(conn);
        dreams(home.path(), "2040-01-01", vec![1, 2]);
        assert!(prepare_for_day(home.path(), "2040-01-01", "7").unwrap());
        let conn = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        conn.execute(
            "UPDATE idx_counterparty_clustering_consent_v1 SET state='revoked',revoked_at_ns=2 WHERE channel_id='channel' AND account_id='account' AND scoped_sender_hash='sender'", [],
        ).unwrap();
        conn.execute(
            "UPDATE idx_counterparty_clustering_consent_v1 SET state='verified_granted',revision=2,revoked_at_ns=NULL,proof_verified_at_ns=3 WHERE channel_id='channel' AND account_id='account' AND scoped_sender_hash='sender'", [],
        ).unwrap();
        drop(conn);

        assert!(resume_existing_for_day(home.path(), "2040-01-01", "7").is_err());
        let conn = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM idx_episode", [], |r| r.get::<_, i64>(0)).unwrap(), 2);
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM idx_consolidated", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
    }

    #[test]
    fn generation_or_corrupted_binding_denial_leaves_phase_effects_unmutated() {
        let home = home();
        dreams(home.path(), "2040-01-01", vec![1, 2]);
        assert!(prepare_for_day(home.path(), "2040-01-01", "7").unwrap());
        assert!(resume_existing_for_day(home.path(), "2040-01-01", "8").is_err());
        let conn = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        conn.execute("UPDATE dream_phase_input SET event_text_sha256='corrupt'", []).unwrap();
        drop(conn);
        assert!(resume_existing_for_day(home.path(), "2040-01-01", "7").is_err());
        let conn = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM idx_episode", [], |r| r.get::<_, i64>(0)).unwrap(), 2);
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM idx_consolidated", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM idx_memory_links", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
    }

    #[test]
    fn claimed_resume_only_uses_existing_bound_input_and_cannot_select_new_rows() {
        let home = home();
        dreams(home.path(), "2040-01-01", vec![1, 2]);
        assert!(prepare_for_day(home.path(), "2040-01-01", "7").unwrap());
        let conn = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        insert_local_episode(&conn, 3, false, 2);
        drop(conn);
        dreams(home.path(), "2040-01-01", vec![3]);
        resume_existing_for_day(home.path(), "2040-01-01", "7").unwrap();
        let conn = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM dream_phase_input", [], |r| r.get::<_, i64>(0)).unwrap(), 2);
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM idx_episode WHERE event_id=3", [], |r| r.get::<_, i64>(0)).unwrap(), 1);
        assert!(resume_existing_for_day(home.path(), "2040-01-02", "7").unwrap().is_empty());
    }

    #[test]
    fn prepared_repair_recreates_only_the_declared_missing_pair_once() {
        let home = home();
        dreams(home.path(), "2040-01-01", vec![1, 2]);
        run_prepared(home.path(), "2040-01-01", "7");
        dreams(home.path(), "2040-01-02", Vec::new());
        run_prepared(home.path(), "2040-01-02", "7");
        let mut conn = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        let run_id: String = conn.query_row("SELECT run_id FROM dream_phase_run WHERE local_day='2040-01-02'", [], |r| r.get(0)).unwrap();
        let other_run = "other-qualified-pair";
        conn.execute(
            "INSERT INTO dream_phase_run(run_id,local_day,input_sha256,accepted_generation,created_at_ns) VALUES(?1,'2040-01-03','other-input','7',3)",
            [other_run],
        ).unwrap();
        let first_run: String = conn.query_row("SELECT run_id FROM dream_phase_run WHERE local_day='2040-01-01'", [], |r| r.get(0)).unwrap();
        conn.execute("INSERT INTO dream_rem_pair(run_id,lo_event_id,hi_event_id,observed_at_ns) VALUES(?1,3,4,3)", [&first_run]).unwrap();
        conn.execute("INSERT INTO dream_rem_pair(run_id,lo_event_id,hi_event_id,observed_at_ns) VALUES(?1,3,4,3)", [other_run]).unwrap();
        conn.execute("DELETE FROM idx_memory_links WHERE lo_id=1 AND hi_id=2", []).unwrap();
        conn.execute("UPDATE dream_phase_receipt SET state='prepared',result_sha256=NULL WHERE run_id=?1 AND phase='repair'", [&run_id]).unwrap();
        complete_repair(&mut conn, &run_id).unwrap();
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM idx_memory_links WHERE lo_id=1 AND hi_id=2", [], |r| r.get::<_, i64>(0)).unwrap(), 1);
        assert_eq!(conn.query_row("SELECT weight FROM idx_memory_links WHERE lo_id=1 AND hi_id=2", [], |r| r.get::<_, f64>(0)).unwrap(), 1.0);
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM idx_memory_links WHERE lo_id=3 AND hi_id=4", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
        complete_repair(&mut conn, &run_id).unwrap();
        assert_eq!(conn.query_row("SELECT weight FROM idx_memory_links WHERE lo_id=1 AND hi_id=2", [], |r| r.get::<_, f64>(0)).unwrap(), 1.0);
    }

    #[test]
    fn rejected_light_write_rolls_back_without_completing_the_prepared_receipt() {
        let home = home();
        dreams(home.path(), "2040-01-01", vec![1, 2]);
        assert!(prepare_for_day(home.path(), "2040-01-01", "7").unwrap());
        let conn = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        conn.execute_batch("CREATE TRIGGER reject_second_dream_warm BEFORE INSERT ON idx_consolidated WHEN NEW.event_id=2 BEGIN SELECT RAISE(ABORT, 'forced second Dream Light failure'); END;").unwrap();
        drop(conn);
        assert!(resume_existing_for_day(home.path(), "2040-01-01", "7").is_err());
        let conn = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM idx_episode", [], |r| r.get::<_, i64>(0)).unwrap(), 2);
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM idx_consolidated", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
        assert_eq!(conn.query_row("SELECT state FROM dream_phase_receipt WHERE phase='light'", [], |r| r.get::<_, String>(0)).unwrap(), "prepared");
    }
}
