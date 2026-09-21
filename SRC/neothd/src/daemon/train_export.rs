//! W177 local, provenance-bound training-set export.
//!
//! This module only creates redacted JSONL plus a content-free manifest.  It
//! neither dispatches providers nor changes feedback, WAL, configuration, or
//! transcript state.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::Serialize;

use crate::feedback::response::{read_training_export_candidates, TrainingExportLabel};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrainingSetFormat { Openai, Sharegpt }

impl TrainingSetFormat {
    pub fn parse(value: &str) -> Option<Self> {
        match value { "openai" => Some(Self::Openai), "sharegpt" => Some(Self::Sharegpt), _ => None }
    }
    fn as_str(self) -> &'static str { match self { Self::Openai => "openai", Self::Sharegpt => "sharegpt" } }
}

#[derive(Debug, Default, Serialize)]
pub struct TrainingExportSummary {
    pub format: String,
    pub output_path: String,
    pub manifest_path: String,
    pub exported: usize,
    pub teacher_corrected: usize,
    pub excluded_needs_correction: usize,
    pub excluded_not_helpful: usize,
    pub excluded_unlabelled: usize,
    pub excluded_legacy_unbound: usize,
    pub excluded_missing_source: usize,
    pub excluded_duplicate_binding: usize,
    pub excluded_teacher_ambiguous: usize,
    pub unchanged: bool,
}

#[derive(Default, Serialize)]
struct UsageProvenance {
    events: usize,
    successful: usize,
    failed: usize,
    malformed: usize,
    providers: BTreeMap<String, usize>,
    models: BTreeMap<String, usize>,
    workflows: BTreeMap<String, usize>,
}

#[derive(Serialize)]
struct Manifest<'a> {
    schema_version: u8,
    format: &'a str,
    dataset_sha256: String,
    dataset_bytes: usize,
    exported: usize,
    teacher_corrected: usize,
    excluded_needs_correction: usize,
    excluded_not_helpful: usize,
    excluded_unlabelled: usize,
    excluded_legacy_unbound: usize,
    excluded_missing_source: usize,
    excluded_duplicate_binding: usize,
    excluded_teacher_ambiguous: usize,
    usage: UsageProvenance,
}

struct Pair { operator: String, agent: String }

const MAX_USAGE_FILES: usize = 512;
const MAX_USAGE_FILE_BYTES: u64 = 1_048_576;

pub fn export_training_set(home: &Path, output: &Path, format: TrainingSetFormat) -> Result<TrainingExportSummary> {
    let mut summary = TrainingExportSummary {
        format: format.as_str().to_owned(),
        output_path: output.display().to_string(),
        manifest_path: manifest_path(output)?.display().to_string(),
        ..Default::default()
    };
    let candidates = read_training_export_candidates(home)
        .map_err(|error| anyhow::anyhow!("read training export candidates: {error:?}"))?;
    let mut bindings = BTreeMap::<i64, Vec<String>>::new();
    for candidate in candidates {
        match candidate.label {
            TrainingExportLabel::NeedsCorrection => summary.excluded_needs_correction += 1,
            TrainingExportLabel::NotHelpful => summary.excluded_not_helpful += 1,
            TrainingExportLabel::Unlabelled => summary.excluded_unlabelled += 1,
            TrainingExportLabel::LegacyUnbound => summary.excluded_legacy_unbound += 1,
            TrainingExportLabel::Accepted => match candidate.raw_turn_id {
                Some(id) if id > 0 => bindings.entry(id).or_default().push(candidate.session_id),
                _ => summary.excluded_legacy_unbound += 1,
            },
        }
    }
    let mut accepted = BTreeMap::new();
    for (raw_turn_id, sessions) in bindings {
        if sessions.len() == 1 {
            accepted.insert(raw_turn_id, sessions.into_iter().next().expect("one binding"));
        } else {
            summary.excluded_duplicate_binding += sessions.len();
        }
    }

    let db = home.join("views.db");
    let connection = if accepted.is_empty() || !db.is_file() { None } else {
        Some(Connection::open_with_flags(&db, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)
            .with_context(|| format!("open training transcript source {} read-only", db.display()))?)
    };
    let mut pairs = Vec::new();
    for (raw_turn_id, session_id) in accepted {
        let pair = match connection.as_ref() {
            Some(conn) => exact_adjacent_pair(conn, raw_turn_id, &session_id)
                .context("read exact training pair")?,
            None => None,
        };
        let Some(pair) = pair else {
            summary.excluded_missing_source += 1;
            continue;
        };
        pairs.push(pair);
    }
    let mut source_reply_counts = BTreeMap::<String, usize>::new();
    for pair in &pairs {
        *source_reply_counts.entry(pair.agent.clone()).or_default() += 1;
    }
    let mut lines = Vec::new();
    for pair in pairs {
        let assistant = match teacher_replacement(home, &pair.agent) {
            TeacherResolution::Original => pair.agent,
            TeacherResolution::Corrected(correction)
                if source_reply_counts.get(&pair.agent) == Some(&1) =>
            {
                summary.teacher_corrected += 1;
                correction
            }
            TeacherResolution::Corrected(_) | TeacherResolution::Ambiguous => {
                summary.excluded_teacher_ambiguous += 1;
                continue;
            }
        };
        let operator = crate::security::redact::sanitize_tool_output(&pair.operator);
        let assistant = crate::security::redact::sanitize_tool_output(&assistant);
        lines.push(render_jsonl_line(format, &operator, &assistant)?);
    }
    summary.exported = lines.len();
    let mut dataset = lines.join("\n").into_bytes();
    if !dataset.is_empty() { dataset.push(b'\n'); }
    let manifest = Manifest {
        schema_version: 1, format: format.as_str(), dataset_sha256: sha256(&dataset), dataset_bytes: dataset.len(),
        exported: summary.exported, teacher_corrected: summary.teacher_corrected,
        excluded_needs_correction: summary.excluded_needs_correction, excluded_not_helpful: summary.excluded_not_helpful,
        excluded_unlabelled: summary.excluded_unlabelled, excluded_legacy_unbound: summary.excluded_legacy_unbound,
        excluded_missing_source: summary.excluded_missing_source, excluded_duplicate_binding: summary.excluded_duplicate_binding,
        excluded_teacher_ambiguous: summary.excluded_teacher_ambiguous, usage: usage_provenance(home),
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).context("serialize training export manifest")?;
    let published = publish_pair(output, &dataset, &manifest_bytes)?;
    summary.unchanged = !published;
    Ok(summary)
}

fn exact_adjacent_pair(conn: &Connection, agent_id: i64, session: &str) -> rusqlite::Result<Option<Pair>> {
    conn.query_row(
        "SELECT operator.text, agent.text FROM raw_turns AS agent JOIN raw_turns AS operator \
         ON operator.id = agent.id - 1 AND operator.session_id = agent.session_id AND operator.role = 'operator' \
         WHERE agent.id = ?1 AND agent.session_id = ?2 AND agent.role = 'agent'",
        rusqlite::params![agent_id, session],
        |row| Ok(Pair { operator: row.get(0)?, agent: row.get(1)? }),
    ).optional()
}

enum TeacherResolution {
    Original,
    Corrected(String),
    Ambiguous,
}

fn teacher_replacement(home: &Path, agent: &str) -> TeacherResolution {
    let suffix = format!("teacher_correction_{:016x}", xxhash_rust::xxh3::xxh3_64(agent.as_bytes()));
    let path = home.join("skills").join(&suffix).join("skill.yaml");
    if !path.exists() {
        return TeacherResolution::Original;
    }
    let Ok(body) = std::fs::read_to_string(path) else {
        return TeacherResolution::Ambiguous;
    };
    let Ok(manifest) = serde_yaml::from_str::<crate::skills::schema::SkillManifest>(&body) else {
        return TeacherResolution::Ambiguous;
    };
    if manifest.id != suffix {
        return TeacherResolution::Ambiguous;
    }
    TeacherResolution::Corrected(manifest.system_prompt)
}

fn render_jsonl_line(format: TrainingSetFormat, operator: &str, assistant: &str) -> Result<String> {
    let value = match format {
        TrainingSetFormat::Openai => serde_json::json!({"messages":[{"role":"user","content":operator},{"role":"assistant","content":assistant}]}),
        TrainingSetFormat::Sharegpt => serde_json::json!({"conversations":[{"from":"human","value":operator},{"from":"gpt","value":assistant}]}),
    };
    serde_json::to_string(&value).context("serialize redacted training JSONL record")
}

fn manifest_path(output: &Path) -> Result<PathBuf> {
    let name = output.file_name().context("training export --out must name a file")?.to_string_lossy();
    Ok(output.with_file_name(format!("{name}.manifest.json")))
}

fn publish_pair(output: &Path, dataset: &[u8], manifest: &[u8]) -> Result<bool> {
    let manifest_path = manifest_path(output)?;
    match (output.exists(), manifest_path.exists()) {
        (true, true) => {
            if std::fs::read(output).ok().as_deref() == Some(dataset) && std::fs::read(&manifest_path).ok().as_deref() == Some(manifest) { return Ok(false); }
            anyhow::bail!("training export target pair already exists and differs; refusing overwrite");
        }
        (false, false) => {}
        _ => anyhow::bail!("training export target has an incomplete dataset/manifest pair; refusing overwrite"),
    }
    if let Some(parent) = output.parent().filter(|path| !path.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).with_context(|| format!("create training export parent {}", parent.display()))?;
    }
    let stage_nonce = uuid::Uuid::now_v7();
    let stage_dataset = output.with_file_name(format!(".{}.{}.stage", output.file_name().unwrap().to_string_lossy(), stage_nonce));
    let stage_manifest = manifest_path.with_file_name(format!(".{}.{}.stage", manifest_path.file_name().unwrap().to_string_lossy(), stage_nonce));
    if stage_dataset.exists() || stage_manifest.exists() { anyhow::bail!("training export staging path already exists; refusing overwrite"); }
    crate::util::atomic_write::write_private_create_new(&stage_dataset, dataset)?;
    if let Err(error) = crate::util::atomic_write::write_private_create_new(&stage_manifest, manifest) {
        let _ = crate::util::atomic_write::durable_remove_file(&stage_dataset);
        return Err(error.into());
    }
    let parsed: serde_json::Value = match std::fs::read(&stage_manifest)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    {
        Some(parsed) => parsed,
        None => {
            let _ = crate::util::atomic_write::durable_remove_file(&stage_dataset);
            let _ = crate::util::atomic_write::durable_remove_file(&stage_manifest);
            anyhow::bail!("verify staged training manifest");
        }
    };
    let dataset_sha256 = sha256(dataset);
    if parsed.get("dataset_sha256").and_then(serde_json::Value::as_str) != Some(dataset_sha256.as_str()) {
        let _ = crate::util::atomic_write::durable_remove_file(&stage_dataset);
        let _ = crate::util::atomic_write::durable_remove_file(&stage_manifest);
        anyhow::bail!("staged manifest does not bind staged dataset");
    }
    // This is intentionally a recoverable pair publication, not a fictitious
    // two-file atomic replacement. The verified manifest lands first; a
    // dataset publication failure removes that newly-created manifest, so a
    // previously absent pair stays absent.
    if let Err(error) = crate::util::atomic_write::write_private_create_new(&manifest_path, manifest) {
        let _ = crate::util::atomic_write::durable_remove_file(&stage_dataset);
        let _ = crate::util::atomic_write::durable_remove_file(&stage_manifest);
        return Err(error.into());
    }
    if let Err(error) = crate::util::atomic_write::write_private_create_new(output, dataset) {
        let _ = crate::util::atomic_write::durable_remove_file(&manifest_path);
        let _ = crate::util::atomic_write::durable_remove_file(&stage_dataset);
        let _ = crate::util::atomic_write::durable_remove_file(&stage_manifest);
        return Err(error.into());
    }
    let _ = crate::util::atomic_write::durable_remove_file(&stage_dataset);
    let _ = crate::util::atomic_write::durable_remove_file(&stage_manifest);
    Ok(true)
}

fn usage_provenance(home: &Path) -> UsageProvenance {
    let mut result = UsageProvenance::default();
    let Ok(entries) = std::fs::read_dir(home.join("usage")) else { return result; };
    let mut files: Vec<_> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .collect();
    files.sort();
    if files.len() > MAX_USAGE_FILES {
        result.malformed += files.len() - MAX_USAGE_FILES;
        files.truncate(MAX_USAGE_FILES);
    }
    for file in files {
        let Ok(metadata) = std::fs::metadata(&file) else { result.malformed += 1; continue; };
        if !metadata.is_file() || metadata.len() > MAX_USAGE_FILE_BYTES {
            result.malformed += 1;
            continue;
        }
        let Ok(handle) = std::fs::File::open(&file) else { result.malformed += 1; continue; };
        let mut body = String::new();
        let mut limited = handle.take(MAX_USAGE_FILE_BYTES + 1);
        let Ok(bytes_read) = limited.read_to_string(&mut body) else { result.malformed += 1; continue; };
        if bytes_read as u64 > MAX_USAGE_FILE_BYTES {
            result.malformed += 1;
            continue;
        }
        for line in body.lines().filter(|line| !line.trim().is_empty()) {
            let Ok(event) = serde_json::from_str::<crate::daemon::usage_log::UsageEvent>(line) else { result.malformed += 1; continue; };
            result.events += 1;
            if event.ok { result.successful += 1; } else { result.failed += 1; }
            for (value, bucket) in [
                (Some(event.provider.as_str()), &mut result.providers),
                (Some(event.model.as_str()), &mut result.models),
                (event.call_type.as_deref(), &mut result.workflows),
            ] {
                if let Some(value) = value {
                    *bucket.entry(crate::security::redact::sanitize_tool_output(value)).or_default() += 1;
                }
            }
        }
    }
    result
}

fn sha256(bytes: &[u8]) -> String { use sha2::Digest as _; hex::encode(sha2::Sha256::digest(bytes)) }

#[cfg(test)]
mod tests {
    use super::*;

    fn register_target(
        home: &Path,
        conn: &Connection,
        session_id: &str,
        ts_unix: i64,
        operator: &str,
        agent: &str,
    ) -> (crate::feedback::response::ResponseTargetStatus, i64) {
        crate::memory::transcript_store::insert_turn(
            conn, session_id, "operator", ts_unix, operator,
        )
        .unwrap();
        let receipt = crate::memory::transcript_store::insert_feedback_eligible_agent_turn(
            home, conn, session_id, ts_unix, agent,
        )
        .unwrap();
        let raw_turn_id = receipt.raw_turn_id();
        let target = crate::feedback::response::register_drained_terminal_response_bound(
            home, session_id, false, ts_unix, &receipt,
        )
        .unwrap()
        .unwrap();
        (target, raw_turn_id)
    }

    fn set_signal(
        home: &Path,
        target: &crate::feedback::response::ResponseTargetStatus,
        signal: crate::feedback::response::ResponseSignal,
    ) {
        assert!(matches!(
            crate::feedback::response::apply_response_feedback(
                home,
                &target.response_id,
                &target.session_id,
                target.revision,
                crate::feedback::response::ResponseFeedbackOperation::Set(signal),
                100,
            ),
            Ok(crate::feedback::response::ResponseFeedbackOutcome::Set { .. })
        ));
    }

    #[test]
    fn formats_redaction_and_wire_records_are_closed_and_content_free() {
        assert!(TrainingSetFormat::parse("openai").is_some());
        assert!(TrainingSetFormat::parse("sharegpt").is_some());
        assert!(TrainingSetFormat::parse("jsonl").is_none());
        let assistant = crate::security::redact::sanitize_tool_output(
            "token=sk-abcdefghijklmnopqrstuvwxyz1234567890",
        );
        let openai: serde_json::Value = serde_json::from_str(
            &render_jsonl_line(TrainingSetFormat::Openai, "operator", &assistant).unwrap(),
        )
        .unwrap();
        assert_eq!(openai["messages"][0]["role"], "user");
        assert_eq!(openai["messages"][1]["role"], "assistant");
        assert!(openai.to_string().contains("REDACTED"));
        assert!(openai.get("session_id").is_none());
        assert!(openai.get("raw_turn_id").is_none());

        let sharegpt: serde_json::Value = serde_json::from_str(
            &render_jsonl_line(TrainingSetFormat::Sharegpt, "operator", &assistant).unwrap(),
        )
        .unwrap();
        assert_eq!(sharegpt["conversations"][0]["from"], "human");
        assert_eq!(sharegpt["conversations"][1]["from"], "gpt");
        assert!(sharegpt.to_string().contains("REDACTED"));
        assert!(sharegpt.get("session_id").is_none());
        assert!(sharegpt.get("raw_turn_id").is_none());
    }

    #[test]
    fn bound_feedback_export_counts_every_label_and_redacts_both_formats() {
        use crate::feedback::response::ResponseSignal;

        let root = tempfile::tempdir().unwrap();
        let home = root.path();
        let conn = crate::memory::store::open(home.join("views.db")).unwrap();
        let (accepted, _) = register_target(
            home,
            &conn,
            "accepted",
            1,
            "operator token=sk-abcdefghijklmnopqrstuvwxyz1234567890",
            "draft reply",
        );
        set_signal(home, &accepted, ResponseSignal::Accepted);
        let (needs_correction, _) = register_target(home, &conn, "needs", 2, "question", "reply");
        set_signal(home, &needs_correction, ResponseSignal::NeedsCorrection);
        let (not_helpful, _) = register_target(home, &conn, "negative", 3, "question", "reply");
        set_signal(home, &not_helpful, ResponseSignal::NotHelpful);
        let (_unlabelled, _) = register_target(home, &conn, "unlabelled", 4, "question", "reply");
        let (missing, missing_turn_id) = register_target(home, &conn, "missing", 5, "question", "reply");
        set_signal(home, &missing, ResponseSignal::Accepted);
        conn.execute("DELETE FROM raw_turns WHERE id = ?1", [missing_turn_id]).unwrap();
        let (_legacy, _) = register_target(home, &conn, "legacy", 6, "question", "reply");
        let feedback_path = home.join("feedback").join("response-feedback.json");
        let mut projection: serde_json::Value = serde_json::from_slice(&std::fs::read(&feedback_path).unwrap()).unwrap();
        projection["targets"][5]["raw_turn_id"] = serde_json::Value::Null;
        std::fs::write(&feedback_path, serde_json::to_vec(&projection).unwrap()).unwrap();

        let suffix = format!("teacher_correction_{:016x}", xxhash_rust::xxh3::xxh3_64(b"draft reply"));
        let teacher_dir = home.join("skills").join(&suffix);
        std::fs::create_dir_all(&teacher_dir).unwrap();
        std::fs::write(
            teacher_dir.join("skill.yaml"),
            format!(
                "id: {suffix}\ndescription: test correction\nsystem_prompt: teacher token=sk-abcdefghijklmnopqrstuvwxyz1234567890\n",
            ),
        )
        .unwrap();

        for (format, filename, top_level_key) in [
            (TrainingSetFormat::Openai, "openai.jsonl", "messages"),
            (TrainingSetFormat::Sharegpt, "sharegpt.jsonl", "conversations"),
        ] {
            let output = home.join(filename);
            let summary = export_training_set(home, &output, format).unwrap();
            assert_eq!(summary.exported, 1);
            assert_eq!(summary.teacher_corrected, 1);
            assert_eq!(summary.excluded_needs_correction, 1);
            assert_eq!(summary.excluded_not_helpful, 1);
            assert_eq!(summary.excluded_unlabelled, 1);
            assert_eq!(summary.excluded_legacy_unbound, 1);
            assert_eq!(summary.excluded_missing_source, 1);
            let dataset = std::fs::read_to_string(output).unwrap();
            assert!(dataset.contains(top_level_key));
            assert!(dataset.contains("REDACTED"));
            assert!(!dataset.contains("sk-abcdefghijklmnopqrstuvwxyz1234567890"));
            assert!(!dataset.contains("session_id"));
            assert!(!dataset.contains("raw_turn_id"));
        }
    }

    #[test]
    fn malformed_teacher_manifest_is_ambiguous_and_never_becomes_training_text() {
        let root = tempfile::tempdir().unwrap();
        let reply = "draft reply";
        let suffix = format!("teacher_correction_{:016x}", xxhash_rust::xxh3::xxh3_64(reply.as_bytes()));
        let teacher_dir = root.path().join("skills").join(suffix);
        std::fs::create_dir_all(&teacher_dir).unwrap();
        std::fs::write(teacher_dir.join("skill.yaml"), "id: not-the-bound-correction\n").unwrap();
        assert!(matches!(teacher_replacement(root.path(), reply), TeacherResolution::Ambiguous));
    }

    #[test]
    fn teacher_correction_never_binds_to_multiple_accepted_originals() {
        use crate::feedback::response::ResponseSignal;

        let root = tempfile::tempdir().unwrap();
        let home = root.path();
        let conn = crate::memory::store::open(home.join("views.db")).unwrap();
        for (session, timestamp) in [("one", 1), ("two", 2)] {
            let (target, _) = register_target(home, &conn, session, timestamp, "question", "same reply");
            set_signal(home, &target, ResponseSignal::Accepted);
        }
        let suffix = format!("teacher_correction_{:016x}", xxhash_rust::xxh3::xxh3_64(b"same reply"));
        let teacher_dir = home.join("skills").join(&suffix);
        std::fs::create_dir_all(&teacher_dir).unwrap();
        std::fs::write(
            teacher_dir.join("skill.yaml"),
            format!("id: {suffix}\ndescription: test correction\nsystem_prompt: corrected\n"),
        )
        .unwrap();

        let summary = export_training_set(home, &home.join("set.jsonl"), TrainingSetFormat::Openai).unwrap();
        assert_eq!(summary.exported, 0);
        assert_eq!(summary.teacher_corrected, 0);
        assert_eq!(summary.excluded_teacher_ambiguous, 2);
    }

    #[test]
    fn publication_is_idempotent_and_refuses_an_incomplete_pair() {
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("dataset.jsonl");
        let dataset = b"{\"messages\":[]}\n";
        let manifest = format!("{{\"dataset_sha256\":\"{}\"}}", sha256(dataset)).into_bytes();
        assert!(publish_pair(&output, dataset, &manifest).unwrap());
        assert!(!publish_pair(&output, dataset, &manifest).unwrap());
        std::fs::remove_file(manifest_path(&output).unwrap()).unwrap();
        assert!(publish_pair(&output, dataset, &manifest).is_err());
        assert_eq!(std::fs::read(&output).unwrap(), dataset);
    }
}
