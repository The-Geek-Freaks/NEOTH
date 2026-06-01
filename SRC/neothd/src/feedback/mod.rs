//! G-03 — operator self-correction signal.
//!
//! When an operator's chat turn reads as a CORRECTION of the preceding reply
//! (the rule-based [`tone`] scorer crosses the negative threshold), record an
//! `OPERATOR_FEEDBACK` (`0xBB`) WAL frame. That frame is the durable,
//! queryable signal — `neoth wal show --type operator_feedback` shows the
//! operator exactly where NEOTH underperformed.
//!
//! This slice ships the PRODUCER (the chat hook) + the durable signal. The
//! adaptation CONSUMER ([`consume`]) reads those `0xBB` frames — aggregating
//! them into a [`consume::FeedbackSummary`] for `neoth feedback summary` and
//! feeding the profile-adapt cron a sustained-pushback self-dev proposal.
//!
//! The prompt text itself is never stored (a `prompt_hash` only) so a
//! feedback frame can't leak message content.

pub mod consume;
pub mod tone;

pub use tone::{NEGATIVE_THRESHOLD, POSITIVE_THRESHOLD, ToneScore, score_follow_up};

use std::path::Path;

use crate::wal::events::EVENT_TYPE_OPERATOR_FEEDBACK;

/// Score `prompt` and, if it reads as operator pushback, emit an
/// `OPERATOR_FEEDBACK` frame. Returns the [`ToneScore`] when a frame was
/// recorded (i.e. the turn was a correction), else `None`.
///
/// Best-effort + fire-and-forget: it NEVER blocks or fails the chat turn. The
/// audit emit mirrors the HF-01 one-shot-writer pattern — if `neothd serve`
/// owns the WAL we skip rather than race the segment.
pub async fn record_operator_correction(home: &Path, prompt: &str) -> Option<ToneScore> {
    let score = score_follow_up(prompt);
    if !score.is_correction() {
        return None;
    }
    let prompt_hash = xxhash_rust::xxh3::xxh3_64(prompt.as_bytes());
    emit_operator_feedback(home, &score, prompt_hash).await;
    Some(score)
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Build the `0xBB` payload. Public-in-crate so a test can assert the shape.
pub(crate) fn feedback_payload(score: &ToneScore, prompt_hash: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "sentiment_score": score.score,
        "matched_patterns": score.matched,
        "prompt_hash": prompt_hash,
        "ts_unix": now_unix(),
    }))
    .unwrap_or_else(|_| b"{}".to_vec())
}

/// Best-effort one-shot WAL emit of the feedback frame (HF-01 pattern).
async fn emit_operator_feedback(home: &Path, score: &ToneScore, prompt_hash: u64) {
    let pidfile = crate::daemon::pidfile::default_pidfile();
    if let Ok(Some(_)) = crate::daemon::pidfile::live_daemon_pid(&pidfile) {
        // The daemon owns the WAL; don't open a 2nd writer and race it.
        tracing::debug!("operator-feedback audit skipped: neothd serve owns the WAL writer");
        return;
    }
    let segment = home.join("wal").join("000001.wal");
    if let Some(parent) = segment.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
    }
    let payload = feedback_payload(score, prompt_hash);
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_OPERATOR_FEEDBACK, &payload).build();
    match crate::wal::spawn(segment) {
        Ok((writer, join)) => {
            if let Err(e) = writer.append(header, payload).await {
                tracing::warn!(error = %e, "operator-feedback audit append failed");
            }
            drop(writer);
            let _ = join.await;
        }
        Err(e) => tracing::warn!(error = %e, "could not spawn one-shot WAL writer for feedback"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_carries_score_and_hash_not_unique_prompt_content() {
        // The payload stores our OWN canonical matched phrases (fine — they
        // are the detector's fixed vocabulary, not operator content) plus a
        // hash. The operator's UNIQUE content must never be stored.
        let prompt = "no, that's wrong — the SECRET_PROJECT budget is off";
        let score = score_follow_up(prompt);
        let bytes = feedback_payload(&score, 0xDEAD_BEEF);
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v["sentiment_score"].as_f64().unwrap() < 0.0);
        assert_eq!(v["prompt_hash"].as_u64().unwrap(), 0xDEAD_BEEF);
        assert!(v["matched_patterns"].is_array());
        let s = String::from_utf8(bytes).unwrap();
        assert!(
            !s.contains("SECRET_PROJECT"),
            "unique operator content must not leak into the feedback frame"
        );
    }

    #[tokio::test]
    async fn neutral_prompt_records_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let r = record_operator_correction(dir.path(), "what time is the meeting?").await;
        assert!(r.is_none(), "a neutral question is not a correction");
    }
}
