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
/// Best-effort + fire-and-forget: it NEVER fails the chat turn. A live daemon
/// receives the frame through the same-user audit RPC; otherwise a
/// collision-free home-bound one-shot writer owns the append.
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
    crate::time::now_unix_i64()
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

/// Best-effort WAL emit of the feedback frame (HF-01 pattern).
async fn emit_operator_feedback(home: &Path, score: &ToneScore, prompt_hash: u64) {
    let pidfile = home.join("neothd.pid");
    match crate::daemon::pidfile::live_daemon_pid(&pidfile) {
        Ok(Some(_)) => {
            let payload = feedback_payload(score, prompt_hash);
            if let Err(error) = crate::daemon::audit_rpc::try_post_audit_frame(
                home,
                EVENT_TYPE_OPERATOR_FEEDBACK,
                &payload,
            )
            .await
            {
                tracing::warn!(
                    %error,
                    "operator-feedback audit could not reach the live daemon"
                );
            }
            return;
        }
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(
                %error,
                path = %pidfile.display(),
                "operator-feedback audit refused an unowned WAL writer"
            );
            return;
        }
    }
    let wal_dir = home.join("wal");
    if std::fs::create_dir_all(&wal_dir).is_err() {
        return;
    }
    let segment = crate::wal::writer::unique_standalone_segment_path(&wal_dir, "operator-feedback");
    let payload = feedback_payload(score, prompt_hash);
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_OPERATOR_FEEDBACK, &payload).build();
    match crate::wal::spawn_for_home(segment, home.to_path_buf()) {
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

    #[tokio::test]
    async fn correction_audit_uses_the_selected_home_and_collision_free_segments() {
        let home = tempfile::tempdir().unwrap();
        for prompt in ["no, that is wrong", "stop, this is incorrect"] {
            assert!(
                record_operator_correction(home.path(), prompt)
                    .await
                    .is_some()
            );
        }

        let wal_dir = home.path().join("wal");
        assert!(wal_dir.join("hmac.key").is_file());
        let segments = std::fs::read_dir(&wal_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "wal"))
            .count();
        assert_eq!(segments, 2, "one-shot feedback writers must not collide");
    }
}
