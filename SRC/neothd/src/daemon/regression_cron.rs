//! ADV-14 — longitudinal recall-regression anchor daemon cron.
//!
//! At cutover an operator captures a small ANCHOR set: for each of a handful of
//! representative queries, the L2-normalised embedding of the answer NEOTH gave
//! then (`~/.neoth/eval/regression_anchor.jsonl`, one `{query, anchor_vector}`
//! per line). This cron — when `freedom.yaml::regression_anchor.enabled` — runs
//! weekly: it re-asks each anchor query through the configured provider,
//! embeds the fresh answer, and compares cosine-to-anchor. An answer whose
//! cosine drops STRICTLY BELOW `threshold` (default 0.70) is durable evidence
//! that the model's response to a known query drifted after a model/config
//! change — emitted as a `0x3F REGRESSION_ALERT` WAL frame.
//!
//! ## Design (grooved cron recipe — mirrors [`super::drift_alert_cron`])
//! A pure, unit-testable core ([`evaluate_regression`]) + a tolerant loader
//! ([`load_anchors`]) + the I/O tick ([`run_regression_tick`], which does the
//! re-ask/re-embed) + [`spawn_regression_cron_loop`] that returns `None` when
//! disabled (no idle tokio task for the default-OFF case). Like the
//! drift-alert cron, a frame is emitted ONLY for an actual regression, so
//! `neoth wal show --type regression_alert` is a clean, operator-actionable
//! signal — not "still fine" noise.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::config::RegressionAnchorConfig;
use crate::providers::embed::{EmbedProvider, EmbedRequest, cosine};
use crate::providers::{Provider, Request};
use crate::wal::writer::WalWriterHandle;

/// One captured anchor: a query + the L2-normalised embedding of the answer
/// NEOTH gave at cutover. Stored one-per-line in
/// `~/.neoth/eval/regression_anchor.jsonl`. The vector MUST be L2-normalised
/// (it comes straight from an `EmbedResponse::vector`, which is) so cosine =
/// dot product against the equally-normalised fresh embedding.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct RegressionAnchor {
    pub query: String,
    pub anchor_vector: Vec<f32>,
}

/// One flagged regression: the anchor query whose fresh answer drifted, with
/// the cosine score that fell below the threshold.
#[derive(Debug, Clone, PartialEq)]
pub struct RegressionAlert {
    pub query: String,
    pub cosine: f32,
}

/// Default anchor file location under the neoth home.
pub fn anchor_path(home: &Path) -> PathBuf {
    home.join("eval").join("regression_anchor.jsonl")
}

/// Load anchors from a JSONL file (one [`RegressionAnchor`] per line).
/// Tolerant: a missing file → empty (no anchors → no alerts); blank or garbled
/// lines + entries with an empty query / empty vector are skipped. Never
/// panics — a malformed anchor file degrades to "no regression check", never a
/// crash.
pub fn load_anchors(path: &Path) -> Vec<RegressionAnchor> {
    let Ok(body) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    body.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<RegressionAnchor>(l).ok())
        .filter(|a| !a.query.trim().is_empty() && !a.anchor_vector.is_empty())
        .collect()
}

/// PURE core: pair each anchor with the freshly-embedded current vector at the
/// SAME index, and flag those whose cosine to the anchor vector is STRICTLY
/// below `threshold`. A dim mismatch yields cosine `0.0` (via the shared
/// [`cosine`] helper) → flagged — the correct conservative signal (a different
/// embed model can't be silently treated as "no regression").
pub fn evaluate_regression(
    anchors: &[RegressionAnchor],
    current_vectors: &[Vec<f32>],
    threshold: f32,
) -> Vec<RegressionAlert> {
    anchors
        .iter()
        .zip(current_vectors)
        .filter_map(|(anchor, current)| {
            let c = cosine(&anchor.anchor_vector, current);
            (c < threshold).then(|| RegressionAlert {
                query: anchor.query.clone(),
                cosine: c,
            })
        })
        .collect()
}

/// One regression cron pass. Loads anchors, re-asks each query through
/// `provider`, embeds the fresh answer via `embed`, evaluates cosine-vs-anchor,
/// and emits a `0x3F REGRESSION_ALERT` per flagged anchor. Returns the alerts.
///
/// Best-effort per anchor: a provider OR embed error on one anchor is logged
/// and that anchor is SKIPPED (not flagged) — a transient failure isn't a
/// regression, and flagging it would cry wolf.
pub async fn run_regression_tick(
    home: &Path,
    config: &RegressionAnchorConfig,
    provider: &crate::providers::cost_authorization::AuthorizedProvider,
    embed: &dyn EmbedProvider,
    writer: &WalWriterHandle,
) -> Result<Vec<RegressionAlert>, String> {
    let anchors = load_anchors(&anchor_path(home));
    if anchors.is_empty() {
        tracing::debug!("regression cron: no anchors, skipping tick");
        return Ok(Vec::new());
    }

    // Re-ask + re-embed each anchor query. Failures skip that anchor.
    let mut anchors_ok: Vec<RegressionAnchor> = Vec::new();
    let mut current_vectors: Vec<Vec<f32>> = Vec::new();
    for anchor in &anchors {
        let req = Request {
            prompt: anchor.query.clone(),
            ..Default::default()
        };
        let completion = match provider.complete(req).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(query = %anchor.query, error = %e, "regression: provider failed; skipping anchor");
                continue;
            }
        };
        let response = match embed.embed(EmbedRequest::new(completion.text)).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(query = %anchor.query, error = %e, "regression: embed failed; skipping anchor");
                continue;
            }
        };
        anchors_ok.push(anchor.clone());
        current_vectors.push(response.vector);
    }

    let alerts = evaluate_regression(&anchors_ok, &current_vectors, config.threshold);

    let ts_unix = crate::time::now_unix_i64();
    for alert in &alerts {
        let payload = serde_json::to_vec(&serde_json::json!({
            "query": alert.query,
            "cosine": alert.cosine,
            "threshold": config.threshold,
            "ts_unix": ts_unix,
        }))
        .map_err(|e| format!("serialize regression payload: {e}"))?;
        let header = crate::wal::HeaderBuilder::new(
            crate::wal::events::EVENT_TYPE_REGRESSION_ALERT,
            &payload,
        )
        .flags(crate::wal::EventFlags::SYNTHETIC)
        .build();
        writer
            .append(header, payload)
            .await
            .map_err(|e| format!("wal append: {e}"))?;
        tracing::warn!(
            query = %alert.query,
            cosine = alert.cosine,
            threshold = config.threshold,
            "regression alert: recall answer drifted from cutover anchor — review the model/config change",
        );
    }
    Ok(alerts)
}

/// Spawn the regression cron loop. Returns the `JoinHandle` so the daemon
/// tracks it; `None` when `config.enabled == false` (the default) so opt-out
/// operators carry no idle tokio task. Weekly by default; the interval is
/// clamped to a 60s floor by [`RegressionAnchorConfig::interval_duration`].
pub fn spawn_regression_cron_loop(
    config: RegressionAnchorConfig,
    home: PathBuf,
    provider: Arc<crate::providers::cost_authorization::AuthorizedProvider>,
    embed: Arc<dyn EmbedProvider>,
    writer: WalWriterHandle,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.enabled {
        tracing::info!("regression cron disabled in config (regression_anchor.enabled = false)");
        return None;
    }
    let interval = config.interval_duration();
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = interval.as_secs(),
            threshold = config.threshold,
            "regression cron loop online (ADV-14)",
        );
        loop {
            ticker.tick().await;
            match run_regression_tick(&home, &config, provider.as_ref(), embed.as_ref(), &writer)
                .await
            {
                Ok(alerts) if !alerts.is_empty() => tracing::warn!(
                    count = alerts.len(),
                    "regression cron: emitted REGRESSION_ALERT frame(s)",
                ),
                Ok(_) => tracing::debug!("regression cron: no regressions this tick"),
                Err(e) => tracing::error!(error = %e, "regression tick failed"),
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::Completion;
    use crate::providers::embed::EmbedResponse;
    use crate::wal::events::EVENT_TYPE_REGRESSION_ALERT;

    fn authorized(
        provider: impl Provider + 'static,
    ) -> crate::providers::cost_authorization::AuthorizedProvider {
        crate::providers::cost_authorization::AuthorizedProvider::from_arc(
            Arc::new(provider),
            crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
                crate::permissions::AutonomyLevel::Full,
            ),
            Some("mock".to_string()),
            "regression.test",
        )
    }
    use async_trait::async_trait;
    use std::time::Duration;

    fn anchor(query: &str, v: Vec<f32>) -> RegressionAnchor {
        RegressionAnchor {
            query: query.into(),
            anchor_vector: v,
        }
    }

    #[test]
    fn evaluate_flags_only_below_threshold() {
        let anchors = vec![
            anchor("q-stable", vec![1.0, 0.0, 0.0]),
            anchor("q-drifted", vec![1.0, 0.0, 0.0]),
        ];
        let current = vec![
            vec![1.0, 0.0, 0.0], // cosine 1.0 — stable, no alert
            vec![0.0, 1.0, 0.0], // cosine 0.0 — drifted, alert
        ];
        let alerts = evaluate_regression(&anchors, &current, 0.70);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].query, "q-drifted");
        assert!(alerts[0].cosine < 0.70);
    }

    #[test]
    fn evaluate_dim_mismatch_flags_conservatively() {
        // Different embed model (dim 2 vs 3) ⇒ cosine 0.0 ⇒ flagged, never
        // silently treated as "no regression".
        let anchors = vec![anchor("q", vec![1.0, 0.0, 0.0])];
        let current = vec![vec![1.0, 0.0]];
        assert_eq!(evaluate_regression(&anchors, &current, 0.70).len(), 1);
    }

    #[test]
    fn load_anchors_is_tolerant() {
        // Missing file → empty.
        let missing = std::path::Path::new("/no/such/regression_anchor.jsonl");
        assert!(load_anchors(missing).is_empty());

        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.jsonl");
        std::fs::write(
            &p,
            "{\"query\":\"q1\",\"anchor_vector\":[1.0,0.0]}\n\
             \n\
             not json at all\n\
             {\"query\":\"\",\"anchor_vector\":[1.0]}\n\
             {\"query\":\"q2\",\"anchor_vector\":[]}\n\
             {\"query\":\"q3\",\"anchor_vector\":[0.0,1.0]}\n",
        )
        .unwrap();
        let anchors = load_anchors(&p);
        // q1 + q3 only (blank line, bad json, empty-query, empty-vector dropped).
        assert_eq!(anchors.len(), 2);
        assert_eq!(anchors[0].query, "q1");
        assert_eq!(anchors[1].query, "q3");
    }

    #[test]
    fn default_interval_is_weekly() {
        assert_eq!(
            RegressionAnchorConfig::default().interval_secs,
            7 * 24 * 3600
        );
        assert_eq!(
            crate::config::DEFAULT_REGRESSION_INTERVAL_SECS,
            7 * 24 * 3600
        );
    }

    // ── mock provider + embed for the emit-site tick test ────────────────────

    struct MockProvider {
        reply: &'static str,
    }
    #[async_trait]
    impl Provider for MockProvider {
        fn name(&self) -> &'static str {
            "mock"
        }
        async fn complete(&self, _req: Request) -> anyhow::Result<Completion> {
            Ok(Completion {
                termination: Default::default(),
                text: self.reply.into(),
                identity: Default::default(),
                model: "mock".into(),
                latency: Duration::from_millis(1),
                input_tokens: None,
                output_tokens: None,
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
    }

    struct MockEmbed {
        vector: Vec<f32>,
    }
    #[async_trait]
    impl EmbedProvider for MockEmbed {
        fn name(&self) -> &'static str {
            "mock-embed"
        }
        fn default_dim(&self) -> usize {
            self.vector.len()
        }
        async fn embed(&self, _req: EmbedRequest) -> anyhow::Result<EmbedResponse> {
            Ok(EmbedResponse {
                vector: self.vector.clone(),
                model: "mock-embed".into(),
                latency: Duration::from_millis(1),
            })
        }
    }

    fn count_regression_frames(seg: &std::path::Path) -> usize {
        let Ok(bytes) = std::fs::read(seg) else {
            return 0;
        };
        let Ok(hdr) = crate::wal::segment_header::parse_segment_header(&bytes) else {
            return 0;
        };
        let mut cursor = hdr.header_len();
        let mut count = 0usize;
        while cursor < bytes.len() {
            let dec = match crate::wal::frame::decode_frame(&bytes[cursor..]) {
                Ok(d) => d,
                Err(_) => break,
            };
            if dec.header.event_type == EVENT_TYPE_REGRESSION_ALERT {
                count += 1;
            }
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        count
    }

    #[tokio::test]
    async fn tick_emits_alert_when_answer_drifts() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(anchor_path(home.path()).parent().unwrap()).unwrap();
        // Anchor vector points one way; the mock embed returns the orthogonal
        // vector ⇒ cosine 0.0 < 0.70 ⇒ regression.
        std::fs::write(
            anchor_path(home.path()),
            "{\"query\":\"what is your name?\",\"anchor_vector\":[1.0,0.0]}\n",
        )
        .unwrap();
        let seg_dir = tempfile::tempdir().unwrap();
        let seg = seg_dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();

        let provider = authorized(MockProvider {
            reply: "I am something else now",
        });
        let embed = MockEmbed {
            vector: vec![0.0, 1.0],
        };
        let cfg = RegressionAnchorConfig {
            enabled: true,
            threshold: 0.70,
            interval_secs: crate::config::DEFAULT_REGRESSION_INTERVAL_SECS,
        };
        let alerts = run_regression_tick(home.path(), &cfg, &provider, &embed, &writer)
            .await
            .expect("tick ok");
        assert_eq!(alerts.len(), 1, "orthogonal answer must flag a regression");

        drop(writer);
        join.await.ok();
        assert_eq!(count_regression_frames(&seg), 1, "exactly one 0x3F frame");
    }

    #[tokio::test]
    async fn tick_no_alert_when_answer_stable() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(anchor_path(home.path()).parent().unwrap()).unwrap();
        std::fs::write(
            anchor_path(home.path()),
            "{\"query\":\"q\",\"anchor_vector\":[1.0,0.0]}\n",
        )
        .unwrap();
        let seg_dir = tempfile::tempdir().unwrap();
        let seg = seg_dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        // Mock embed returns the SAME direction ⇒ cosine 1.0 ⇒ no regression.
        let provider = authorized(MockProvider {
            reply: "same as before",
        });
        let embed = MockEmbed {
            vector: vec![1.0, 0.0],
        };
        let cfg = RegressionAnchorConfig {
            enabled: true,
            threshold: 0.70,
            interval_secs: crate::config::DEFAULT_REGRESSION_INTERVAL_SECS,
        };
        let alerts = run_regression_tick(home.path(), &cfg, &provider, &embed, &writer)
            .await
            .unwrap();
        assert!(alerts.is_empty(), "stable answer ⇒ no alert");
        drop(writer);
        join.await.ok();
        assert_eq!(count_regression_frames(&seg), 0);
    }

    #[tokio::test]
    async fn spawn_returns_none_when_disabled() {
        let home = tempfile::tempdir().unwrap();
        let seg_dir = tempfile::tempdir().unwrap();
        let seg = seg_dir.path().join("000001.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg).unwrap();
        let provider = Arc::new(authorized(MockProvider { reply: "x" }));
        let embed: Arc<dyn EmbedProvider> = Arc::new(MockEmbed { vector: vec![1.0] });
        let cfg = RegressionAnchorConfig {
            enabled: false,
            ..Default::default()
        };
        let handle =
            spawn_regression_cron_loop(cfg, home.path().to_path_buf(), provider, embed, writer);
        assert!(handle.is_none());
    }
}
