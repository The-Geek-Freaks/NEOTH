//! Read-only provider/capability operational quality observation.
//!
//! This is deliberately an observation, not a router input.  It reads only a
//! complete authenticated terminal-WAL prefix and derives short-window failure
//! and latency signals for one exact provider/model/closed workflow identity.
//! Terminal success says that an adapter completed a call; it says nothing
//! about factuality, usefulness, or reasoning quality.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;

use anyhow::{Context, Result};

use crate::daemon::usage_log::{WorkflowKey, WorkflowKind};
use crate::wal::events::{EVENT_TYPE_PROVIDER_ERROR, EVENT_TYPE_PROVIDER_RESPONSE};

pub(crate) const RECENT_WINDOW_SECONDS: i64 = 24 * 60 * 60;
pub(crate) const BASELINE_WINDOW_SECONDS: i64 = 7 * 24 * 60 * 60;
pub(crate) const MIN_RECENT_SAMPLES: u64 = 8;
pub(crate) const MIN_BASELINE_SAMPLES: u64 = 12;
const MAX_RETAINED_SAMPLES: usize = 4_096;
const MAX_IDENTITIES: usize = 128;
pub(crate) const MAX_RENDERED_DEGRADATIONS: usize = 4;

const CAPABILITY_DOCTOR_SCAN_LIMITS: crate::wal::scan::HomeWalScanLimits =
    crate::wal::scan::HomeWalScanLimits {
        max_directory_entries: 256,
        max_segments: 128,
        max_segment_physical_bytes: 8 * 1024 * 1024,
        max_total_physical_bytes: 32 * 1024 * 1024,
        max_segment_logical_bytes: 16 * 1024 * 1024,
        max_total_logical_bytes: 64 * 1024 * 1024,
    };

#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub(crate) struct CapabilityIdentity {
    pub(crate) provider: String,
    pub(crate) model: String,
    pub(crate) workflow: WorkflowKey,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct WindowSamples {
    completed: u64,
    failed: u64,
    latencies: Vec<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CapabilityTrend {
    Stable,
    Degrading,
    Recovering,
    InsufficientSamples,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CapabilityObservation {
    pub(crate) identity: CapabilityIdentity,
    pub(crate) trend: CapabilityTrend,
    pub(crate) recent_samples: u64,
    pub(crate) baseline_samples: u64,
    pub(crate) recent_failures: u64,
    pub(crate) baseline_failures: u64,
    pub(crate) recent_p90_latency_ms: u64,
    pub(crate) baseline_p90_latency_ms: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CapabilityDecayReport {
    pub(crate) observations: Vec<CapabilityObservation>,
    /// Authenticated provider terminal rows that lack a closed current
    /// capability triple. They must remain visible rather than being assigned
    /// to a present-day route.
    pub(crate) unattributed_terminal_rows: u64,
    /// Old terminal rows that predate the projection schema. They are not
    /// evidence for this slice, because their unique terminal identity and
    /// provenance contract are unavailable.
    pub(crate) legacy_terminal_rows: u64,
}

#[derive(Clone, Debug)]
struct TerminalSample {
    identity: CapabilityIdentity,
    ts_unix: i64,
    ok: bool,
    latency_ms: u64,
    invocation_id: String,
}

/// Read a bounded, authenticated, complete home-WAL prefix. The scan helper
/// owns directory/file identity validation and its physical/logical byte caps.
/// A partial prefix is refused; Doctor must never present it as a whole window.
pub(crate) fn inspect_authenticated_terminal_history(
    home: &Path,
    now_unix: i64,
) -> Result<CapabilityDecayReport> {
    anyhow::ensure!(
        now_unix >= 0,
        "capability observation clock is before Unix epoch"
    );
    let mut samples = Vec::new();
    let mut unattributed_terminal_rows = 0u64;
    let mut legacy_terminal_rows = 0u64;
    let mut invocation_ids = HashSet::new();
    let mut identities = BTreeSet::new();
    let recent_since = now_unix
        .checked_sub(RECENT_WINDOW_SECONDS)
        .context("capability recent window underflow")?;
    let baseline_since = recent_since
        .checked_sub(BASELINE_WINDOW_SECONDS)
        .context("capability baseline window underflow")?;
    let scan = crate::wal::scan::for_each_authenticated_prefix_frame_at_home(
        home,
        CAPABILITY_DOCTOR_SCAN_LIMITS,
        |_, frame| {
            if !matches!(
                frame.header.event_type,
                EVENT_TYPE_PROVIDER_RESPONSE | EVENT_TYPE_PROVIDER_ERROR
            ) {
                return Ok(());
            }
            match terminal_sample_from_payload(frame.header.event_type, frame.payload)? {
                TerminalPayload::Legacy => {
                    legacy_terminal_rows = legacy_terminal_rows
                        .checked_add(1)
                        .context("capability legacy terminal counter overflow")?;
                }
                TerminalPayload::Unattributed => {
                    unattributed_terminal_rows = unattributed_terminal_rows
                        .checked_add(1)
                        .context("capability unattributed terminal counter overflow")?;
                }
                TerminalPayload::Sample(sample) => {
                    anyhow::ensure!(
                        sample.ts_unix <= now_unix,
                        "provider terminal observation is in the future"
                    );
                    if sample.ts_unix < baseline_since {
                        return Ok(());
                    }
                    anyhow::ensure!(
                        samples.len() < MAX_RETAINED_SAMPLES,
                        "capability observation exceeds the {MAX_RETAINED_SAMPLES}-sample limit"
                    );
                    if identities.insert(sample.identity.clone()) {
                        anyhow::ensure!(
                            identities.len() <= MAX_IDENTITIES,
                            "capability observation exceeds the {MAX_IDENTITIES}-identity limit"
                        );
                    }
                    anyhow::ensure!(
                        invocation_ids.insert(sample.invocation_id.clone()),
                        "duplicate provider terminal invocation in authenticated history"
                    );
                    samples.push(sample);
                }
            }
            Ok(())
        },
    )
    .context("scan authenticated complete home WAL for capability quality")?;
    anyhow::ensure!(
        scan.complete,
        "capability observation refuses an incomplete authenticated home WAL prefix"
    );
    derive_report(
        samples,
        now_unix,
        unattributed_terminal_rows,
        legacy_terminal_rows,
    )
}

enum TerminalPayload {
    Legacy,
    Unattributed,
    Sample(TerminalSample),
}

fn terminal_sample_from_payload(event_type: u8, payload: &[u8]) -> Result<TerminalPayload> {
    let value: serde_json::Value =
        serde_json::from_slice(payload).context("decode provider terminal observation payload")?;
    if value
        .get("usage_projection_schema")
        .and_then(serde_json::Value::as_str)
        != Some("neoth.provider-usage.v2")
    {
        return Ok(TerminalPayload::Legacy);
    }
    let invocation_id = required_string(&value, "invocation_id")?;
    anyhow::ensure!(
        invocation_id.len() == 64 && invocation_id.bytes().all(is_lower_hex),
        "provider terminal invocation id is not canonical SHA-256 hex"
    );
    let provider = required_string(&value, "provider")?;
    let model = value
        .get("wire_model")
        .and_then(serde_json::Value::as_str)
        .or_else(|| value.get("model").and_then(serde_json::Value::as_str))
        .filter(|value| !value.is_empty())
        .context("provider terminal omits wire model")?;
    if !is_safe_operator_label(provider) || !is_safe_operator_label(model) {
        return Ok(TerminalPayload::Unattributed);
    }
    let ts_unix = value
        .get("ts_unix")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| i64::try_from(value).ok())
        .context("provider terminal omits valid timestamp")?;
    let latency_ms = value
        .get("latency_ms")
        .and_then(serde_json::Value::as_u64)
        .or_else(|| {
            value
                .get("latency_ns")
                .and_then(serde_json::Value::as_u64)
                .map(|value| value / 1_000_000)
        })
        .context("provider terminal omits latency")?;
    let ok = value
        .get("ok")
        .and_then(serde_json::Value::as_bool)
        .context("provider terminal omits ok")?;
    anyhow::ensure!(
        (event_type == EVENT_TYPE_PROVIDER_RESPONSE && ok)
            || (event_type == EVENT_TYPE_PROVIDER_ERROR && !ok),
        "provider terminal event type conflicts with terminal outcome"
    );
    let workflow = WorkflowKey::from_audited(
        value.get("call_scope").and_then(serde_json::Value::as_str),
        value.get("source").and_then(serde_json::Value::as_str),
        value.get("call_type").and_then(serde_json::Value::as_str),
    );
    if workflow.0 == WorkflowKind::Unclassified {
        return Ok(TerminalPayload::Unattributed);
    }
    Ok(TerminalPayload::Sample(TerminalSample {
        identity: CapabilityIdentity {
            provider: provider.to_owned(),
            model: model.to_owned(),
            workflow,
        },
        ts_unix,
        ok,
        latency_ms,
        invocation_id: invocation_id.to_owned(),
    }))
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit())
}

fn is_safe_operator_label(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

fn required_string<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("provider terminal omits non-empty {field}"))
}

fn derive_report(
    samples: Vec<TerminalSample>,
    now_unix: i64,
    unattributed_terminal_rows: u64,
    legacy_terminal_rows: u64,
) -> Result<CapabilityDecayReport> {
    let recent_since = now_unix
        .checked_sub(RECENT_WINDOW_SECONDS)
        .context("capability recent window underflow")?;
    let baseline_since = recent_since
        .checked_sub(BASELINE_WINDOW_SECONDS)
        .context("capability baseline window underflow")?;
    let mut by_identity = BTreeMap::<CapabilityIdentity, (WindowSamples, WindowSamples)>::new();
    for sample in samples {
        anyhow::ensure!(
            sample.ts_unix <= now_unix,
            "provider terminal observation is in the future"
        );
        let window = if sample.ts_unix >= recent_since {
            0
        } else if sample.ts_unix >= baseline_since {
            1
        } else {
            continue;
        };
        let entry = by_identity.entry(sample.identity).or_default();
        let target = if window == 0 {
            &mut entry.0
        } else {
            &mut entry.1
        };
        target.completed = target
            .completed
            .checked_add(1)
            .context("capability sample counter overflow")?;
        if !sample.ok {
            target.failed = target
                .failed
                .checked_add(1)
                .context("capability failure counter overflow")?;
        }
        target.latencies.push(sample.latency_ms);
    }
    let observations = by_identity
        .into_iter()
        .map(|(identity, (recent, baseline))| {
            let recent_p90_latency_ms = p90(&recent.latencies);
            let baseline_p90_latency_ms = p90(&baseline.latencies);
            CapabilityObservation {
                identity,
                trend: classify(
                    &recent,
                    &baseline,
                    recent_p90_latency_ms,
                    baseline_p90_latency_ms,
                ),
                recent_samples: recent.completed,
                baseline_samples: baseline.completed,
                recent_failures: recent.failed,
                baseline_failures: baseline.failed,
                recent_p90_latency_ms,
                baseline_p90_latency_ms,
            }
        })
        .collect();
    Ok(CapabilityDecayReport {
        observations,
        unattributed_terminal_rows,
        legacy_terminal_rows,
    })
}

fn p90(samples: &[u64]) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let p90_index = (sorted.len().saturating_mul(90).saturating_add(99) / 100).saturating_sub(1);
    sorted[p90_index]
}

fn classify(
    recent: &WindowSamples,
    baseline: &WindowSamples,
    recent_p90: u64,
    baseline_p90: u64,
) -> CapabilityTrend {
    if recent.completed < MIN_RECENT_SAMPLES || baseline.completed < MIN_BASELINE_SAMPLES {
        return CapabilityTrend::InsufficientSamples;
    }
    let recent_failure_ppm = recent.failed.saturating_mul(1_000_000) / recent.completed;
    let baseline_failure_ppm = baseline.failed.saturating_mul(1_000_000) / baseline.completed;
    let failure_degrading = recent_failure_ppm >= 200_000
        && recent_failure_ppm >= baseline_failure_ppm.saturating_add(150_000);
    let latency_degrading = recent_p90 >= baseline_p90.saturating_add(250)
        && recent_p90 >= baseline_p90.saturating_mul(175) / 100;
    if failure_degrading || latency_degrading {
        return CapabilityTrend::Degrading;
    }
    let failure_recovering = baseline_failure_ppm >= 200_000
        && recent_failure_ppm <= 50_000
        && recent_failure_ppm.saturating_add(150_000) <= baseline_failure_ppm;
    let latency_recovering =
        baseline_p90 >= 500 && recent_p90.saturating_mul(100) <= baseline_p90.saturating_mul(60);
    if failure_recovering || latency_recovering {
        CapabilityTrend::Recovering
    } else {
        CapabilityTrend::Stable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    use crate::wal::writer::WalWriterHandle;

    async fn ready_authenticated_writer(
        home: &Path,
    ) -> (
        std::path::PathBuf,
        WalWriterHandle,
        tokio::task::JoinHandle<std::result::Result<(), String>>,
    ) {
        let wal = home.join("wal");
        std::fs::create_dir_all(&wal).expect("create test home WAL directory");
        let segment = wal.join("000001.wal");
        let (writer, join, ready) =
            crate::wal::writer::spawn_for_home_ready(segment.clone(), home.to_path_buf())
                .expect("spawn authenticated home WAL writer");
        ready
            .wait()
            .await
            .expect("initialize authenticated home WAL writer");
        (segment, writer, join)
    }

    fn producer_terminal_payload(invocation: u8, ts_unix: i64, ok: bool) -> Vec<u8> {
        let mut payload = serde_json::json!({
            "schema": "neoth.provider-lifecycle.v1",
            "usage_projection_schema": "neoth.provider-usage.v2",
            "invocation_id": format!("{invocation:064x}"),
            "request_binding_sha256": "1".repeat(64),
            "call_scope": "chat_provider_round",
            "provider": "openai_api",
            "wire_model": "gpt-5",
            "model": "gpt-5",
            "streaming": false,
            "automated": false,
            "ts_unix": ts_unix,
            "ok": ok,
            "latency_ms": 100,
            "source": "chat",
            "call_type": "chat_provider_round",
        });
        let object = payload
            .as_object_mut()
            .expect("provider terminal fixture must be an object");
        if ok {
            object.insert("terminal_kind".into(), "complete".into());
        } else {
            object.insert("error_kind".into(), "transport".into());
        }
        serde_json::to_vec(&payload).expect("encode current provider terminal payload")
    }

    async fn append_provider_terminal(
        writer: &WalWriterHandle,
        invocation: u8,
        ts_unix: i64,
        ok: bool,
    ) {
        let payload = producer_terminal_payload(invocation, ts_unix, ok);
        let event_type = if ok {
            EVENT_TYPE_PROVIDER_RESPONSE
        } else {
            EVENT_TYPE_PROVIDER_ERROR
        };
        writer
            .append_authenticated(
                crate::wal::HeaderBuilder::new(event_type, &payload).build(),
                payload,
            )
            .await
            .expect("append authenticated provider terminal fixture");
    }

    fn sample(
        provider: &str,
        workflow: WorkflowKind,
        ts_unix: i64,
        ok: bool,
        latency_ms: u64,
        invocation: u8,
    ) -> TerminalSample {
        TerminalSample {
            identity: CapabilityIdentity {
                provider: provider.into(),
                model: "m".into(),
                workflow: WorkflowKey(workflow),
            },
            ts_unix,
            ok,
            latency_ms,
            invocation_id: format!("{invocation:064x}"),
        }
    }

    #[test]
    fn min_samples_keep_each_identity_inconclusive() {
        let now = 10 * 86_400;
        let rows = (0..7)
            .map(|id| sample("a", WorkflowKind::ChatTurn, now - 10, true, 10, id))
            .collect();
        let report = derive_report(rows, now, 0, 0).unwrap();
        assert_eq!(
            report.observations[0].trend,
            CapabilityTrend::InsufficientSamples
        );
    }

    #[test]
    fn regression_and_recovery_require_separate_conservative_windows() {
        let now = crate::time::now_unix_i64();
        let mut degrading = Vec::new();
        for id in 0..12 {
            degrading.push(sample(
                "a",
                WorkflowKind::ChatTurn,
                now - RECENT_WINDOW_SECONDS - 10,
                true,
                100,
                id,
            ));
        }
        for id in 20..28 {
            degrading.push(sample(
                "a",
                WorkflowKind::ChatTurn,
                now - 10,
                id % 2 == 0,
                800,
                id,
            ));
        }
        assert_eq!(
            derive_report(degrading, now, 0, 0).unwrap().observations[0].trend,
            CapabilityTrend::Degrading
        );
        let mut recovering = Vec::new();
        for id in 0..12 {
            recovering.push(sample(
                "a",
                WorkflowKind::ChatTurn,
                now - RECENT_WINDOW_SECONDS - 10,
                id % 2 == 0,
                900,
                id,
            ));
        }
        for id in 20..28 {
            recovering.push(sample("a", WorkflowKind::ChatTurn, now - 10, true, 100, id));
        }
        assert_eq!(
            derive_report(recovering, now, 0, 0).unwrap().observations[0].trend,
            CapabilityTrend::Recovering
        );
    }

    #[test]
    fn provider_and_capability_never_share_a_window() {
        let now = crate::time::now_unix_i64();
        let mut rows = Vec::new();
        for id in 0..12 {
            rows.push(sample(
                "a",
                WorkflowKind::ChatTurn,
                now - RECENT_WINDOW_SECONDS - 10,
                true,
                100,
                id,
            ));
            rows.push(sample(
                "b",
                WorkflowKind::DeepResearch,
                now - RECENT_WINDOW_SECONDS - 10,
                true,
                100,
                id + 30,
            ));
        }
        for id in 60..68 {
            rows.push(sample(
                "a",
                WorkflowKind::ChatTurn,
                now - 10,
                false,
                900,
                id,
            ));
            rows.push(sample(
                "b",
                WorkflowKind::DeepResearch,
                now - 10,
                true,
                100,
                id + 30,
            ));
        }
        let report = derive_report(rows, now, 0, 0).unwrap();
        assert_eq!(report.observations.len(), 2);
        assert!(report.observations.iter().any(|row| {
            row.identity.provider == "a" && row.trend == CapabilityTrend::Degrading
        }));
        assert!(
            report.observations.iter().any(|row| {
                row.identity.provider == "b" && row.trend == CapabilityTrend::Stable
            })
        );
    }

    #[test]
    fn malformed_or_unattributed_terminal_payload_never_becomes_quality_evidence() {
        let payload = serde_json::json!({
            "usage_projection_schema": "neoth.provider-usage.v2",
            "invocation_id": "0000000000000000000000000000000000000000000000000000000000000000",
            "provider": "a",
            "wire_model": "m",
            "ts_unix": 1,
            "latency_ms": 1,
            "ok": true,
            "call_scope": "unknown",
            "source": "unknown",
            "call_type": "unknown",
        });
        assert!(matches!(
            terminal_sample_from_payload(
                EVENT_TYPE_PROVIDER_RESPONSE,
                &serde_json::to_vec(&payload).unwrap()
            )
            .unwrap(),
            TerminalPayload::Unattributed
        ));
        assert!(
            terminal_sample_from_payload(
                EVENT_TYPE_PROVIDER_RESPONSE,
                br#"{"usage_projection_schema":"neoth.provider-usage.v2"}"#
            )
            .is_err()
        );
        let mut unsafe_model = payload.clone();
        unsafe_model["wire_model"] = serde_json::Value::String("model\nspoof".into());
        assert!(matches!(
            terminal_sample_from_payload(
                EVENT_TYPE_PROVIDER_RESPONSE,
                &serde_json::to_vec(&unsafe_model).unwrap()
            )
            .unwrap(),
            TerminalPayload::Unattributed
        ));
        assert!(
            terminal_sample_from_payload(
                EVENT_TYPE_PROVIDER_ERROR,
                &serde_json::to_vec(&payload).unwrap()
            )
            .is_err()
        );
        let mut uppercase_invocation = payload;
        uppercase_invocation["invocation_id"] = serde_json::Value::String("A".repeat(64));
        assert!(
            terminal_sample_from_payload(
                EVENT_TYPE_PROVIDER_RESPONSE,
                &serde_json::to_vec(&uppercase_invocation).unwrap()
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn authenticated_provider_terminal_producer_reaches_scanner_and_doctor() {
        let home = tempfile::tempdir().expect("test home");
        let now = crate::time::now_unix_i64();
        let (_, writer, join) = ready_authenticated_writer(home.path()).await;
        for invocation in 0..12 {
            append_provider_terminal(&writer, invocation, now - RECENT_WINDOW_SECONDS - 10, true)
                .await;
        }
        for invocation in 20..28 {
            append_provider_terminal(&writer, invocation, now - 10, true).await;
        }
        drop(writer);
        join.await
            .expect("join authenticated provider terminal writer")
            .expect("close authenticated provider terminal writer");

        let report = inspect_authenticated_terminal_history(home.path(), now).unwrap();
        assert_eq!(report.observations.len(), 1);
        assert_eq!(report.observations[0].identity.provider, "openai_api");
        assert_eq!(report.observations[0].identity.model, "gpt-5");
        assert_eq!(
            report.observations[0].identity.workflow.as_str(),
            "chat_turn"
        );
        assert_eq!(report.observations[0].trend, CapabilityTrend::Stable);
        let outcome = crate::cli::doctor::run_all_checks(home.path())
            .into_iter()
            .find(|outcome| outcome.name == "capability quality")
            .expect("public Doctor surface must include capability quality");
        assert_eq!(outcome.name, "capability quality");
        assert!(outcome.detail.contains("operational evidence"));
    }

    #[tokio::test]
    async fn authenticated_terminal_history_refuses_a_later_incomplete_prefix() {
        let home = tempfile::tempdir().expect("test home");
        let now = crate::time::now_unix_i64();
        let (segment, writer, join) = ready_authenticated_writer(home.path()).await;
        append_provider_terminal(&writer, 1, now - 10, true).await;
        drop(writer);
        join.await
            .expect("join authenticated provider terminal writer")
            .expect("close authenticated provider terminal writer");
        let mut tail = std::fs::OpenOptions::new()
            .append(true)
            .open(&segment)
            .expect("open completed WAL for torn-tail fixture");
        tail.write_all(&[0x4e, 0x45])
            .expect("append torn terminal WAL tail");
        tail.sync_all().expect("sync torn terminal WAL tail");
        assert!(inspect_authenticated_terminal_history(home.path(), now).is_err());
    }
}
