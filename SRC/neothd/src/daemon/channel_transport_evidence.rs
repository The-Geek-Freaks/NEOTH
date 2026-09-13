//! Read-only, account-isolated channel transport evidence.
//!
//! This module has one authority boundary: a complete authenticated home-WAL
//! prefix. It neither discovers current channel configuration nor creates any
//! retry, runtime-health, or mutable delivery state.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::channels::registry::{ChannelId, ChannelRef};
use crate::daemon::proactive_egress::{
    ProactiveAccountEgressCollector, ProactiveFrameDisposition, VerifiedProactiveTerminal,
    VerifiedTransportFailure,
};
use crate::wal::events::{EVENT_TYPE_EXTENDED, ExtendedSubtype};
use crate::wal::frame::DecodedFrame;

const EVIDENCE_WINDOW_SECONDS: i64 = 24 * 60 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransportOrigin {
    MappedTelegramLive,
    ProactiveV4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransportFailure {
    Transport,
    Authentication,
    RateLimited,
    NotSupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AccountTransportState {
    AcceptedByAdapter,
    Failed(TransportFailure),
    UnknownAfterArmed,
    UnsettledLiveIntent,
    NotAttempted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AccountTransportObservation {
    pub(crate) channel_ref: ChannelRef,
    pub(crate) intent_id: String,
    pub(crate) origin: TransportOrigin,
    pub(crate) state: AccountTransportState,
    pub(crate) observed_at_unix: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct TransportCounters {
    pub(crate) completed: u64,
    pub(crate) accepted: u64,
    pub(crate) failed: u64,
    pub(crate) unknown_after_armed: u64,
    pub(crate) unsettled_live_intent: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundLiveIntentFrame {
    intent_id: String,
    channel: String,
    to_hash: String,
    message_hash: String,
    #[serde(rename = "message_bytes")]
    _message_bytes: usize,
    ts_unix: u64,
    channel_ref: Option<ChannelRef>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SanitizedLiveResult {
    outcome: Option<&'static str>,
    ts_unix: Option<u64>,
    receipt_present: Option<bool>,
    malformed: bool,
}

#[derive(Default)]
struct BoundLiveCollector {
    intents: HashMap<String, BoundLiveIntentFrame>,
    intent_positions: HashMap<String, u64>,
    results: HashMap<String, SanitizedLiveResult>,
    result_positions: HashMap<String, u64>,
    duplicate_results: HashMap<String, usize>,
    next_position: u64,
}

impl BoundLiveCollector {
    fn observe(&mut self, frame: &DecodedFrame<'_>) -> Result<()> {
        if frame.header.event_type != EVENT_TYPE_EXTENDED {
            return Ok(());
        }
        let position = self.next_position;
        self.next_position = self
            .next_position
            .checked_add(1)
            .context("bound live frame position overflow")?;
        match frame.header.event_subtype {
            subtype if subtype == ExtendedSubtype::ChannelEgressIntent as u8 => {
                self.observe_intent(frame.payload, position)
            }
            subtype if subtype == ExtendedSubtype::ChannelEgressResult as u8 => {
                self.observe_result(frame.payload, position)
            }
            _ => Ok(()),
        }
    }

    fn observe_intent(&mut self, payload: &[u8], position: u64) -> Result<()> {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(payload) else {
            return Ok(());
        };
        if value.get("channel_ref").is_none() {
            return Ok(());
        }
        let intent: BoundLiveIntentFrame =
            serde_json::from_value(value).context("decode bound live channel egress intent")?;
        let channel_ref = intent
            .channel_ref
            .as_ref()
            .context("bound live intent omits channel_ref")?;
        validate_live_identity(&intent.intent_id, channel_ref, &intent.channel)?;
        validate_live_intent_payload(&intent)?;
        let intent_id = intent.intent_id.clone();
        anyhow::ensure!(
            self.intents.insert(intent_id.clone(), intent).is_none(),
            "duplicate bound live intent"
        );
        anyhow::ensure!(
            self.intent_positions.insert(intent_id, position).is_none(),
            "duplicate bound live intent position"
        );
        Ok(())
    }

    fn observe_result(&mut self, payload: &[u8], position: u64) -> Result<()> {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(payload) else {
            return Ok(());
        };
        let Some(intent_id) = value.get("intent_id").and_then(serde_json::Value::as_str) else {
            return Ok(());
        };
        if !is_canonical_live_intent_id(intent_id) {
            return Ok(());
        }
        let sanitized = sanitize_live_result(&value);
        let duplicate_count = self
            .duplicate_results
            .entry(intent_id.to_string())
            .or_insert(0);
        *duplicate_count = duplicate_count
            .checked_add(1)
            .context("bound live result duplicate counter overflow")?;
        let result_id = intent_id.to_string();
        self.results.entry(result_id.clone()).or_insert(sanitized);
        self.result_positions.entry(result_id).or_insert(position);
        Ok(())
    }

    fn finish(self) -> Result<Vec<AccountTransportObservation>> {
        let mut observations = Vec::new();
        for intent in self.intents.values() {
            let channel_ref = intent
                .channel_ref
                .clone()
                .context("bound live intent omits channel_ref")?;
            let created_at_unix = checked_live_timestamp(intent.ts_unix, "bound live intent")?;
            let result_value = self.results.get(&intent.intent_id);
            if let Some(result_value) = result_value {
                anyhow::ensure!(
                    self.duplicate_results
                        .get(&intent.intent_id)
                        .copied()
                        .unwrap_or_default()
                        == 1,
                    "duplicate bound live result"
                );
                anyhow::ensure!(
                    !result_value.malformed,
                    "decode bound live channel egress result"
                );
                let completed_at_unix = checked_live_timestamp(
                    result_value
                        .ts_unix
                        .context("bound live result omits timestamp")?,
                    "bound live result",
                )?;
                anyhow::ensure!(
                    completed_at_unix >= created_at_unix,
                    "bound live result precedes its intent"
                );
                anyhow::ensure!(
                    self.result_positions
                        .get(&intent.intent_id)
                        .copied()
                        .context("bound live result omits its scan position")?
                        > self
                            .intent_positions
                            .get(&intent.intent_id)
                            .copied()
                            .context("bound live intent omits its scan position")?,
                    "bound live result appears before its intent"
                );
                observations.push(AccountTransportObservation {
                    channel_ref,
                    intent_id: intent.intent_id.clone(),
                    origin: TransportOrigin::MappedTelegramLive,
                    state: live_result_state(
                        result_value
                            .outcome
                            .context("bound live result omits outcome")?,
                        result_value
                            .receipt_present
                            .context("bound live result omits provider receipt state")?,
                    )?,
                    observed_at_unix: completed_at_unix,
                });
            } else {
                observations.push(AccountTransportObservation {
                    channel_ref,
                    intent_id: intent.intent_id.clone(),
                    origin: TransportOrigin::MappedTelegramLive,
                    state: AccountTransportState::UnsettledLiveIntent,
                    observed_at_unix: created_at_unix,
                });
            }
        }
        Ok(observations)
    }
}

/// Reads one complete authenticated home-WAL prefix and derives only historical
/// account-bound Telegram transport evidence. An error yields no counters.
pub(crate) fn read_account_transport_evidence(
    home: &Path,
    now_unix: i64,
) -> Result<BTreeMap<ChannelRef, TransportCounters>> {
    anyhow::ensure!(
        now_unix >= 0,
        "transport evidence clock is before Unix epoch"
    );
    let mut proactive = ProactiveAccountEgressCollector::new();
    let mut live = BoundLiveCollector::default();
    let scan = crate::wal::scan::for_each_authenticated_prefix_frame_at_home(
        home,
        crate::wal::scan::supported_home_scan_limits(),
        |_, frame| match proactive.observe(frame)? {
            ProactiveFrameDisposition::ConsumedProactive => Ok(()),
            ProactiveFrameDisposition::NotProactive => live.observe(frame),
        },
    )
    .context("scan authenticated complete home WAL for transport evidence")?;
    anyhow::ensure!(
        scan.complete,
        "transport evidence refuses an incomplete authenticated home WAL prefix"
    );

    let mut observations = live.finish()?;
    for proactive_record in proactive.finish()? {
        anyhow::ensure!(
            proactive_record.created_at_unix <= now_unix,
            "proactive transport evidence intent timestamp is in the future"
        );
        let state_and_time = match proactive_record.terminal {
            Some(VerifiedProactiveTerminal::AcceptedByAdapter { completed_at_unix }) => {
                (AccountTransportState::AcceptedByAdapter, completed_at_unix)
            }
            Some(VerifiedProactiveTerminal::Failed {
                kind,
                completed_at_unix,
            }) => (
                AccountTransportState::Failed(match kind {
                    VerifiedTransportFailure::Transport => TransportFailure::Transport,
                    VerifiedTransportFailure::Authentication => TransportFailure::Authentication,
                    VerifiedTransportFailure::RateLimited => TransportFailure::RateLimited,
                    VerifiedTransportFailure::NotSupported => TransportFailure::NotSupported,
                }),
                completed_at_unix,
            ),
            Some(VerifiedProactiveTerminal::CrashUnknown { completed_at_unix }) => {
                (AccountTransportState::UnknownAfterArmed, completed_at_unix)
            }
            Some(VerifiedProactiveTerminal::NotAttempted { completed_at_unix }) => {
                (AccountTransportState::NotAttempted, completed_at_unix)
            }
            None => (
                AccountTransportState::UnknownAfterArmed,
                proactive_record
                    .armed_at_unix
                    .context("unsettled proactive record omits Armed time")?,
            ),
        };
        observations.push(AccountTransportObservation {
            channel_ref: proactive_record.channel_ref,
            intent_id: proactive_record.intent_id,
            origin: TransportOrigin::ProactiveV4,
            state: state_and_time.0,
            observed_at_unix: state_and_time.1,
        });
    }

    aggregate_recent_observations(observations, now_unix)
}

fn validate_live_identity(intent_id: &str, channel_ref: &ChannelRef, channel: &str) -> Result<()> {
    anyhow::ensure!(
        is_canonical_live_intent_id(intent_id),
        "bound live intent id is not canonical lower-case 32-hex"
    );
    anyhow::ensure!(
        channel == "telegram" && channel_ref.channel_id == ChannelId::Telegram,
        "bound live evidence requires an exact Telegram channel/ref pair"
    );
    Ok(())
}

fn validate_live_intent_payload(intent: &BoundLiveIntentFrame) -> Result<()> {
    anyhow::ensure!(
        is_lower_hex(&intent.to_hash, 16) && is_lower_hex(&intent.message_hash, 16),
        "bound live intent has invalid hashed message metadata"
    );
    Ok(())
}

fn is_canonical_live_intent_id(value: &str) -> bool {
    is_lower_hex(value, 32)
}

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value.bytes().all(|byte| {
            byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit())
        })
}

fn checked_live_timestamp(value: u64, label: &str) -> Result<i64> {
    i64::try_from(value).with_context(|| format!("{label} timestamp exceeds i64"))
}

fn sanitize_live_result(value: &serde_json::Value) -> SanitizedLiveResult {
    let Some(object) = value.as_object() else {
        return SanitizedLiveResult {
            outcome: None,
            ts_unix: None,
            receipt_present: None,
            malformed: true,
        };
    };
    let allowed = ["intent_id", "outcome", "provider_message_id", "ts_unix"];
    let unexpected = object.keys().any(|key| !allowed.contains(&key.as_str()));
    let outcome = object
        .get("outcome")
        .and_then(serde_json::Value::as_str)
        .and_then(|outcome| match outcome {
            "delivered" => Some("delivered"),
            "transport" => Some("transport"),
            "auth" => Some("auth"),
            "rate_limited" => Some("rate_limited"),
            "not_supported" => Some("not_supported"),
            _ => None,
        });
    let ts_unix = object.get("ts_unix").and_then(serde_json::Value::as_u64);
    let receipt_present = match object.get("provider_message_id") {
        Some(serde_json::Value::Null) => Some(false),
        Some(serde_json::Value::String(value)) if !value.is_empty() => Some(true),
        _ => None,
    };
    SanitizedLiveResult {
        malformed: unexpected
            || outcome.is_none()
            || ts_unix.is_none()
            || receipt_present.is_none(),
        outcome,
        ts_unix,
        receipt_present,
    }
}

fn live_result_state(outcome: &str, receipt_present: bool) -> Result<AccountTransportState> {
    match outcome {
        "delivered" => {
            anyhow::ensure!(
                receipt_present,
                "bound live delivered result lacks a provider receipt"
            );
            Ok(AccountTransportState::AcceptedByAdapter)
        }
        "transport" => {
            anyhow::ensure!(
                !receipt_present,
                "bound live transport failure unexpectedly has a provider receipt"
            );
            Ok(AccountTransportState::Failed(TransportFailure::Transport))
        }
        "auth" => {
            anyhow::ensure!(
                !receipt_present,
                "bound live authentication failure unexpectedly has a provider receipt"
            );
            Ok(AccountTransportState::Failed(
                TransportFailure::Authentication,
            ))
        }
        "rate_limited" => {
            anyhow::ensure!(
                !receipt_present,
                "bound live rate-limited failure unexpectedly has a provider receipt"
            );
            Ok(AccountTransportState::Failed(TransportFailure::RateLimited))
        }
        "not_supported" => {
            anyhow::ensure!(
                !receipt_present,
                "bound live not-supported failure unexpectedly has a provider receipt"
            );
            Ok(AccountTransportState::Failed(
                TransportFailure::NotSupported,
            ))
        }
        _ => anyhow::bail!("unsupported bound live result outcome"),
    }
}

fn aggregate_recent_observations(
    observations: Vec<AccountTransportObservation>,
    now_unix: i64,
) -> Result<BTreeMap<ChannelRef, TransportCounters>> {
    let earliest_unix = now_unix
        .checked_sub(EVIDENCE_WINDOW_SECONDS)
        .context("transport evidence window underflow")?;
    let mut counters = BTreeMap::new();
    for observation in observations {
        anyhow::ensure!(
            observation.observed_at_unix <= now_unix,
            "transport evidence timestamp is in the future"
        );
        if observation.observed_at_unix < earliest_unix {
            continue;
        }
        let entry = counters
            .entry(observation.channel_ref)
            .or_insert_with(TransportCounters::default);
        match observation.state {
            AccountTransportState::AcceptedByAdapter => {
                entry.completed = entry
                    .completed
                    .checked_add(1)
                    .context("transport evidence completed counter overflow")?;
                entry.accepted = entry
                    .accepted
                    .checked_add(1)
                    .context("transport evidence accepted counter overflow")?;
            }
            AccountTransportState::Failed(_) => {
                entry.completed = entry
                    .completed
                    .checked_add(1)
                    .context("transport evidence completed counter overflow")?;
                entry.failed = entry
                    .failed
                    .checked_add(1)
                    .context("transport evidence failed counter overflow")?;
            }
            AccountTransportState::UnknownAfterArmed => {
                entry.unknown_after_armed = entry
                    .unknown_after_armed
                    .checked_add(1)
                    .context("transport evidence unknown counter overflow")?;
            }
            AccountTransportState::UnsettledLiveIntent => {
                entry.unsettled_live_intent = entry
                    .unsettled_live_intent
                    .checked_add(1)
                    .context("transport evidence unsettled counter overflow")?;
            }
            AccountTransportState::NotAttempted => {}
        }
    }
    Ok(counters)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    use crate::channels::registry::ChannelAccountId;
    use crate::wal::writer::WalWriterHandle;

    const LIVE_A: &str = "0123456789abcdef0123456789abcdef";
    const LIVE_B: &str = "fedcba9876543210fedcba9876543210";

    fn account_ref(account_id: &str) -> ChannelRef {
        ChannelRef::new(
            ChannelId::Telegram,
            ChannelAccountId::new(account_id).expect("valid test account"),
        )
    }

    fn intent_json(intent_id: &str, channel_ref: &ChannelRef, ts_unix: u64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "intent_id": intent_id,
            "channel": "telegram",
            "to_hash": "0123456789abcdef",
            "message_hash": "fedcba9876543210",
            "message_bytes": 4,
            "ts_unix": ts_unix,
            "channel_ref": channel_ref,
        }))
        .expect("encode bound live intent")
    }

    fn result_json(intent_id: &str, outcome: &str, ts_unix: u64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "intent_id": intent_id,
            "outcome": outcome,
            "provider_message_id": if outcome == "delivered" { Some("receipt") } else { None },
            "ts_unix": ts_unix,
        }))
        .expect("encode bound live result")
    }

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

    async fn append_authenticated_live_frame(
        writer: &WalWriterHandle,
        subtype: ExtendedSubtype,
        payload: Vec<u8>,
    ) {
        let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
            .event_subtype(subtype as u8)
            .build();
        writer
            .append_authenticated(header, payload)
            .await
            .expect("append authenticated bound-live fixture frame");
    }

    #[test]
    fn mapped_live_a_and_b_stay_account_isolated() {
        let ref_a = account_ref("account-a");
        let ref_b = account_ref("default");
        let mut collector = BoundLiveCollector::default();
        collector
            .observe_intent(&intent_json(LIVE_A, &ref_a, 100), 0)
            .unwrap();
        collector
            .observe_intent(&intent_json(LIVE_B, &ref_b, 100), 1)
            .unwrap();
        collector
            .observe_result(&result_json(LIVE_A, "delivered", 101), 2)
            .unwrap();
        collector
            .observe_result(&result_json(LIVE_B, "transport", 101), 3)
            .unwrap();

        let counters = aggregate_recent_observations(collector.finish().unwrap(), 101).unwrap();
        assert_eq!(
            counters.get(&ref_a),
            Some(&TransportCounters {
                completed: 1,
                accepted: 1,
                failed: 0,
                unknown_after_armed: 0,
                unsettled_live_intent: 0,
            })
        );
        assert_eq!(
            counters.get(&ref_b),
            Some(&TransportCounters {
                completed: 1,
                accepted: 0,
                failed: 1,
                unknown_after_armed: 0,
                unsettled_live_intent: 0,
            })
        );
    }

    #[test]
    fn unbound_legacy_live_json_is_not_evidence() {
        let mut collector = BoundLiveCollector::default();
        let unbound = serde_json::to_vec(&serde_json::json!({
            "intent_id": LIVE_A,
            "channel": "telegram",
            "to_hash": "0123456789abcdef",
            "message_hash": "fedcba9876543210",
            "message_bytes": 4,
            "ts_unix": 100,
        }))
        .unwrap();
        collector.observe_intent(&unbound, 0).unwrap();
        collector
            .observe_result(&result_json(LIVE_A, "delivered", 101), 1)
            .unwrap();
        assert!(collector.finish().unwrap().is_empty());
    }

    #[test]
    fn sanitizer_retains_receipt_presence_without_retaining_provider_identifier() {
        let distinctive_receipt = "provider-id-must-not-survive-observation";
        let payload = serde_json::to_vec(&serde_json::json!({
            "intent_id": LIVE_A,
            "outcome": "delivered",
            "provider_message_id": distinctive_receipt,
            "ts_unix": 101,
        }))
        .unwrap();
        let mut collector = BoundLiveCollector::default();
        collector.observe_result(&payload, 0).unwrap();
        let retained = collector.results.get(LIVE_A).unwrap();
        assert_eq!(retained.outcome, Some("delivered"));
        assert_eq!(retained.ts_unix, Some(101));
        assert_eq!(retained.receipt_present, Some(true));
        assert!(!retained.malformed);
        assert!(
            !format!("{retained:?}").contains(distinctive_receipt),
            "provider identifier must not survive the sanitizer"
        );
    }

    #[test]
    fn sanitizer_drops_unknown_outcome_and_rejects_only_matching_bound_result() {
        let distinctive_outcome = "unknown-outcome-must-not-survive-observation";
        let payload = result_json(LIVE_A, distinctive_outcome, 101);
        let mut orphan = BoundLiveCollector::default();
        orphan.observe_result(&payload, 1).unwrap();
        let retained = orphan.results.get(LIVE_A).unwrap();
        assert_eq!(retained.outcome, None);
        assert!(retained.malformed);
        assert!(!format!("{retained:?}").contains(distinctive_outcome));
        assert!(orphan.finish().unwrap().is_empty());

        let mut bound = BoundLiveCollector::default();
        bound
            .observe_intent(&intent_json(LIVE_A, &account_ref("account-a"), 100), 0)
            .unwrap();
        bound.observe_result(&payload, 1).unwrap();
        assert!(bound.finish().is_err());
    }

    #[test]
    fn bound_live_rejects_malformed_or_conflicting_rows_and_invalid_time_ordering() {
        let ref_a = account_ref("account-a");
        let mut mismatched = BoundLiveCollector::default();
        let mut wrong_channel: serde_json::Value =
            serde_json::from_slice(&intent_json(LIVE_A, &ref_a, 100)).unwrap();
        wrong_channel["channel"] = serde_json::Value::String("slack".to_string());
        assert!(
            mismatched
                .observe_intent(&serde_json::to_vec(&wrong_channel).unwrap(), 0)
                .is_err()
        );

        let mut malformed = BoundLiveCollector::default();
        let malformed_payload = serde_json::to_vec(&serde_json::json!({
            "intent_id": LIVE_A,
            "channel": "telegram",
            "channel_ref": ref_a,
        }))
        .unwrap();
        assert!(malformed.observe_intent(&malformed_payload, 0).is_err());

        let ref_a = account_ref("account-a");
        let mut conflicting = BoundLiveCollector::default();
        conflicting
            .observe_intent(&intent_json(LIVE_A, &ref_a, 100), 0)
            .unwrap();
        assert!(
            conflicting
                .observe_intent(&intent_json(LIVE_A, &ref_a, 100), 1)
                .is_err()
        );

        let mut ordered = BoundLiveCollector::default();
        ordered
            .observe_result(&result_json(LIVE_A, "delivered", 101), 0)
            .unwrap();
        ordered
            .observe_intent(&intent_json(LIVE_A, &ref_a, 100), 1)
            .unwrap();
        assert!(ordered.finish().is_err());

        let mut overflow = BoundLiveCollector::default();
        overflow
            .observe_intent(&intent_json(LIVE_A, &ref_a, u64::MAX), 0)
            .unwrap();
        assert!(overflow.finish().is_err());

        let future = AccountTransportObservation {
            channel_ref: ref_a,
            intent_id: LIVE_B.to_string(),
            origin: TransportOrigin::MappedTelegramLive,
            state: AccountTransportState::AcceptedByAdapter,
            observed_at_unix: 102,
        };
        assert!(aggregate_recent_observations(vec![future], 101).is_err());
    }

    #[test]
    fn unknown_unsettled_and_not_attempted_have_their_separate_counter_rules() {
        let ref_a = account_ref("account-a");
        let observations = vec![
            AccountTransportObservation {
                channel_ref: ref_a.clone(),
                intent_id: LIVE_A.to_string(),
                origin: TransportOrigin::ProactiveV4,
                state: AccountTransportState::UnknownAfterArmed,
                observed_at_unix: 100,
            },
            AccountTransportObservation {
                channel_ref: ref_a.clone(),
                intent_id: LIVE_B.to_string(),
                origin: TransportOrigin::MappedTelegramLive,
                state: AccountTransportState::UnsettledLiveIntent,
                observed_at_unix: 100,
            },
            AccountTransportObservation {
                channel_ref: ref_a.clone(),
                intent_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                origin: TransportOrigin::ProactiveV4,
                state: AccountTransportState::NotAttempted,
                observed_at_unix: 100,
            },
        ];
        let counters = aggregate_recent_observations(observations, 100).unwrap();
        assert_eq!(
            counters.get(&ref_a),
            Some(&TransportCounters {
                completed: 0,
                accepted: 0,
                failed: 0,
                unknown_after_armed: 1,
                unsettled_live_intent: 1,
            })
        );
    }

    #[tokio::test]
    async fn authenticated_home_wal_reader_isolates_historical_live_a_and_b_without_current_config()
    {
        let home = tempfile::tempdir().expect("test home");
        let (_segment, writer, join) = ready_authenticated_writer(home.path()).await;
        let ref_a = account_ref("removed-account-a");
        let ref_b = account_ref("removed-account-b");
        append_authenticated_live_frame(
            &writer,
            ExtendedSubtype::ChannelEgressIntent,
            intent_json(LIVE_A, &ref_a, 100),
        )
        .await;
        append_authenticated_live_frame(
            &writer,
            ExtendedSubtype::ChannelEgressResult,
            result_json(LIVE_A, "delivered", 101),
        )
        .await;
        append_authenticated_live_frame(
            &writer,
            ExtendedSubtype::ChannelEgressIntent,
            intent_json(LIVE_B, &ref_b, 100),
        )
        .await;
        append_authenticated_live_frame(
            &writer,
            ExtendedSubtype::ChannelEgressResult,
            result_json(LIVE_B, "transport", 101),
        )
        .await;
        drop(writer);
        join.await
            .expect("join authenticated home WAL writer")
            .expect("close authenticated home WAL writer");

        assert!(
            !home.path().join("freedom.yaml").exists(),
            "historical transport evidence must not require current configuration"
        );
        let counters = read_account_transport_evidence(home.path(), 101)
            .expect("read complete authenticated historical evidence");
        assert_eq!(
            counters.get(&ref_a),
            Some(&TransportCounters {
                completed: 1,
                accepted: 1,
                failed: 0,
                unknown_after_armed: 0,
                unsettled_live_intent: 0,
            })
        );
        assert_eq!(
            counters.get(&ref_b),
            Some(&TransportCounters {
                completed: 1,
                accepted: 0,
                failed: 1,
                unknown_after_armed: 0,
                unsettled_live_intent: 0,
            })
        );
        assert_eq!(counters.len(), 2);
    }

    #[tokio::test]
    async fn complete_empty_and_unbound_authenticated_home_wals_have_no_account_evidence() {
        let empty_home = tempfile::tempdir().expect("empty test home");
        let (_segment, writer, join) = ready_authenticated_writer(empty_home.path()).await;
        drop(writer);
        join.await
            .expect("join empty authenticated home WAL writer")
            .expect("close empty authenticated home WAL writer");
        assert!(
            read_account_transport_evidence(empty_home.path(), 101)
                .expect("read complete empty authenticated home WAL")
                .is_empty()
        );

        let unbound_home = tempfile::tempdir().expect("unbound test home");
        let (_segment, writer, join) = ready_authenticated_writer(unbound_home.path()).await;
        let unbound = serde_json::to_vec(&serde_json::json!({
            "intent_id": LIVE_A,
            "channel": "telegram",
            "to_hash": "0123456789abcdef",
            "message_hash": "fedcba9876543210",
            "message_bytes": 4,
            "ts_unix": 100,
        }))
        .expect("encode unbound live intent");
        append_authenticated_live_frame(&writer, ExtendedSubtype::ChannelEgressIntent, unbound)
            .await;
        append_authenticated_live_frame(
            &writer,
            ExtendedSubtype::ChannelEgressResult,
            result_json(LIVE_A, "delivered", 101),
        )
        .await;
        drop(writer);
        join.await
            .expect("join unbound authenticated home WAL writer")
            .expect("close unbound authenticated home WAL writer");
        assert!(
            read_account_transport_evidence(unbound_home.path(), 101)
                .expect("read complete authenticated WAL with unbound rows")
                .is_empty(),
            "legacy rows without a typed account ref must not create account evidence"
        );
    }

    #[tokio::test]
    async fn authenticated_home_wal_reader_rejects_incomplete_later_tail_without_prefix_counters() {
        let home = tempfile::tempdir().expect("test home");
        let (segment, writer, join) = ready_authenticated_writer(home.path()).await;
        let ref_a = account_ref("account-a");
        append_authenticated_live_frame(
            &writer,
            ExtendedSubtype::ChannelEgressIntent,
            intent_json(LIVE_A, &ref_a, 100),
        )
        .await;
        append_authenticated_live_frame(
            &writer,
            ExtendedSubtype::ChannelEgressResult,
            result_json(LIVE_A, "delivered", 101),
        )
        .await;
        drop(writer);
        join.await
            .expect("join authenticated home WAL writer")
            .expect("close authenticated home WAL writer");

        let mut tail = std::fs::OpenOptions::new()
            .append(true)
            .open(&segment)
            .expect("open complete WAL for torn later-frame fixture");
        tail.write_all(&[0x4e, 0x45])
            .expect("append torn later-frame fixture");
        tail.sync_all().expect("sync torn later-frame fixture");
        assert!(
            read_account_transport_evidence(home.path(), 101).is_err(),
            "an incomplete later WAL tail must not return valid-prefix counters"
        );
    }

    #[tokio::test]
    async fn authenticated_home_wal_reader_rejects_tampered_later_frame_without_prefix_counters() {
        let home = tempfile::tempdir().expect("test home");
        let (segment, writer, join) = ready_authenticated_writer(home.path()).await;
        let ref_a = account_ref("account-a");
        append_authenticated_live_frame(
            &writer,
            ExtendedSubtype::ChannelEgressIntent,
            intent_json(LIVE_A, &ref_a, 100),
        )
        .await;
        append_authenticated_live_frame(
            &writer,
            ExtendedSubtype::ChannelEgressResult,
            result_json(LIVE_A, "delivered", 101),
        )
        .await;
        drop(writer);
        join.await
            .expect("join authenticated home WAL writer")
            .expect("close authenticated home WAL writer");

        let mut bytes = std::fs::read(&segment).expect("read authenticated WAL fixture");
        let delivered = b"delivered";
        let offset = bytes
            .windows(delivered.len())
            .position(|window| window == delivered)
            .expect("find later result outcome in WAL fixture");
        bytes[offset] = b'x';
        std::fs::write(&segment, bytes).expect("tamper later authenticated WAL frame");
        assert!(
            read_account_transport_evidence(home.path(), 101).is_err(),
            "a tampered later WAL frame must not return valid-prefix counters"
        );
    }
}
