//! Request-owned W162 live-throughput controls.
//!
//! This pure reducer accepts only an already-isolated JSON payload from the
//! authenticated v3 stream-control record. It stores no provider text,
//! prompt, reasoning, history, preview, clipboard, session, or WAL value.
//! The caller supplies the request id derived by the existing control-token
//! primitive and clears this projection at every owning-stream boundary.

use serde::Deserialize;
use zeroize::Zeroize as _;

/// The largest possible no-text throughput payload. The real v3 record
/// contains only fixed vocabulary, ids, one rate, and its control token.
pub const MAX_THROUGHPUT_CONTROL_BYTES: usize = 1024;
/// Reject a finite but unusably large rate before it reaches a live surface.
pub const MAX_THROUGHPUT_PER_SECOND: f64 = 1_000_000.0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThroughputBasis {
    VisibleEvent,
    TokenDelta,
}

impl ThroughputBasis {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "visible_event" => Self::VisibleEvent,
            "token_delta" => Self::TokenDelta,
            _ => return None,
        })
    }

    pub const fn unit(self) -> ThroughputUnit {
        match self {
            Self::VisibleEvent => ThroughputUnit::StreamEventsPerSecond,
            Self::TokenDelta => ThroughputUnit::ProviderTokensPerSecond,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThroughputUnit {
    StreamEventsPerSecond,
    ProviderTokensPerSecond,
}

impl ThroughputUnit {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "stream_events_per_second" => Self::StreamEventsPerSecond,
            "provider_tokens_per_second" => Self::ProviderTokensPerSecond,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThroughputState {
    Measuring,
    Paused,
    Unavailable,
    Cancelled,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThroughputReason {
    NoVisibleEvents,
    NoUsageReported,
    Cancelled,
    StreamError,
}

/// The typed daemon GUI bridge has already authenticated the outer frame.
/// This preserves the producer's independent W162 sequence without accepting
/// a raw control record or its token/request binding fields.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum IssuedState {
    Measuring {
        basis: ThroughputBasis,
        per_second: f64,
    },
    Paused {
        basis: ThroughputBasis,
    },
    Unavailable {
        reason: ThroughputReason,
    },
}

impl ThroughputReason {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "no_visible_events" => Self::NoVisibleEvents,
            "no_usage_reported" => Self::NoUsageReported,
            "cancelled" => Self::Cancelled,
            "stream_error" => Self::StreamError,
            _ => return None,
        })
    }
}

/// The transient display projection for exactly one active stream request.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ThroughputSnapshot {
    pub state: ThroughputState,
    pub basis: Option<ThroughputBasis>,
    pub unit: Option<ThroughputUnit>,
    pub per_second: Option<f64>,
    pub reason: Option<ThroughputReason>,
    pub terminal: bool,
}

#[derive(Deserialize)]
struct NullableString(Option<String>);

#[derive(Deserialize)]
struct NullableRate(Option<f64>);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ThroughputFrame {
    neoth_stream: String,
    protocol_version: u64,
    request_id: String,
    control_token: String,
    sequence: u64,
    state: String,
    basis: NullableString,
    unit: NullableString,
    per_second: NullableRate,
    reason: NullableString,
}

impl Drop for ThroughputFrame {
    fn drop(&mut self) {
        self.neoth_stream.zeroize();
        self.request_id.zeroize();
        self.control_token.zeroize();
        self.state.zeroize();
        if let Some(basis) = self.basis.0.as_mut() {
            basis.zeroize();
        }
        if let Some(unit) = self.unit.0.as_mut() {
            unit.zeroize();
        }
        if let Some(reason) = self.reason.0.as_mut() {
            reason.zeroize();
        }
    }
}

/// Request-bound, no-text throughput state. A terminal stream fence, a
/// rejected frame, or a detach clears its snapshot and prevents any late frame
/// from repainting it. `replace_request` is the only way to begin a new lease.
#[derive(Debug)]
pub struct Projection {
    request_id: String,
    next_sequence: u64,
    terminal: bool,
    snapshot: Option<ThroughputSnapshot>,
}

impl Projection {
    /// `request_id` must come from the existing v3 control-token derivation.
    pub fn new(request_id: String) -> Self {
        Self {
            request_id,
            next_sequence: 1,
            terminal: false,
            snapshot: None,
        }
    }

    pub fn snapshot(&self) -> Option<ThroughputSnapshot> {
        self.snapshot
    }

    /// Fence the old request before accepting sequence 1 for a distinct one.
    pub fn replace_request(&mut self, request_id: String) {
        self.request_id = request_id;
        self.next_sequence = 1;
        self.terminal = false;
        self.snapshot = None;
    }

    /// Called when the authenticated provider boundary arrives. A throughput
    /// frame after this boundary is invalid even if its own sequence is next.
    pub fn provider_done(&mut self) {
        self.fence_and_clear();
    }

    /// Called for the authenticated final sentinel and for child/session
    /// detach. All three end the current request's transient ownership.
    pub fn final_sentinel_or_detach(&mut self) {
        self.fence_and_clear();
    }

    /// Typed W168 daemon entry point. The caller supplies the W162 producer
    /// sequence separately from the enclosing GUI frame sequence.
    pub fn accept_issued_state(
        &mut self,
        sequence: u64,
        state: IssuedState,
    ) -> Result<ThroughputSnapshot, &'static str> {
        let result = (|| {
            if self.terminal {
                return Err("throughput after terminal boundary");
            }
            if sequence == 0 || sequence != self.next_sequence {
                return Err("gapped or duplicate throughput control");
            }
            self.next_sequence = self
                .next_sequence
                .checked_add(1)
                .ok_or("throughput sequence exhausted")?;
            let snapshot = match state {
                IssuedState::Measuring { basis, per_second }
                    if per_second.is_finite()
                        && (0.0..=MAX_THROUGHPUT_PER_SECOND).contains(&per_second) =>
                {
                    ThroughputSnapshot {
                        state: ThroughputState::Measuring,
                        basis: Some(basis),
                        unit: Some(basis.unit()),
                        per_second: Some(per_second),
                        reason: None,
                        terminal: false,
                    }
                }
                IssuedState::Paused { basis } => ThroughputSnapshot {
                    state: ThroughputState::Paused,
                    basis: Some(basis),
                    unit: Some(basis.unit()),
                    per_second: None,
                    reason: None,
                    terminal: false,
                },
                IssuedState::Unavailable {
                    reason: reason @ (ThroughputReason::NoVisibleEvents
                    | ThroughputReason::NoUsageReported),
                } => ThroughputSnapshot {
                    state: ThroughputState::Unavailable,
                    basis: None,
                    unit: None,
                    per_second: None,
                    reason: Some(reason),
                    terminal: false,
                },
                IssuedState::Unavailable {
                    reason: ThroughputReason::Cancelled,
                } => ThroughputSnapshot {
                    state: ThroughputState::Cancelled,
                    basis: None,
                    unit: None,
                    per_second: None,
                    reason: Some(ThroughputReason::Cancelled),
                    terminal: true,
                },
                IssuedState::Unavailable {
                    reason: ThroughputReason::StreamError,
                } => ThroughputSnapshot {
                    state: ThroughputState::Error,
                    basis: None,
                    unit: None,
                    per_second: None,
                    reason: Some(ThroughputReason::StreamError),
                    terminal: true,
                },
                IssuedState::Measuring { .. } => return Err("invalid measuring throughput rate"),
            };
            self.snapshot = Some(snapshot);
            if snapshot.terminal {
                self.terminal = true;
            }
            Ok(snapshot)
        })();
        if result.is_err() {
            self.fence_and_clear();
        }
        result
    }

    pub fn apply_json(
        &mut self,
        line: &str,
        expected_control_token: &str,
        protocol_version: u64,
    ) -> Result<ThroughputSnapshot, &'static str> {
        let result = self.apply_json_inner(line, expected_control_token, protocol_version);
        if result.is_err() {
            self.fence_and_clear();
        }
        result
    }

    fn apply_json_inner(
        &mut self,
        line: &str,
        expected_control_token: &str,
        protocol_version: u64,
    ) -> Result<ThroughputSnapshot, &'static str> {
        if self.terminal {
            return Err("throughput after terminal boundary");
        }
        if line.len() > MAX_THROUGHPUT_CONTROL_BYTES {
            return Err("throughput control exceeds its bounded schema");
        }
        let frame = serde_json::from_str::<ThroughputFrame>(line)
            .map_err(|_| "invalid throughput control schema")?;
        self.validate_common(
            &frame.neoth_stream,
            frame.protocol_version,
            &frame.request_id,
            &frame.control_token,
            frame.sequence,
            expected_control_token,
            protocol_version,
        )?;
        match frame.state.as_str() {
            "measuring" => {
                if frame.reason.0.is_some() {
                    return Err("invalid measuring throughput state");
                }
                let basis = required_basis(frame.basis.0.as_deref())?;
                let unit = required_unit(frame.unit.0.as_deref())?;
                let per_second = frame
                    .per_second
                    .0
                    .ok_or("missing measuring throughput rate")?;
                if basis.unit() != unit
                    || !per_second.is_finite()
                    || !(0.0..=MAX_THROUGHPUT_PER_SECOND).contains(&per_second)
                {
                    return Err("invalid measuring throughput rate");
                }
                Ok(self.publish(ThroughputSnapshot {
                    state: ThroughputState::Measuring,
                    basis: Some(basis),
                    unit: Some(unit),
                    per_second: Some(per_second),
                    reason: None,
                    terminal: false,
                }))
            }
            "paused" => {
                if frame.per_second.0.is_some() || frame.reason.0.is_some() {
                    return Err("invalid paused throughput state");
                }
                let basis = required_basis(frame.basis.0.as_deref())?;
                let unit = required_unit(frame.unit.0.as_deref())?;
                if basis.unit() != unit {
                    return Err("paused throughput unit does not match its basis");
                }
                Ok(self.publish(ThroughputSnapshot {
                    state: ThroughputState::Paused,
                    basis: Some(basis),
                    unit: Some(unit),
                    per_second: None,
                    reason: None,
                    terminal: false,
                }))
            }
            "unavailable" => {
                if frame.basis.0.is_some() || frame.unit.0.is_some() || frame.per_second.0.is_some()
                {
                    return Err("invalid unavailable throughput state");
                }
                let reason = required_reason(frame.reason.0.as_deref())?;
                if !matches!(
                    reason,
                    ThroughputReason::NoVisibleEvents | ThroughputReason::NoUsageReported
                ) {
                    return Err("invalid unavailable throughput reason");
                }
                Ok(self.publish(ThroughputSnapshot {
                    state: ThroughputState::Unavailable,
                    basis: None,
                    unit: None,
                    per_second: None,
                    reason: Some(reason),
                    terminal: false,
                }))
            }
            "cancelled" | "error" => {
                if frame.basis.0.is_some() || frame.unit.0.is_some() || frame.per_second.0.is_some()
                {
                    return Err("invalid terminal throughput state");
                }
                let reason = required_reason(frame.reason.0.as_deref())?;
                let state = match (frame.state.as_str(), reason) {
                    ("cancelled", ThroughputReason::Cancelled) => ThroughputState::Cancelled,
                    ("error", ThroughputReason::StreamError) => ThroughputState::Error,
                    _ => return Err("invalid terminal throughput reason"),
                };
                let snapshot = self.publish(ThroughputSnapshot {
                    state,
                    basis: None,
                    unit: None,
                    per_second: None,
                    reason: Some(reason),
                    terminal: true,
                });
                self.terminal = true;
                Ok(snapshot)
            }
            _ => Err("unknown throughput state"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_common(
        &mut self,
        kind: &str,
        frame_version: u64,
        request_id: &str,
        control_token: &str,
        sequence: u64,
        expected_control_token: &str,
        protocol_version: u64,
    ) -> Result<(), &'static str> {
        if kind != "throughput_state"
            || frame_version != protocol_version
            || request_id != self.request_id
            || control_token != expected_control_token
        {
            return Err("forged or stale throughput control");
        }
        if sequence != self.next_sequence || sequence == 0 {
            return Err("gapped or duplicate throughput control");
        }
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or("throughput sequence exhausted")?;
        Ok(())
    }

    fn publish(&mut self, snapshot: ThroughputSnapshot) -> ThroughputSnapshot {
        self.snapshot = Some(snapshot);
        snapshot
    }

    fn fence_and_clear(&mut self) {
        self.snapshot = None;
        self.terminal = true;
    }
}

fn required_reason(value: Option<&str>) -> Result<ThroughputReason, &'static str> {
    value
        .and_then(ThroughputReason::parse)
        .ok_or("unknown throughput reason")
}

fn required_basis(value: Option<&str>) -> Result<ThroughputBasis, &'static str> {
    value
        .and_then(ThroughputBasis::parse)
        .ok_or("unknown throughput basis")
}

fn required_unit(value: Option<&str>) -> Result<ThroughputUnit, &'static str> {
    value
        .and_then(ThroughputUnit::parse)
        .ok_or("unknown throughput unit")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(
        sequence: u64,
        state: &str,
        basis: serde_json::Value,
        unit: serde_json::Value,
        per_second: serde_json::Value,
        reason: serde_json::Value,
    ) -> String {
        serde_json::json!({
            "neoth_stream": "throughput_state",
            "protocol_version": 3,
            "request_id": "request-a",
            "control_token": "token-a",
            "sequence": sequence,
            "state": state,
            "basis": basis,
            "unit": unit,
            "per_second": per_second,
            "reason": reason,
        })
        .to_string()
    }

    #[test]
    fn visible_event_rate_preserves_its_actual_unit() {
        let mut projection = Projection::new("request-a".into());
        let snapshot = projection
            .apply_json(
                &frame(
                    1,
                    "measuring",
                    serde_json::json!("visible_event"),
                    serde_json::json!("stream_events_per_second"),
                    serde_json::json!(12.5),
                    serde_json::Value::Null,
                ),
                "token-a",
                3,
            )
            .unwrap();
        assert_eq!(snapshot.state, ThroughputState::Measuring);
        assert_eq!(snapshot.basis, Some(ThroughputBasis::VisibleEvent));
        assert_eq!(snapshot.unit, Some(ThroughputUnit::StreamEventsPerSecond));
        assert_eq!(snapshot.per_second, Some(12.5));
    }

    #[test]
    fn paused_state_requires_null_rate_but_keeps_the_explicit_basis() {
        let mut projection = Projection::new("request-a".into());
        let snapshot = projection
            .apply_json(
                &frame(
                    1,
                    "paused",
                    serde_json::json!("visible_event"),
                    serde_json::json!("stream_events_per_second"),
                    serde_json::Value::Null,
                    serde_json::Value::Null,
                ),
                "token-a",
                3,
            )
            .unwrap();
        assert_eq!(snapshot.state, ThroughputState::Paused);
        assert_eq!(snapshot.basis, Some(ThroughputBasis::VisibleEvent));
        assert!(snapshot.per_second.is_none());
    }

    #[test]
    fn invalid_unit_and_final_usage_field_fail_closed() {
        let mut projection = Projection::new("request-a".into());
        assert!(
            projection
                .apply_json(
                    &frame(
                        1,
                        "measuring",
                        serde_json::json!("visible_event"),
                        serde_json::json!("provider_tokens_per_second"),
                        serde_json::json!(1.0),
                        serde_json::Value::Null,
                    ),
                    "token-a",
                    3,
                )
                .is_err()
        );
        assert!(projection.snapshot().is_none());

        projection.replace_request("request-a".into());
        let final_total = r#"{"neoth_stream":"throughput_state","protocol_version":3,"request_id":"request-a","control_token":"token-a","sequence":1,"state":"measuring","basis":"token_delta","unit":"provider_tokens_per_second","per_second":1.0,"reason":null,"output_tokens":99}"#;
        assert!(projection.apply_json(final_total, "token-a", 3).is_err());
        assert!(projection.snapshot().is_none());
    }

    #[test]
    fn stale_gap_and_provider_done_cannot_repaint_a_request() {
        let mut projection = Projection::new("request-a".into());
        assert!(
            projection
                .apply_json(
                    &frame(
                        2,
                        "unavailable",
                        serde_json::Value::Null,
                        serde_json::Value::Null,
                        serde_json::Value::Null,
                        serde_json::json!("no_visible_events"),
                    ),
                    "token-a",
                    3,
                )
                .is_err()
        );
        projection.replace_request("request-a".into());
        projection.provider_done();
        assert!(
            projection
                .apply_json(
                    &frame(
                        1,
                        "unavailable",
                        serde_json::Value::Null,
                        serde_json::Value::Null,
                        serde_json::Value::Null,
                        serde_json::json!("no_visible_events"),
                    ),
                    "token-a",
                    3,
                )
                .is_err()
        );
        assert!(projection.snapshot().is_none());
    }

    #[test]
    fn cancellation_is_terminal_until_the_request_is_replaced() {
        let mut projection = Projection::new("request-a".into());
        let cancelled = frame(
            1,
            "cancelled",
            serde_json::Value::Null,
            serde_json::Value::Null,
            serde_json::Value::Null,
            serde_json::json!("cancelled"),
        );
        assert_eq!(
            projection
                .apply_json(&cancelled, "token-a", 3)
                .unwrap()
                .state,
            ThroughputState::Cancelled
        );
        assert!(projection.apply_json(&cancelled, "token-a", 3).is_err());
        projection.replace_request("request-b".into());
        assert!(
            projection
                .apply_json(
                    &frame(
                        1,
                        "unavailable",
                        serde_json::Value::Null,
                        serde_json::Value::Null,
                        serde_json::Value::Null,
                        serde_json::json!("no_visible_events"),
                    )
                    .replace("request-a", "request-b"),
                    "token-a",
                    3,
                )
                .is_ok()
        );
    }

    #[test]
    fn typed_daemon_state_preserves_inner_sequence_and_terminal_fence() {
        let mut projection = Projection::new("daemon-operation-168".into());
        let snapshot = projection
            .accept_issued_state(
                1,
                IssuedState::Measuring {
                    basis: ThroughputBasis::TokenDelta,
                    per_second: 12.5,
                },
            )
            .expect("accept typed daemon rate");
        assert_eq!(snapshot.unit, Some(ThroughputUnit::ProviderTokensPerSecond));
        assert!(projection
            .accept_issued_state(
                3,
                IssuedState::Unavailable {
                    reason: ThroughputReason::NoUsageReported,
                },
            )
            .is_err());
        assert!(projection.snapshot().is_none());

        projection.replace_request("daemon-operation-169".into());
        assert_eq!(
            projection
                .accept_issued_state(
                    1,
                    IssuedState::Unavailable {
                        reason: ThroughputReason::Cancelled,
                    },
                )
                .expect("accept typed cancellation")
                .state,
            ThroughputState::Cancelled
        );
        assert!(projection
            .accept_issued_state(
                2,
                IssuedState::Paused {
                    basis: ThroughputBasis::VisibleEvent,
                },
            )
            .is_err());
    }
}
