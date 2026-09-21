//! W164 — request-owned, private response-feedback target projection.
//!
//! The terminal producer issues this v3 control only after the response has
//! drained and only for a non-incognito response.  The GUI keeps the opaque
//! target out of Slint and releases an actionable presentation only after the
//! ordinary `done` boundary and this bound target have both arrived.

use serde::Deserialize;
use zeroize::{Zeroize as _, Zeroizing};

/// A target frame carries two short opaque identifiers and no reply content.
pub const MAX_RESPONSE_FEEDBACK_TARGET_BYTES: usize = 1_024;
const MAX_SESSION_ID_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetStatus {
    Ready,
    Unavailable,
}

impl TargetStatus {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "ready" => Some(Self::Ready),
            "unavailable" => Some(Self::Unavailable),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedbackSignal {
    Accepted,
    NeedsCorrection,
    NotHelpful,
}

impl FeedbackSignal {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::NeedsCorrection => "needs-correction",
            Self::NotHelpful => "not-helpful",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Set(FeedbackSignal),
    Remove,
}

/// Presentation data is deliberately content-free and may cross the Slint
/// boundary. `status` is operator text owned by the caller, never an id.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub available: bool,
    pub running: bool,
    pub status: TargetStatus,
    pub active_signal: Option<FeedbackSignal>,
}

/// Private input to the CLI worker. Do not expose this type to Slint, logs, or
/// toast text. Its `Debug` implementation intentionally redacts both ids.
#[derive(Clone, PartialEq, Eq)]
pub struct ActionTarget {
    response_id: Zeroizing<String>,
    session_id: Zeroizing<String>,
    revision: u64,
    action: Action,
}

impl ActionTarget {
    pub fn response_id(&self) -> &str {
        self.response_id.as_str()
    }
    pub fn session_id(&self) -> &str {
        self.session_id.as_str()
    }
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    pub const fn action(&self) -> Action {
        self.action
    }
}

impl std::fmt::Debug for ActionTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActionTarget")
            .field("response_id", &"<redacted>")
            .field("session_id", &"<redacted>")
            .field("revision", &self.revision)
            .field("action", &self.action)
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetFrame {
    neoth_stream: String,
    protocol_version: u64,
    request_id: String,
    control_token: String,
    response_id: Option<String>,
    session_id: Option<String>,
    revision: Option<u64>,
    status: String,
}

impl Drop for TargetFrame {
    fn drop(&mut self) {
        self.neoth_stream.zeroize();
        self.request_id.zeroize();
        self.control_token.zeroize();
        if let Some(response_id) = self.response_id.as_mut() {
            response_id.zeroize();
        }
        if let Some(session_id) = self.session_id.as_mut() {
            session_id.zeroize();
        }
        self.status.zeroize();
    }
}

/// Exactly one post-drain target belongs to one GUI request. `done_seen` is
/// recorded from the existing authenticated StreamDone; it is not inferred
/// from provider text or child exit status.
pub struct Projection {
    request_id: Zeroizing<String>,
    done_seen: bool,
    fenced: bool,
    target_status: TargetStatus,
    response_id: Option<Zeroizing<String>>,
    session_id: Option<Zeroizing<String>>,
    revision: u64,
    active_signal: Option<FeedbackSignal>,
    running: bool,
}

impl std::fmt::Debug for Projection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Projection")
            .field("request_id", &"<redacted>")
            .field("done_seen", &self.done_seen)
            .field("fenced", &self.fenced)
            .field("target_status", &self.target_status)
            .field("has_target", &self.response_id.is_some())
            .field("revision", &self.revision)
            .field("active_signal", &self.active_signal)
            .field("running", &self.running)
            .finish()
    }
}

impl Projection {
    pub fn new(request_id: String) -> Self {
        Self {
            request_id: Zeroizing::new(request_id),
            done_seen: false,
            fenced: false,
            target_status: TargetStatus::Unavailable,
            response_id: None,
            session_id: None,
            revision: 0,
            active_signal: None,
            running: false,
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            available: self.done_seen
                && !self.fenced
                && self.target_status == TargetStatus::Ready
                && self.response_id.is_some()
                && self.session_id.is_some(),
            running: self.running,
            status: self.target_status,
            active_signal: self.active_signal,
        }
    }

    /// The old StreamDone remains the truthful provider completion boundary.
    pub fn stream_done(&mut self) {
        self.done_seen = true;
    }

    /// Daemon GUI terminals already crossed the authenticated bridge boundary.
    /// They carry the same terminal-issued opaque pair as the stream control,
    /// so they bypass JSON parsing but retain the identical done/fence and
    /// identity validation rules. No caller may synthesize a target here.
    pub fn accept_issued_terminal_target(
        &mut self,
        response_id: String,
        session_id: String,
        revision: u64,
    ) -> Result<Snapshot, &'static str> {
        if self.fenced
            || !self.done_seen
            || self.response_id.is_some()
            || self.session_id.is_some()
            || !is_response_id(response_id.as_str())
            || !is_session_id(session_id.as_str())
        {
            self.clear_and_fence();
            return Err("daemon response feedback target is unavailable or malformed");
        }
        self.response_id = Some(Zeroizing::new(response_id));
        self.session_id = Some(Zeroizing::new(session_id));
        self.revision = revision;
        self.target_status = TargetStatus::Ready;
        Ok(self.snapshot())
    }

    pub fn accept_issued_terminal_unavailable(&mut self) -> Result<Snapshot, &'static str> {
        if self.fenced || !self.done_seen || self.response_id.is_some() || self.session_id.is_some()
        {
            self.clear_and_fence();
            return Err(
                "daemon response feedback unavailable marker is outside its terminal window",
            );
        }
        self.target_status = TargetStatus::Unavailable;
        Ok(self.snapshot())
    }

    /// A cancellation, child failure, detach, history switch, new request, or
    /// malformed target removes private state and permanently fences it.
    pub fn clear_and_fence(&mut self) {
        self.fenced = true;
        self.running = false;
        self.target_status = TargetStatus::Unavailable;
        self.response_id = None;
        self.session_id = None;
        self.revision = 0;
        self.active_signal = None;
    }

    pub fn apply_json(
        &mut self,
        line: &str,
        expected_control_token: &str,
        protocol_version: u64,
    ) -> Result<Snapshot, &'static str> {
        if self.fenced || !self.done_seen || self.response_id.is_some() || self.session_id.is_some()
        {
            self.clear_and_fence();
            return Err("response feedback target is outside its terminal window");
        }
        let result = self.apply_json_inner(line, expected_control_token, protocol_version);
        if result.is_err() {
            self.clear_and_fence();
        }
        result
    }

    fn apply_json_inner(
        &mut self,
        line: &str,
        expected_control_token: &str,
        protocol_version: u64,
    ) -> Result<Snapshot, &'static str> {
        if line.len() > MAX_RESPONSE_FEEDBACK_TARGET_BYTES {
            return Err("response feedback target exceeds its bounded schema");
        }
        let mut frame = serde_json::from_str::<TargetFrame>(line)
            .map_err(|_| "invalid response feedback target schema")?;
        if frame.neoth_stream != "response_feedback_target"
            || frame.protocol_version != protocol_version
            || frame.request_id != self.request_id.as_str()
            || frame.control_token != expected_control_token
        {
            return Err("forged or stale response feedback target");
        }
        let status = TargetStatus::parse(frame.status.as_str())
            .ok_or("unknown response feedback target status")?;
        match status {
            TargetStatus::Ready => {
                let (Some(response_id), Some(session_id), Some(revision)) = (
                    frame.response_id.take(),
                    frame.session_id.take(),
                    frame.revision.take(),
                ) else {
                    return Err("ready response feedback target is missing identity");
                };
                if !is_response_id(response_id.as_str()) || !is_session_id(session_id.as_str()) {
                    return Err("invalid response feedback target identity");
                }
                self.response_id = Some(Zeroizing::new(response_id));
                self.session_id = Some(Zeroizing::new(session_id));
                self.revision = revision;
            }
            TargetStatus::Unavailable => {
                if frame.response_id.is_some()
                    || frame.session_id.is_some()
                    || frame.revision.is_some()
                {
                    return Err("unavailable response feedback target must not carry identity");
                }
            }
        }
        self.target_status = status;
        Ok(self.snapshot())
    }

    /// Claim the one-use local action lease. The worker must return a typed
    /// receipt and a fresh exact status readback before calling
    /// `finish_verified_action`.
    pub fn begin_action(&mut self, action: Action) -> Option<ActionTarget> {
        let snapshot = self.snapshot();
        if !snapshot.available || snapshot.running {
            return None;
        }
        let (Some(response_id), Some(session_id)) = (&self.response_id, &self.session_id) else {
            return None;
        };
        self.running = true;
        Some(ActionTarget {
            response_id: response_id.clone(),
            session_id: session_id.clone(),
            revision: self.revision,
            action,
        })
    }

    /// Commit only an exact, fresh readback of the same target at the receipt
    /// revision. Any mismatch is unavailable; it can never retry against a
    /// newer response or silently select an optimistic state.
    pub fn finish_verified_action(
        &mut self,
        target: &ActionTarget,
        revision: u64,
        active_signal: Option<FeedbackSignal>,
    ) -> Result<Snapshot, &'static str> {
        let same_target = self
            .response_id
            .as_deref()
            .is_some_and(|id| id == target.response_id())
            && self
                .session_id
                .as_deref()
                .is_some_and(|id| id == target.session_id());
        if !self.running || !same_target || revision < target.revision() {
            self.clear_and_fence();
            return Err("response feedback receipt/readback did not bind the current target");
        }
        self.running = false;
        self.revision = revision;
        self.active_signal = active_signal;
        Ok(self.snapshot())
    }

    pub fn fail_action(&mut self) -> Snapshot {
        self.clear_and_fence();
        self.snapshot()
    }
}

fn is_response_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_session_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SESSION_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(status: &str, response_id: &str, session_id: &str, revision: u64) -> String {
        serde_json::json!({
            "neoth_stream": "response_feedback_target", "protocol_version": 3,
            "request_id": "request-a", "control_token": "token-a",
            "response_id": if response_id.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(response_id.into()) },
            "session_id": if session_id.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(session_id.into()) },
            "revision": if status == "unavailable" { serde_json::Value::Null } else { serde_json::json!(revision) }, "status": status,
        }).to_string()
    }

    #[test]
    fn target_becomes_actionable_only_after_done_then_exact_authenticated_frame() {
        let mut projection = Projection::new("request-a".into());
        assert!(
            projection
                .apply_json(
                    &target("ready", "aabbccddeeff00112233445566778899", "session-a", 0),
                    "token-a",
                    3
                )
                .is_err()
        );
        projection = Projection::new("request-a".into());
        projection.stream_done();
        let snapshot = projection
            .apply_json(
                &target("ready", "aabbccddeeff00112233445566778899", "session-a", 0),
                "token-a",
                3,
            )
            .expect("post-drain target");
        assert!(snapshot.available);
        assert!(!snapshot.running);
    }

    #[test]
    fn malformed_forged_and_unavailable_frames_never_publish_an_id() {
        for frame in [
            r#"{"neoth_stream":"response_feedback_target","protocol_version":3,"request_id":"request-a","control_token":"token-a","response_id":"aabbccddeeff00112233445566778899","session_id":"session-a","revision":0,"status":"ready","reply":"private"}"#.to_string(),
            target("ready", "AABBCCDDEEFF00112233445566778899", "session-a", 0),
            target("unavailable", "aabbccddeeff00112233445566778899", "session-a", 0),
        ] {
            let mut projection = Projection::new("request-a".into());
            projection.stream_done();
            assert!(projection.apply_json(&frame, "token-a", 3).is_err());
            assert!(!projection.snapshot().available);
        }
    }

    #[test]
    fn action_is_singleflight_and_only_exact_fresh_readback_can_repaint_it() {
        let mut projection = Projection::new("request-a".into());
        projection.stream_done();
        projection
            .apply_json(
                &target("ready", "aabbccddeeff00112233445566778899", "session-a", 2),
                "token-a",
                3,
            )
            .expect("target");
        let action = projection
            .begin_action(Action::Set(FeedbackSignal::Accepted))
            .expect("first action");
        assert!(projection.begin_action(Action::Remove).is_none());
        let snapshot = projection
            .finish_verified_action(&action, 3, Some(FeedbackSignal::Accepted))
            .expect("fresh readback");
        assert!(!snapshot.running);
        assert_eq!(
            snapshot.active_signal,
            Some(FeedbackSignal::Accepted)
        );

        let stale = projection
            .begin_action(Action::Remove)
            .expect("new lease after receipt");
        assert!(projection.finish_verified_action(&stale, 2, None).is_err());
        assert!(!projection.snapshot().available);
    }
}
