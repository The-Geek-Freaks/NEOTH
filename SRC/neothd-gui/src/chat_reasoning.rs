//! Request-owned GUI reasoning controls. This reducer is deliberately separate
//! from the visible chat stream, transcript model, preview, and Buddy recents.

use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_REASONING_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalState {
    Unsupported,
    Hidden,
    Redacted,
    Complete,
    Cancelled,
}

impl TerminalState {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "unsupported" => Self::Unsupported,
            "hidden" => Self::Hidden,
            "redacted" => Self::Redacted,
            "complete" => Self::Complete,
            "cancelled" => Self::Cancelled,
            _ => return None,
        })
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Unsupported => "unsupported",
            Self::Hidden => "hidden",
            Self::Redacted => "redacted",
            Self::Complete => "complete",
            Self::Cancelled => "cancelled",
        }
    }
}

pub struct Projection {
    request_id: String,
    granted: bool,
    next_sequence: u64,
    terminal: Option<TerminalState>,
    event_count: u64,
    byte_count: u64,
    text: Zeroizing<String>,
}

impl std::fmt::Debug for Projection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Projection")
            .field("request_id", &self.request_id)
            .field("granted", &self.granted)
            .field("next_sequence", &self.next_sequence)
            .field("terminal", &self.terminal)
            .field("event_count", &self.event_count)
            .field("byte_count", &self.byte_count)
            .field("text", &"<redacted>")
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeltaFrame {
    neoth_stream: String,
    protocol_version: u64,
    request_id: String,
    control_token: String,
    sequence: u64,
    delta: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateFrame {
    neoth_stream: String,
    protocol_version: u64,
    request_id: String,
    control_token: String,
    sequence: u64,
    state: String,
    event_count: u64,
    byte_count: u64,
}

/// A short-lived view of a request-owned projection.  The caller must only
/// copy this into the matching live surface and must discard it as soon as the
/// request ceases to own that surface.
#[derive(Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub status: &'static str,
    pub text: Zeroizing<String>,
    pub active: bool,
    pub terminal: bool,
}

impl std::fmt::Debug for Snapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Snapshot")
            .field("status", &self.status)
            .field("text", &"<redacted>")
            .field("active", &self.active)
            .field("terminal", &self.terminal)
            .finish()
    }
}

impl Projection {
    pub fn new(request_id: String, granted: bool) -> Self {
        Self {
            request_id,
            granted,
            next_sequence: 1,
            terminal: None,
            event_count: 0,
            byte_count: 0,
            text: Zeroizing::new(String::new()),
        }
    }

    pub fn clear(&mut self) {
        self.text.zeroize();
        self.text.clear();
        self.terminal = None;
        self.next_sequence = 1;
        self.event_count = 0;
        self.byte_count = 0;
    }

    pub fn active(&self) -> bool {
        self.granted && self.terminal.is_none() && !self.text.is_empty()
    }
    pub fn status(&self) -> &'static str {
        self.terminal
            .map(TerminalState::label)
            .unwrap_or(if self.granted { "receiving" } else { "hidden" })
    }
    pub fn text(&self) -> &str {
        self.text.as_str()
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            status: self.status(),
            text: Zeroizing::new(self.text().to_owned()),
            active: self.active(),
            terminal: self.terminal.is_some(),
        }
    }

    pub fn apply_json(
        &mut self,
        line: &str,
        expected_token: &str,
        protocol_version: u64,
    ) -> Result<(), &'static str> {
        let result = self.apply_json_inner(line, expected_token, protocol_version);
        if matches!(
            result.as_ref(),
            Err(error) if *error != "gapped or duplicate reasoning delta"
        ) {
            // A rejected sequence frame cannot mutate this projection, so a
            // later terminal frame with the retained counters remains valid.
            // Other malformed or forged controls invalidate this exact
            // request-owned slot; delivery guards prevent stale work from
            // erasing a newer request.
            self.clear();
        }
        result
    }

    fn apply_json_inner(
        &mut self,
        line: &str,
        expected_token: &str,
        protocol_version: u64,
    ) -> Result<(), &'static str> {
        // Decode only strict typed frames. This rejects duplicate and unknown
        // keys without first materializing raw reasoning in a JSON Value.
        if let Ok(frame) = serde_json::from_str::<DeltaFrame>(line) {
            let mut kind = Zeroizing::new(frame.neoth_stream);
            let mut request_id = Zeroizing::new(frame.request_id);
            let mut control_token = Zeroizing::new(frame.control_token);
            if kind.as_str() != "reasoning_delta" {
                return Err("unexpected reasoning delta shape");
            }
            if control_token.as_str() != expected_token
                || request_id.as_str() != self.request_id
                || frame.protocol_version != protocol_version
            {
                return Err("forged or stale reasoning control");
            }
            if self.terminal.is_some() {
                return Err("reasoning after terminal");
            }
            let mut delta = Zeroizing::new(frame.delta);
            if frame.sequence != self.next_sequence || delta.is_empty() {
                return Err("gapped or duplicate reasoning delta");
            }
            let next = self.byte_count.saturating_add(delta.len() as u64);
            if next as usize > MAX_REASONING_BYTES {
                return Err("reasoning byte limit exceeded");
            }
            self.next_sequence = self.next_sequence.saturating_add(1);
            self.event_count = self.event_count.saturating_add(1);
            self.byte_count = next;
            if self.granted {
                self.text.push_str(delta.as_str());
            }
            delta.zeroize();
            kind.zeroize();
            request_id.zeroize();
            control_token.zeroize();
            return Ok(());
        }
        if let Ok(frame) = serde_json::from_str::<StateFrame>(line) {
            let mut kind = Zeroizing::new(frame.neoth_stream);
            let mut request_id = Zeroizing::new(frame.request_id);
            let mut control_token = Zeroizing::new(frame.control_token);
            if kind.as_str() != "reasoning_state" {
                return Err("unexpected reasoning state shape");
            }
            if control_token.as_str() != expected_token
                || request_id.as_str() != self.request_id
                || frame.protocol_version != protocol_version
            {
                return Err("forged or stale reasoning control");
            }
            if self.terminal.is_some() {
                return Err("duplicate reasoning terminal");
            }
            let state = TerminalState::parse(&frame.state).ok_or("unknown reasoning state")?;
            if frame.sequence != self.next_sequence
                || frame.event_count != self.event_count
                || frame.byte_count != self.byte_count
            {
                return Err("reasoning terminal counters mismatch");
            }
            self.terminal = Some(state);
            self.text.zeroize();
            self.text.clear();
            kind.zeroize();
            request_id.zeroize();
            control_token.zeroize();
            return Ok(());
        }
        Err("unexpected reasoning control shape")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn frame(kind: &str, sequence: u64, extra: serde_json::Value) -> String {
        let mut value = serde_json::json!({"neoth_stream":kind,"protocol_version":3,"request_id":"request","control_token":"token","sequence":sequence});
        value
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        value.to_string()
    }
    #[test]
    fn strict_sequence_limit_and_terminal_clear() {
        let mut projection = Projection::new("request".into(), true);
        assert!(
            projection
                .apply_json(
                    &frame("reasoning_delta", 1, serde_json::json!({"delta":"private"})),
                    "token",
                    3
                )
                .is_ok()
        );
        assert_eq!(projection.text(), "private");
        assert!(
            projection
                .apply_json(
                    &frame(
                        "reasoning_delta",
                        1,
                        serde_json::json!({"delta":"duplicate"})
                    ),
                    "token",
                    3
                )
                .is_err()
        );
        assert!(
            projection
                .apply_json(
                    &frame(
                        "reasoning_state",
                        2,
                        serde_json::json!({"state":"complete","event_count":1,"byte_count":7})
                    ),
                    "token",
                    3
                )
                .is_ok()
        );
        assert!(projection.text().is_empty());
        assert!(!projection.active());
    }

    #[test]
    fn duplicate_or_forged_frame_clears_the_exact_projection() {
        let mut projection = Projection::new("request".into(), true);
        assert!(
            projection
                .apply_json(
                    &frame("reasoning_delta", 1, serde_json::json!({"delta":"private"})),
                    "token",
                    3
                )
                .is_ok()
        );
        let duplicate_key = r#"{"neoth_stream":"reasoning_delta","neoth_stream":"reasoning_delta","protocol_version":3,"request_id":"request","control_token":"token","sequence":2,"delta":"forged"}"#;
        assert!(projection.apply_json(duplicate_key, "token", 3).is_err());
        assert!(
            projection.text().is_empty(),
            "invalid input zeroizes retained bytes"
        );
        assert_eq!(projection.status(), "receiving");
        assert!(
            projection
                .apply_json(
                    &frame("reasoning_delta", 2, serde_json::json!({"delta":"stale"})),
                    "wrong",
                    3
                )
                .is_err()
        );
        assert!(projection.text().is_empty());
    }

    #[test]
    fn default_off_counts_controls_without_retaining_text() {
        let mut projection = Projection::new("request".into(), false);
        assert!(
            projection
                .apply_json(
                    &frame(
                        "reasoning_delta",
                        1,
                        serde_json::json!({"delta":"not retained"})
                    ),
                    "token",
                    3
                )
                .is_ok()
        );
        assert!(projection.text().is_empty());
        assert!(!projection.active());
        assert_eq!(projection.status(), "hidden");
    }
}
