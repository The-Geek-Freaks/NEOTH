//! Request-owned visible output; no reasoning, GUI capabilities or transcript IDs.
use anyhow::Result;
use tokio::sync::watch;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::companion_protocol::{CompanionChatStreamSnapshot, COMPANION_STREAM_MAX_PREVIEW_BYTES};
use crate::cli::chat_turn_pipeline::{ChatOutput, ChatTurnEvent, ChatTurnEventSink};

pub(crate) struct CompanionStreamSink {
    text: Zeroizing<String>,
    sender: watch::Sender<CompanionChatStreamSnapshot>,
}
impl CompanionStreamSink {
    pub(super) fn new(request_id: Uuid) -> (Self, watch::Receiver<CompanionChatStreamSnapshot>) {
        let (sender, receiver) = watch::channel(CompanionChatStreamSnapshot {
            stream_schema_version: 1, request_id, revision: 0, text: String::new(), truncated: false,
        });
        (Self { text: Zeroizing::new(String::new()), sender }, receiver)
    }
    pub(super) fn response_text(&self) -> String { self.text.to_string() }

    fn accept_visible(&mut self, text: &str) -> Result<()> {
        // Check before allocating; a terminal never silently truncates text.
        anyhow::ensure!(self.text.len().saturating_add(text.len()) <= 64 * 1024, "companion output exceeds terminal cap");
        self.text.push_str(text);
        let mut end = self.text.len().min(COMPANION_STREAM_MAX_PREVIEW_BYTES);
        while !self.text.is_char_boundary(end) { end -= 1; }
        let preview = self.text[..end].to_owned();
        let truncated = end < self.text.len();
        self.sender.send_modify(|snapshot| {
            snapshot.revision = snapshot.revision.saturating_add(1);
            snapshot.text = preview;
            snapshot.truncated = truncated;
        });
        Ok(())
    }
}
impl ChatTurnEventSink for CompanionStreamSink {
    fn emit(&mut self, event: ChatTurnEvent) -> Result<()> {
        match event {
            ChatTurnEvent::Output(ChatOutput::ProviderDelta { text, .. }) =>
                self.accept_visible(&text),
            ChatTurnEvent::Output(ChatOutput::DeferredProviderFrames { accepted_body, .. }) =>
                self.accept_visible(&accepted_body),
            // No stdout reconstruction, reasoning, recall, internal notices,
            // replay scoring body or GUI feedback identifiers cross this sink.
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn visible_snapshots_coalesce_without_losing_text_or_duplicating_terminal() {
        let (mut sink, receiver) = CompanionStreamSink::new(Uuid::nil());
        sink.emit(ChatTurnEvent::Output(ChatOutput::ProviderDelta { sequence: 1, text: "first ".into(), stream_control_token: None })).unwrap();
        sink.emit(ChatTurnEvent::Output(ChatOutput::ProviderDelta { sequence: 2, text: "second".into(), stream_control_token: None })).unwrap();
        let snapshot = receiver.borrow();
        assert_eq!(snapshot.revision, 2);
        assert_eq!(snapshot.text, "first second");
        assert_eq!(sink.response_text(), "first second");
        assert!(!snapshot.truncated);
    }
    #[test]
    fn preview_bound_preserves_utf8_and_full_terminal_or_errors_before_growth() {
        let (mut sink, receiver) = CompanionStreamSink::new(Uuid::nil());
        let text = "€".repeat(4000);
        sink.accept_visible(&text).unwrap();
        let snapshot = receiver.borrow().clone();
        assert!(snapshot.truncated);
        assert!(snapshot.text.len() <= COMPANION_STREAM_MAX_PREVIEW_BYTES);
        assert!(text.starts_with(&snapshot.text));
        assert_eq!(sink.response_text(), text);
        assert!(sink.accept_visible(&"x".repeat(64 * 1024)).is_err());
        assert_eq!(receiver.borrow().revision, 1);
        assert_eq!(sink.response_text(), text);
    }
    #[test]
    fn private_and_plain_outputs_do_not_become_stream_text() {
        let (mut sink, receiver) = CompanionStreamSink::new(Uuid::nil());
        sink.emit(ChatTurnEvent::Output(ChatOutput::HumanStdout { text: "terminal duplicate".into() })).unwrap();
        sink.emit(ChatTurnEvent::Output(ChatOutput::HumanStderr { text: "private error".into() })).unwrap();
        sink.emit(ChatTurnEvent::Output(ChatOutput::Notice { stream: true, text: "private notice".into() })).unwrap();
        assert_eq!(receiver.borrow().revision, 0);
        assert!(sink.response_text().is_empty());
    }
}
