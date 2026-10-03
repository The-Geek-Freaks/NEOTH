//! A2 turn ownership: a qualified utterance is committed once, while a short
//! pause may reopen the same uncommitted utterance without producing a second
//! provider request.

use std::time::Duration;

/// The conversation loop keeps this state next to the Silero assembler.  It
/// does not decide speech; it records what the assembler already proved.
#[derive(Debug, Default)]
pub(crate) struct TurnTracker {
    next_turn: u64,
    open: Option<OpenTurn>,
}

#[derive(Debug)]
struct OpenTurn {
    id: u64,
    speech_ms: u64,
    committed: bool,
    soft_ended: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TurnDisposition {
    /// A short fragment is discarded before it can make an STT/provider call.
    CancelShortFragment,
    /// A previously soft-ended, still-uncommitted utterance resumed.
    Reopened { turn_id: u64 },
    /// Exactly one qualified STT hand-off is admitted for this turn.
    Commit { turn_id: u64 },
    /// The completed turn was already committed and may not be replayed.
    AlreadyCommitted { turn_id: u64 },
}

impl TurnTracker {
    pub(crate) fn begin_speech(&mut self) -> TurnDisposition {
        if let Some(open) = self.open.as_mut() {
            if open.soft_ended && !open.committed {
                open.soft_ended = false;
                return TurnDisposition::Reopened { turn_id: open.id };
            }
        }
        self.next_turn = self.next_turn.saturating_add(1);
        self.open = Some(OpenTurn {
            id: self.next_turn,
            speech_ms: 0,
            committed: false,
            soft_ended: false,
        });
        TurnDisposition::Reopened {
            turn_id: self.next_turn,
        }
    }

    pub(crate) fn add_speech(&mut self, duration: Duration) {
        if let Some(open) = self.open.as_mut() {
            open.speech_ms = open
                .speech_ms
                .saturating_add(duration.as_millis().min(u64::MAX as u128) as u64);
        }
    }

    /// A VAD hangover is a soft boundary.  The owner may reopen it until the
    /// resulting utterance crosses the configured minimum and is committed.
    pub(crate) fn soft_end(&mut self) {
        if let Some(open) = self.open.as_mut() {
            open.soft_ended = true;
        }
    }

    pub(crate) fn ready(&mut self, min_fragment_ms: u64) -> TurnDisposition {
        let Some(open) = self.open.as_mut() else {
            return TurnDisposition::CancelShortFragment;
        };
        if open.speech_ms < min_fragment_ms {
            self.open = None;
            return TurnDisposition::CancelShortFragment;
        }
        if open.committed {
            return TurnDisposition::AlreadyCommitted { turn_id: open.id };
        }
        open.committed = true;
        open.soft_ended = false;
        TurnDisposition::Commit { turn_id: open.id }
    }

    pub(crate) fn clear_uncommitted(&mut self) {
        if self.open.as_ref().is_some_and(|turn| !turn.committed) {
            self.open = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn speculative_pause_reopens_once_but_committed_turn_never_replays() {
        let mut turns = TurnTracker::default();
        assert!(matches!(
            turns.begin_speech(),
            TurnDisposition::Reopened { turn_id: 1 }
        ));
        turns.add_speech(Duration::from_millis(60));
        turns.soft_end();
        assert!(matches!(
            turns.begin_speech(),
            TurnDisposition::Reopened { turn_id: 1 }
        ));
        turns.add_speech(Duration::from_millis(60));
        assert_eq!(turns.ready(100), TurnDisposition::Commit { turn_id: 1 });
        assert_eq!(
            turns.ready(100),
            TurnDisposition::AlreadyCommitted { turn_id: 1 }
        );
    }

    #[test]
    fn short_fragment_never_reaches_a_turn_commit() {
        let mut turns = TurnTracker::default();
        turns.begin_speech();
        turns.add_speech(Duration::from_millis(99));
        assert_eq!(turns.ready(100), TurnDisposition::CancelShortFragment);
    }
}
