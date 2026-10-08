//! Bounded, daemon-local replay storage shared by chat carriers.
//!
//! This owns retention only. Each carrier still owns authorization, sequence
//! allocation, output classification and terminal settlement.
use std::collections::VecDeque;

pub(super) trait ReplayPayload {
    fn replay_bytes(&self) -> usize;
    fn clear_replay_text(&mut self);
}

pub(super) struct ReplayFrame<P: ReplayPayload> {
    pub(super) sequence: u64,
    pub(super) payload: P,
    bytes: usize,
}

impl<P: ReplayPayload> ReplayFrame<P> {
    pub(super) fn new(sequence: u64, payload: P) -> Self {
        let bytes = payload.replay_bytes();
        Self {
            sequence,
            payload,
            bytes,
        }
    }
}

impl<P: ReplayPayload> Drop for ReplayFrame<P> {
    fn drop(&mut self) {
        self.payload.clear_replay_text();
    }
}

pub(super) struct ChatReplay<P: ReplayPayload> {
    frames: VecDeque<ReplayFrame<P>>,
    retained_bytes: usize,
    latest_sequence: u64,
    frame_limit: usize,
    byte_limit: usize,
}

impl<P: ReplayPayload> ChatReplay<P> {
    pub(super) fn new(frame_limit: usize, byte_limit: usize) -> Self {
        Self {
            frames: VecDeque::new(),
            retained_bytes: 0,
            latest_sequence: 0,
            frame_limit,
            byte_limit,
        }
    }

    pub(super) fn retain(&mut self, frame: ReplayFrame<P>) {
        self.latest_sequence = frame.sequence;
        self.retained_bytes = self.retained_bytes.saturating_add(frame.bytes);
        self.frames.push_back(frame);
        while self.frames.len() > self.frame_limit || self.retained_bytes > self.byte_limit {
            if let Some(evicted) = self.frames.pop_front() {
                self.retained_bytes = self.retained_bytes.saturating_sub(evicted.bytes);
                // ReplayFrame::drop clears the removed payload before release.
            }
        }
    }

    /// A cursor equal to this value can resume without missing retained output.
    /// An empty queue after eviction is still a gap for older cursors.
    pub(super) fn earliest_cursor(&self) -> u64 {
        self.frames
            .front()
            .map(|frame| frame.sequence.saturating_sub(1))
            .unwrap_or(self.latest_sequence)
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &ReplayFrame<P>> {
        self.frames.iter()
    }

    pub(super) fn clear(&mut self) {
        self.frames.clear();
        self.retained_bytes = 0;
        // Keep the cursor boundary: clearing text cannot make old output replayable.
    }

    #[cfg(any(test, feature = "gui-bridge-test-support"))]
    pub(super) fn len(&self) -> usize {
        self.frames.len()
    }

    #[cfg(test)]
    pub(super) fn front(&self) -> Option<&ReplayFrame<P>> {
        self.frames.front()
    }

    #[cfg(test)]
    pub(super) fn back(&self) -> Option<&ReplayFrame<P>> {
        self.frames.back()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use zeroize::Zeroize;

    struct Payload {
        text: String,
        cleared: Arc<Mutex<Vec<bool>>>,
    }

    impl ReplayPayload for Payload {
        fn replay_bytes(&self) -> usize {
            self.text.len()
        }

        fn clear_replay_text(&mut self) {
            self.text.zeroize();
            self.cleared.lock().unwrap().push(self.text.is_empty());
        }
    }

    fn frame(sequence: u64, text: &str, cleared: &Arc<Mutex<Vec<bool>>>) -> ReplayFrame<Payload> {
        ReplayFrame::new(
            sequence,
            Payload {
                text: text.to_owned(),
                cleared: cleared.clone(),
            },
        )
    }

    #[test]
    fn empty_after_oversized_frame_keeps_the_missing_cursor_boundary() {
        let cleared = Arc::new(Mutex::new(Vec::new()));
        let mut replay = ChatReplay::new(3, 4);
        assert_eq!(replay.earliest_cursor(), 0);
        replay.retain(frame(1, "ok", &cleared));
        replay.retain(frame(2, "oversized", &cleared));
        assert_eq!(replay.len(), 0);
        assert_eq!(replay.retained_bytes, 0);
        assert_eq!(replay.earliest_cursor(), 2);
        assert_eq!(*cleared.lock().unwrap(), vec![true, true]);
        replay.retain(frame(3, "", &cleared));
        assert_eq!(replay.earliest_cursor(), 2);
        assert_eq!(replay.front().unwrap().sequence, 3);
    }

    #[test]
    fn frame_and_utf8_byte_limits_keep_only_the_contiguous_tail() {
        let cleared = Arc::new(Mutex::new(Vec::new()));
        let mut replay = ChatReplay::new(2, 5);
        replay.retain(frame(1, "aaa", &cleared));
        replay.retain(frame(2, "ö", &cleared));
        assert_eq!(replay.retained_bytes, 5);
        replay.retain(frame(3, "bb", &cleared));
        assert_eq!(replay.earliest_cursor(), 1);
        assert_eq!(replay.retained_bytes, 4);
        replay.retain(frame(4, "", &cleared));
        assert_eq!(replay.earliest_cursor(), 2);
        assert_eq!(
            replay.iter().map(|item| item.sequence).collect::<Vec<_>>(),
            vec![3, 4]
        );
        assert_eq!(replay.retained_bytes, 2);
    }

    #[test]
    fn clear_and_drop_erase_each_owned_payload_once() {
        let cleared = Arc::new(Mutex::new(Vec::new()));
        {
            let mut replay = ChatReplay::new(2, 20);
            replay.retain(frame(1, "first", &cleared));
            replay.retain(frame(2, "second", &cleared));
            replay.clear();
            assert_eq!(replay.retained_bytes, 0);
            assert_eq!(replay.earliest_cursor(), 2);
            assert_eq!(*cleared.lock().unwrap(), vec![true, true]);
            replay.retain(frame(3, "last", &cleared));
        }
        assert_eq!(*cleared.lock().unwrap(), vec![true, true, true]);
    }

    #[test]
    fn zero_capacity_refuses_retention_without_resetting_the_cursor() {
        let cleared = Arc::new(Mutex::new(Vec::new()));
        let mut replay = ChatReplay::new(0, 0);
        replay.retain(frame(1, "", &cleared));
        assert_eq!(replay.len(), 0);
        assert_eq!(replay.earliest_cursor(), 1);
        assert_eq!(*cleared.lock().unwrap(), vec![true]);
    }

    #[test]
    fn replay_from_last_seen_sequence_never_duplicates_prior_text() {
        let cleared = Arc::new(Mutex::new(Vec::new()));
        let mut replay = ChatReplay::new(3, 20);
        for sequence in 1..=3 {
            replay.retain(frame(sequence, "delta", &cleared));
        }
        let after_two = replay
            .iter()
            .filter(|item| item.sequence > 2)
            .map(|item| (item.sequence, item.payload.text.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(after_two, vec![(3, "delta")]);
        assert_eq!(replay.back().unwrap().sequence, 3);
    }
}
