//! Bounded visible-text to configured-TTS batching for A5.

use std::collections::VecDeque;

const MAX_SENTENCES_PER_BATCH: usize = 3;
const MAX_QUEUED_SENTENCES: usize = 64;
const MAX_BUFFERED_REQUESTS: usize = 4;

/// The provider bridge has already removed reasoning/notice frames.  This
/// processor treats text as untrusted framing and admits at most one
/// configured-TTS request of completed sentences at a time.
///
/// `max_chars` is a Unicode-scalar limit, matching
/// `TtsDispatcherConfig::max_chars_per_request` and its dispatcher check.
/// At most four configured requests' worth of scalars and 64 completed
/// sentences are retained. UTF-8 payload is therefore at most
/// `4 * max_chars * 4` bytes before allocator overhead.
#[derive(Debug)]
pub(crate) struct LmOutputProcessor {
    max_chars: usize,
    max_buffered_chars: usize,
    pending_chars: usize,
    pending: String,
    complete_chars: usize,
    complete: VecDeque<String>,
    terminal_flushed: bool,
}

impl LmOutputProcessor {
    pub(crate) fn new(max_chars: usize) -> Result<Self, &'static str> {
        if max_chars == 0 {
            return Err("tts_max_chars_must_be_positive");
        }
        let max_buffered_chars = max_chars
            .checked_mul(MAX_BUFFERED_REQUESTS)
            .ok_or("tts_max_chars_exceeds_realtime_memory_bound")?;
        Ok(Self {
            max_chars,
            max_buffered_chars,
            pending_chars: 0,
            pending: String::new(),
            complete_chars: 0,
            complete: VecDeque::new(),
            terminal_flushed: false,
        })
    }

    pub(crate) fn push_visible_delta(&mut self, delta: &str) -> Result<(), &'static str> {
        if self.terminal_flushed {
            return Err("visible_delta_after_terminal_flush");
        }
        for ch in delta.chars() {
            if self.complete_chars + self.pending_chars == self.max_buffered_chars {
                return Err("visible_text_exceeds_realtime_buffer_cap");
            }
            self.pending.push(ch);
            self.pending_chars += 1;
            if is_sentence_end(ch) {
                self.enqueue_pending_sentence()?;
            }
        }
        Ok(())
    }

    /// Return one bounded request containing up to three complete sentences.
    pub(crate) fn next_batch(&mut self) -> Option<String> {
        let mut batch = String::new();
        for _ in 0..MAX_SENTENCES_PER_BATCH {
            let Some(sentence) = self.complete.pop_front() else {
                break;
            };
            let sentence_chars = sentence.chars().count();
            self.complete_chars -= sentence_chars;
            if batch.is_empty() && sentence_chars > self.max_chars {
                let (head, tail) = split_utf8_at(&sentence, self.max_chars);
                if !tail.is_empty() {
                    self.complete.push_front(tail.to_owned());
                    self.complete_chars += tail.chars().count();
                }
                return Some(head.to_owned());
            }
            let batch_chars = batch.chars().count();
            let separator = usize::from(!batch.is_empty());
            if batch_chars
                .saturating_add(separator)
                .saturating_add(sentence_chars)
                > self.max_chars
            {
                self.complete.push_front(sentence);
                self.complete_chars += sentence_chars;
                break;
            }
            if !batch.is_empty() {
                batch.push(' ');
            }
            batch.push_str(&sentence);
        }
        (!batch.is_empty()).then_some(batch)
    }

    pub(crate) fn flush_terminal(&mut self) -> Result<(), &'static str> {
        if self.terminal_flushed {
            return Ok(());
        }
        if self.pending.trim().is_empty() {
            self.pending.clear();
            self.pending_chars = 0;
        } else {
            self.enqueue_pending_sentence()?;
        }
        self.terminal_flushed = true;
        Ok(())
    }

    fn enqueue_pending_sentence(&mut self) -> Result<(), &'static str> {
        if self.pending.trim().is_empty() {
            self.pending.clear();
            self.pending_chars = 0;
            return Ok(());
        }
        if self.complete.len() == MAX_QUEUED_SENTENCES {
            return Err("completed_tts_sentence_queue_full");
        }
        let sentence = std::mem::take(&mut self.pending);
        self.pending_chars = 0;
        let sentence = sentence.trim();
        if !sentence.is_empty() {
            self.complete_chars += sentence.chars().count();
            self.complete.push_back(sentence.to_owned());
        }
        Ok(())
    }
}

fn is_sentence_end(ch: char) -> bool {
    matches!(ch, '.' | '!' | '?' | '\n')
}

fn split_utf8_at(value: &str, cap_chars: usize) -> (&str, &str) {
    let boundary = value
        .char_indices()
        .nth(cap_chars)
        .map_or(value.len(), |(index, _)| index);
    value.split_at(boundary)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn batches_three_sentences_and_flushes_final_fragment_once() {
        let mut out = LmOutputProcessor::new(64).unwrap();
        out.push_visible_delta("One. Two? Three! Four").unwrap();
        assert_eq!(out.next_batch().as_deref(), Some("One. Two? Three!"));
        out.flush_terminal().unwrap();
        assert_eq!(out.next_batch().as_deref(), Some("Four"));
        assert_eq!(out.next_batch(), None);
    }

    #[test]
    fn repeated_unterminated_deltas_fail_before_pending_growth() {
        let mut out = LmOutputProcessor::new(1).unwrap();
        out.push_visible_delta("a").unwrap();
        out.push_visible_delta("b").unwrap();
        out.push_visible_delta("c").unwrap();
        out.push_visible_delta("d").unwrap();
        assert_eq!(
            out.push_visible_delta("e"),
            Err("visible_text_exceeds_realtime_buffer_cap")
        );
        out.flush_terminal().unwrap();
        assert_eq!(out.next_batch().as_deref(), Some("a"));
    }

    #[test]
    fn multibyte_limits_are_unicode_scalar_limits() {
        let mut out = LmOutputProcessor::new(2).unwrap();
        out.push_visible_delta("é.").unwrap();
        assert_eq!(out.next_batch().as_deref(), Some("é."));

        let mut one = LmOutputProcessor::new(1).unwrap();
        one.push_visible_delta("éééé").unwrap();
        assert_eq!(
            one.push_visible_delta("x"),
            Err("visible_text_exceeds_realtime_buffer_cap")
        );
        assert_eq!(split_utf8_at("éx", 1), ("é", "x"));
    }

    #[test]
    fn repeated_terminal_flush_preserves_order_and_never_duplicates_tail() {
        let mut out = LmOutputProcessor::new(32).unwrap();
        out.push_visible_delta("First. Last").unwrap();
        out.flush_terminal().unwrap();
        out.flush_terminal().unwrap();
        assert_eq!(out.next_batch().as_deref(), Some("First. Last"));
        assert_eq!(out.next_batch(), None);
        assert_eq!(
            out.push_visible_delta("ignored"),
            Err("visible_delta_after_terminal_flush")
        );
    }

    #[test]
    fn coalesced_four_sentence_delta_yields_two_batches() {
        let mut out = LmOutputProcessor::new(16).unwrap();
        out.push_visible_delta("One. Two. Three. Four.").unwrap();
        assert_eq!(out.next_batch().as_deref(), Some("One. Two. Three."));
        assert_eq!(out.next_batch().as_deref(), Some("Four."));
    }

    #[test]
    fn completed_queue_rejects_before_sixty_fifth_sentence_grows_it() {
        let mut out = LmOutputProcessor::new(1_000).unwrap();
        let delta = "a. ".repeat(MAX_QUEUED_SENTENCES + 1);
        assert_eq!(
            out.push_visible_delta(&delta),
            Err("completed_tts_sentence_queue_full")
        );
        assert_eq!(out.next_batch().as_deref(), Some("a. a. a."));
    }
}
