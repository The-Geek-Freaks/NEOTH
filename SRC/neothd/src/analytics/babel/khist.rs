//! GOLD-DELTA-16 — in-process K_d histogram feed.
//!
//! The WAL never carries response text (by design), so K_d — mean pairwise
//! cosine similarity of output token-frequency histograms — cannot come
//! from a WAL scan. This module is the live bridge: the inference response
//! paths call [`submit_response_text`] which reduces the text to a
//! content-free `token_hash → count` histogram IN PLACE (the text is read
//! once and dropped; only counts cross the channel), and the Babel daemon
//! drains the channel each tick.
//!
//! Discipline: the observer must NEVER block inference. The channel is
//! bounded and submission is `try_send` — when the observer isn't running
//! or the buffer is full, samples are silently dropped (a thinner K_d
//! sample beats a stalled reply path).

use std::collections::HashMap;
use std::sync::OnceLock;

use tokio::sync::mpsc;

/// One content-free response sample.
pub struct KHistSample {
    pub ts_unix: i64,
    pub histogram: HashMap<u32, u32>,
}

static FEED: OnceLock<mpsc::Sender<KHistSample>> = OnceLock::new();

/// Register the observer end of the feed. First caller wins (the Babel
/// daemon at spawn); `None` means a receiver already exists — the caller
/// should run without a live K_d feed rather than fight over it.
pub fn register(capacity: usize) -> Option<mpsc::Receiver<KHistSample>> {
    let (tx, rx) = mpsc::channel(capacity.max(1));
    FEED.set(tx).ok()?;
    Some(rx)
}

/// Token-frequency histogram: whitespace tokens → xxh3-64 folded to u32.
/// K_d_v0 (`feature.rs`) computes cosine similarity over these sparse maps.
pub fn histogram_of(text: &str) -> HashMap<u32, u32> {
    let mut h: HashMap<u32, u32> = HashMap::new();
    for tok in text.split_whitespace() {
        let key = (xxhash_rust::xxh3::xxh3_64(tok.as_bytes()) & 0xFFFF_FFFF) as u32;
        *h.entry(key).or_insert(0) += 1;
    }
    h
}

/// Fire-and-forget submission from an inference response path.
pub fn submit_response_text(ts_unix: i64, text: &str) {
    let Some(tx) = FEED.get() else { return };
    if text.is_empty() {
        return;
    }
    let sample = KHistSample { ts_unix, histogram: histogram_of(text) };
    // Drop-on-full / drop-on-closed by design: the observer never blocks
    // or errors the reply path.
    let _ = tx.try_send(sample);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_counts_repeated_tokens() {
        let h = histogram_of("the cat and the dog");
        assert_eq!(h.values().sum::<u32>(), 5, "5 tokens total");
        assert_eq!(h.len(), 4, "4 distinct tokens");
        assert!(h.values().any(|&c| c == 2), "'the' counted twice");
        assert!(histogram_of("").is_empty());
    }

    /// OnceLock is process-global — register/submit/drain lives in ONE test
    /// so parallel lib tests never fight over the slot.
    #[test]
    fn register_submit_drain_roundtrip_and_second_register_fails() {
        let mut rx = register(8).expect("first register wins");
        assert!(register(8).is_none(), "second register refused");
        submit_response_text(100, "alpha beta alpha");
        submit_response_text(101, "");
        let sample = rx.try_recv().expect("sample delivered");
        assert_eq!(sample.ts_unix, 100);
        assert_eq!(sample.histogram.values().sum::<u32>(), 3);
        assert!(rx.try_recv().is_err(), "empty text never submitted");
    }
}
