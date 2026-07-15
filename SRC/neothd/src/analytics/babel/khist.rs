//! Bounded in-process K_d feed.
//!
//! `None` in `babel.k_d_embedding_model` keeps the original K_d_v0 token
//! histogram path unchanged.  An explicit model switches the feed to local
//! `EmbedProvider` inference: response text is truncated in-process, embedded
//! at the source, then dropped; only a vector or a closed failure code crosses
//! the channel.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

use tokio::sync::{Semaphore, mpsc};

use crate::providers::embed::{EmbedProvider, EmbedRequest};

pub const MAX_EMBED_INPUT_CHARS: usize = 4_096;
pub const MAX_EMBED_DIM: usize = 16_384;
const MAX_EMBED_IN_FLIGHT: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KdFailureReason {
    ProviderUnavailable,
    RuntimeUnavailable,
    Backpressure,
    ProviderError,
    InvalidVector,
    SampleCap,
}

impl KdFailureReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProviderUnavailable => "provider_unavailable",
            Self::RuntimeUnavailable => "runtime_unavailable",
            Self::Backpressure => "backpressure",
            Self::ProviderError => "provider_error",
            Self::InvalidVector => "invalid_vector",
            Self::SampleCap => "sample_cap",
        }
    }
}

#[derive(Debug)]
pub enum KSampleValue {
    Histogram(HashMap<u32, u32>),
    Embedding {
        vector: Vec<f32>,
        model_identity: String,
    },
    EmbeddingFailure {
        model_identity: String,
        reason: KdFailureReason,
    },
}

#[derive(Debug)]
pub struct KSample {
    pub ts_unix: i64,
    pub value: KSampleValue,
}

#[derive(Clone)]
pub enum KdFeedMode {
    HistogramV0,
    EmbeddingV1 {
        requested_model: String,
        provider: Option<Arc<dyn EmbedProvider>>,
    },
}

struct FeedState {
    generation: u64,
    tx: mpsc::Sender<KSample>,
    mode: KdFeedMode,
    permits: Arc<Semaphore>,
}

static FEED: OnceLock<RwLock<Option<Arc<FeedState>>>> = OnceLock::new();
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

fn feed() -> &'static RwLock<Option<Arc<FeedState>>> {
    FEED.get_or_init(|| RwLock::new(None))
}

pub struct KReceiver {
    generation: u64,
    rx: mpsc::Receiver<KSample>,
}

impl KReceiver {
    pub fn try_recv(&mut self) -> Result<KSample, mpsc::error::TryRecvError> {
        self.rx.try_recv()
    }
}

impl Drop for KReceiver {
    fn drop(&mut self) {
        let Ok(mut slot) = feed().write() else {
            return;
        };
        if slot
            .as_ref()
            .is_some_and(|state| state.generation == self.generation)
        {
            *slot = None;
        }
    }
}

/// Register (or replace after a daemon reload) the observer end.
pub fn register(capacity: usize, mode: KdFeedMode) -> KReceiver {
    let (tx, rx) = mpsc::channel(capacity.max(1));
    let generation = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
    let state = Arc::new(FeedState {
        generation,
        tx,
        mode,
        permits: Arc::new(Semaphore::new(MAX_EMBED_IN_FLIGHT)),
    });
    if let Ok(mut slot) = feed().write() {
        *slot = Some(state);
    }
    KReceiver { generation, rx }
}

/// Token-frequency histogram: whitespace tokens -> xxh3-64 folded to u32.
/// This is the original byte-for-byte K_d_v0 reduction.
pub fn histogram_of(text: &str) -> HashMap<u32, u32> {
    let mut h: HashMap<u32, u32> = HashMap::new();
    for tok in text.split_whitespace() {
        let key = (xxhash_rust::xxh3::xxh3_64(tok.as_bytes()) & 0xFFFF_FFFF) as u32;
        *h.entry(key).or_insert(0) += 1;
    }
    h
}

pub fn bounded_model_identity(s: &str) -> String {
    s.chars()
        .take(128)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.' | ':') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn submit_failure(state: &FeedState, ts_unix: i64, model: &str, reason: KdFailureReason) {
    let _ = state.tx.try_send(KSample {
        ts_unix,
        value: KSampleValue::EmbeddingFailure {
            model_identity: bounded_model_identity(model),
            reason,
        },
    });
}

/// Source-side submission. Histogram mode remains synchronous/non-blocking.
/// Embedding mode launches at most two local jobs; overflow becomes an
/// explicit content-free degraded sample instead of an unbounded task queue.
pub fn submit_response_text(ts_unix: i64, text: &str) {
    if text.is_empty() {
        return;
    }
    let state = match feed().read() {
        Ok(slot) => slot.clone(),
        Err(_) => None,
    };
    let Some(state) = state else { return };
    match &state.mode {
        KdFeedMode::HistogramV0 => {
            let _ = state.tx.try_send(KSample {
                ts_unix,
                value: KSampleValue::Histogram(histogram_of(text)),
            });
        }
        KdFeedMode::EmbeddingV1 {
            requested_model,
            provider,
        } => {
            let Some(provider) = provider.clone() else {
                submit_failure(
                    &state,
                    ts_unix,
                    requested_model,
                    KdFailureReason::ProviderUnavailable,
                );
                return;
            };
            if tokio::runtime::Handle::try_current().is_err() {
                submit_failure(
                    &state,
                    ts_unix,
                    requested_model,
                    KdFailureReason::RuntimeUnavailable,
                );
                return;
            }
            let Ok(permit) = Arc::clone(&state.permits).try_acquire_owned() else {
                submit_failure(
                    &state,
                    ts_unix,
                    requested_model,
                    KdFailureReason::Backpressure,
                );
                return;
            };
            let bounded_text: String = text.chars().take(MAX_EMBED_INPUT_CHARS).collect();
            let requested_model = requested_model.clone();
            let tx = state.tx.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let result = provider
                    .embed(EmbedRequest::new(bounded_text).with_model(requested_model.clone()))
                    .await;
                match result {
                    Ok(response)
                        if !response.vector.is_empty()
                            && response.vector.len() <= MAX_EMBED_DIM
                            && response.vector.iter().all(|v| v.is_finite()) =>
                    {
                        let _ = tx.try_send(KSample {
                            ts_unix,
                            value: KSampleValue::Embedding {
                                vector: response.vector,
                                model_identity: bounded_model_identity(&response.model),
                            },
                        });
                    }
                    Ok(_) => {
                        let _ = tx.try_send(KSample {
                            ts_unix,
                            value: KSampleValue::EmbeddingFailure {
                                model_identity: bounded_model_identity(&requested_model),
                                reason: KdFailureReason::InvalidVector,
                            },
                        });
                        tracing::warn!(
                            model = %bounded_model_identity(&requested_model),
                            "babel K_d embedding returned an invalid vector; deterministic K=0 degradation"
                        );
                    }
                    Err(error) => {
                        let _ = tx.try_send(KSample {
                            ts_unix,
                            value: KSampleValue::EmbeddingFailure {
                                model_identity: bounded_model_identity(&requested_model),
                                reason: KdFailureReason::ProviderError,
                            },
                        });
                        tracing::warn!(
                            provider = provider.name(),
                            model = %bounded_model_identity(&requested_model),
                            error = %error,
                            "babel K_d local embedding failed; deterministic K=0 degradation"
                        );
                    }
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_counts_repeated_tokens_byte_for_byte() {
        let h = histogram_of("the cat and the dog");
        assert_eq!(h.values().sum::<u32>(), 5);
        assert_eq!(h.len(), 4);
        assert!(h.values().any(|&c| c == 2));
        assert!(histogram_of("").is_empty());
    }

    #[test]
    fn model_identity_is_content_bounded_and_wire_safe() {
        let raw = format!("org/model with spaces/{}", "x".repeat(200));
        let id = bounded_model_identity(&raw);
        assert!(id.len() <= 128);
        assert!(!id.contains(' '));
    }
}
