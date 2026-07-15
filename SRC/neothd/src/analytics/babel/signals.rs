//! Content-free, bounded Babel signal feed.
//!
//! Signal producers apply the operator gates here, before a sample enters the
//! queue.  The payload is a closed enum: no prompt, memory, skill id, path, or
//! other operator content can cross this boundary.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

pub const SIGNAL_MAPPING_VERSION: &str = "BabelSignalMap_v1";

// Pre-hoc mapping frozen 2026-07-14:
// - a newly inserted contradiction -> memory_contradictions
// - a successful explicit/historical recall with zero rows -> memory_recall_misses
// - one final router decision -> exactly one skill_* counter
// No mapping changes a score feature or collapse label. A future mapping must
// use a new version string and window schema before collecting data.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalKind {
    MemoryContradiction,
    MemoryRecallMiss,
    SkillMode,
    SkillKeyword,
    SkillEmbedding,
    SkillNoMatch,
    SkillSuppressed,
}

impl SignalKind {
    fn is_memory(self) -> bool {
        matches!(self, Self::MemoryContradiction | Self::MemoryRecallMiss)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SignalSample {
    pub ts_unix: i64,
    pub kind: SignalKind,
}

/// Per-window counts.  The mapping is deliberately posture-only: these
/// observations do not change C/K/M/A/V/D/H or fabricate collapse labels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SignalPosture {
    pub mapping_version: String,
    pub memory_enabled: bool,
    pub skill_enabled: bool,
    pub memory_contradictions: u32,
    pub memory_recall_misses: u32,
    pub skill_mode: u32,
    pub skill_keyword: u32,
    pub skill_embedding: u32,
    pub skill_no_match: u32,
    pub skill_suppressed: u32,
}

impl Default for SignalPosture {
    fn default() -> Self {
        Self::new(false, false)
    }
}

impl SignalPosture {
    pub fn new(memory_enabled: bool, skill_enabled: bool) -> Self {
        Self {
            mapping_version: SIGNAL_MAPPING_VERSION.to_string(),
            memory_enabled,
            skill_enabled,
            memory_contradictions: 0,
            memory_recall_misses: 0,
            skill_mode: 0,
            skill_keyword: 0,
            skill_embedding: 0,
            skill_no_match: 0,
            skill_suppressed: 0,
        }
    }

    pub fn record(&mut self, kind: SignalKind) {
        let slot = match kind {
            SignalKind::MemoryContradiction => &mut self.memory_contradictions,
            SignalKind::MemoryRecallMiss => &mut self.memory_recall_misses,
            SignalKind::SkillMode => &mut self.skill_mode,
            SignalKind::SkillKeyword => &mut self.skill_keyword,
            SignalKind::SkillEmbedding => &mut self.skill_embedding,
            SignalKind::SkillNoMatch => &mut self.skill_no_match,
            SignalKind::SkillSuppressed => &mut self.skill_suppressed,
        };
        *slot = slot.saturating_add(1);
    }
}

#[derive(Default)]
struct FeedState {
    generation: u64,
    memory_enabled: bool,
    skill_enabled: bool,
    tx: Option<mpsc::Sender<SignalSample>>,
}

static FEED: OnceLock<RwLock<FeedState>> = OnceLock::new();
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

fn feed() -> &'static RwLock<FeedState> {
    FEED.get_or_init(|| RwLock::new(FeedState::default()))
}

pub struct SignalReceiver {
    generation: u64,
    rx: mpsc::Receiver<SignalSample>,
}

impl SignalReceiver {
    pub fn try_recv(&mut self) -> Result<SignalSample, mpsc::error::TryRecvError> {
        self.rx.try_recv()
    }
}

impl Drop for SignalReceiver {
    fn drop(&mut self) {
        let Ok(mut state) = feed().write() else {
            return;
        };
        if state.generation == self.generation {
            state.memory_enabled = false;
            state.skill_enabled = false;
            state.tx = None;
        }
    }
}

/// Install (or replace after a cron reload) the consumer and source gates.
pub fn register(memory_enabled: bool, skill_enabled: bool, capacity: usize) -> SignalReceiver {
    let (tx, rx) = mpsc::channel(capacity.max(1));
    let generation = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut state) = feed().write() {
        *state = FeedState {
            generation,
            memory_enabled,
            skill_enabled,
            tx: Some(tx),
        };
    }
    SignalReceiver { generation, rx }
}

/// Source-side gate + non-blocking enqueue.
pub fn emit(kind: SignalKind) {
    let Ok(state) = feed().read() else { return };
    let enabled = if kind.is_memory() {
        state.memory_enabled
    } else {
        state.skill_enabled
    };
    if !enabled {
        return;
    }
    let Some(tx) = &state.tx else { return };
    let _ = tx.try_send(SignalSample {
        ts_unix: crate::time::now_unix_i64(),
        kind,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_is_explicit_saturating_and_never_reweights_features() {
        let mut p = SignalPosture::new(true, true);
        for kind in [
            SignalKind::MemoryContradiction,
            SignalKind::MemoryRecallMiss,
            SignalKind::SkillMode,
            SignalKind::SkillKeyword,
            SignalKind::SkillEmbedding,
            SignalKind::SkillNoMatch,
            SignalKind::SkillSuppressed,
        ] {
            p.record(kind);
        }
        assert_eq!(p.mapping_version, SIGNAL_MAPPING_VERSION);
        assert_eq!(p.memory_contradictions, 1);
        assert_eq!(p.memory_recall_misses, 1);
        assert_eq!(p.skill_mode + p.skill_keyword + p.skill_embedding, 3);
        assert_eq!(p.skill_no_match, 1);
        assert_eq!(p.skill_suppressed, 1);
    }
}
