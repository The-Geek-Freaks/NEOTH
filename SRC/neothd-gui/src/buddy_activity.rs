//! GuiActivity — the central event→mood bus for the reactive Buddy orb.
//!
//! Every GUI action that should make the orb react routes through ONE place:
//! `GuiActivity` (what happened) → `.mood()` (how the Buddy shows it). This
//! replaces scattered `set_buddy_mood("…")` literals with a single, audited
//! vocabulary — adding a reactive activity is one match arm, and the moods are
//! guaranteed to be ones `buddy.slint` actually renders.
//!
//! Design discipline (per the design-system review): the orb is the ONE place
//! the neon signal palette goes loud. Memory=green, audit=cyan, consent=pink,
//! in-progress=amber stay meaning-bearing — the same semantics the surfaces use
//! quietly, the Buddy uses brightly.

use crate::chat_stream_phase::ChatStreamPhase;

// Variants are fired from two sources: GUI clicks (chat, channel-test, kanban,
// autonomy, memory-forget, settings writes) and the WAL follower in
// `gui_stream.rs` (dreaming, council, self-improve, cron, loops, agents,
// channel ingress — and since I7 also consent gates 0x65/0xDB/0xDC, audit RPC
// 0xAE/0xAF, provider fallback 0x25, memory scorecard 0x9F, security ops
// 0xD9/0xF2, quota breach 0xF0). Only ModelLoading + AgentDeploy remain
// click-source forward-infra.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuiActivity {
    /// Calm default — gently breathing, ready.
    Idle,

    // ── Chat ─────────────────────────────────────────────────────────
    ChatWaiting,
    ChatReceiving,
    ChatFinalizing,
    ChatComplete,
    ChatCancelled,
    ChatFailed,

    // ── Memory ───────────────────────────────────────────────────────
    MemoryRecall,
    MemoryForget,

    // ── Trust / consent / audit ──────────────────────────────────────
    ConsentGate,
    AuditVerify,
    Secured,

    // ── Channels ─────────────────────────────────────────────────────
    ChannelIngress,
    ChannelTest,

    // ── Providers / models ───────────────────────────────────────────
    ModelLoading,
    ProviderFallback,

    // ── Agents / coding ──────────────────────────────────────────────
    AgentParallel,
    AgentDeploy,
    /// Explicit repository-root code-map recall in the Coding panel.
    CodeMapRecall,

    // ── Daemon lifecycle (WAL-driven, fired by the events follower) ──
    /// Dreaming pass composing a journal entry (WAL 0xF4).
    Dreaming,
    /// Council deliberation in flight (WAL 0x60–0x64).
    CouncilDeliberating,
    /// Self-improvement / reflection pass (WAL 0xBE/0xBF, 0x1C–0x1E).
    SelfImproving,
    /// FEAT-05 self-reprogramming proposal/apply in flight.
    SelfReprogramming,
    /// A cron job is executing (WAL 0x40–0x46).
    CronRunning,
    /// Loop engine iteration in flight (WAL 0x7C–0x7F).
    LoopRunning,

    // ── Generic settings write ───────────────────────────────────────
    SettingsApplied,
    SettingsError,

    // ── Resource guard (WAL 0xF0) ────────────────────────────────────
    /// WAL disk quota ceiling hit — writes are being refused (I7).
    QuotaBreached,
}

impl GuiActivity {
    /// Map to the Buddy `(mood, caption)`. The mood strings MUST be ones the
    /// Slint `Buddy` component understands (see `buddy.slint` `hue()` + the
    /// per-mood overlays). `every_activity_maps_to_a_rendered_mood` pins this.
    pub fn mood(self) -> (&'static str, &'static str) {
        match self {
            GuiActivity::Idle => ("idle", "ready"),

            GuiActivity::ChatWaiting => ("thinking", "waiting…"),
            GuiActivity::ChatReceiving => ("working", "receiving…"),
            GuiActivity::ChatFinalizing => ("loading", "finalizing…"),
            GuiActivity::ChatComplete => ("success", "done ✓"),
            GuiActivity::ChatCancelled => ("idle", "cancelled"),
            GuiActivity::ChatFailed => ("error", "error"),

            GuiActivity::MemoryRecall => ("memory", "remembering"),
            GuiActivity::MemoryForget => ("consent", "scrubbing"),

            GuiActivity::ConsentGate => ("alert", "needs consent"),
            GuiActivity::AuditVerify => ("audit", "verifying"),
            GuiActivity::Secured => ("secure", "secured"),

            GuiActivity::ChannelIngress => ("notification", "new activity"),
            GuiActivity::ChannelTest => ("connecting", "connecting…"),

            GuiActivity::ModelLoading => ("loading", "loading"),
            GuiActivity::ProviderFallback => ("intense", "fallback"),

            GuiActivity::AgentParallel => ("parallel", "parallel workers"),
            GuiActivity::AgentDeploy => ("agents", "agents deployed"),
            GuiActivity::CodeMapRecall => ("searching", "searching repository…"),

            GuiActivity::Dreaming => ("sleeping", "dreaming…"),
            GuiActivity::CouncilDeliberating => ("parallel", "council in session"),
            GuiActivity::SelfImproving => ("learning", "self-improving"),
            GuiActivity::SelfReprogramming => ("cracking", "rewriting myself"),
            GuiActivity::CronRunning => ("working", "running a job"),
            GuiActivity::LoopRunning => ("working", "loop running"),

            GuiActivity::SettingsApplied => ("success", "saved"),
            GuiActivity::SettingsError => ("alert", "action failed"),

            GuiActivity::QuotaBreached => ("problem", "disk quota hit"),
        }
    }
}

impl From<ChatStreamPhase> for GuiActivity {
    fn from(phase: ChatStreamPhase) -> Self {
        match phase {
            ChatStreamPhase::Waiting => Self::ChatWaiting,
            ChatStreamPhase::Receiving => Self::ChatReceiving,
            ChatStreamPhase::Finalizing => Self::ChatFinalizing,
            ChatStreamPhase::Complete => Self::ChatComplete,
            ChatStreamPhase::Cancelled => Self::ChatCancelled,
            ChatStreamPhase::Failed => Self::ChatFailed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact mood vocabulary `buddy.slint` renders distinctly (its `hue()`
    /// colour buckets + the per-mood overlay `if root.is-mood(...)` blocks).
    /// If a `GuiActivity` mapped to a mood NOT in here, the orb would silently
    /// fall back to the green default — a wiring bug. This catches it.
    const RENDERED_MOODS: &[&str] = &[
        "idle",
        "thinking",
        "searching",
        "analyzing",
        "working",
        "memory",
        "learning",
        "audit",
        "success",
        "happy",
        "excited",
        "consent",
        "alert",
        "problem",
        "secure",
        "connected",
        "connecting",
        "loading",
        "intense",
        "cracking",
        "notification",
        "parallel",
        "agents",
        "sleeping",
        "error",
        "danger",
    ];

    const ALL: &[GuiActivity] = &[
        GuiActivity::Idle,
        GuiActivity::ChatWaiting,
        GuiActivity::ChatReceiving,
        GuiActivity::ChatFinalizing,
        GuiActivity::ChatComplete,
        GuiActivity::ChatCancelled,
        GuiActivity::ChatFailed,
        GuiActivity::MemoryRecall,
        GuiActivity::MemoryForget,
        GuiActivity::ConsentGate,
        GuiActivity::AuditVerify,
        GuiActivity::Secured,
        GuiActivity::ChannelIngress,
        GuiActivity::ChannelTest,
        GuiActivity::ModelLoading,
        GuiActivity::ProviderFallback,
        GuiActivity::AgentParallel,
        GuiActivity::AgentDeploy,
        GuiActivity::CodeMapRecall,
        GuiActivity::Dreaming,
        GuiActivity::CouncilDeliberating,
        GuiActivity::SelfImproving,
        GuiActivity::SelfReprogramming,
        GuiActivity::CronRunning,
        GuiActivity::LoopRunning,
        GuiActivity::SettingsApplied,
        GuiActivity::SettingsError,
        GuiActivity::QuotaBreached,
    ];

    #[test]
    fn every_activity_maps_to_a_rendered_mood() {
        for &a in ALL {
            let (mood, caption) = a.mood();
            assert!(
                RENDERED_MOODS.contains(&mood),
                "{a:?} → mood {mood:?} is not rendered by buddy.slint"
            );
            assert!(!caption.is_empty(), "{a:?} → empty caption");
        }
    }

    #[test]
    fn chat_lifecycle_maps_all_six_phases() {
        assert_eq!(GuiActivity::ChatWaiting.mood(), ("thinking", "waiting…"));
        assert_eq!(GuiActivity::ChatReceiving.mood(), ("working", "receiving…"));
        assert_eq!(
            GuiActivity::ChatFinalizing.mood(),
            ("loading", "finalizing…")
        );
        assert_eq!(GuiActivity::ChatComplete.mood(), ("success", "done ✓"));
        assert_eq!(GuiActivity::ChatCancelled.mood(), ("idle", "cancelled"));
        assert_eq!(GuiActivity::ChatFailed.mood(), ("error", "error"));
    }

    #[test]
    fn code_map_recall_uses_searching_mood() {
        assert_eq!(
            GuiActivity::CodeMapRecall.mood(),
            ("searching", "searching repository…")
        );
    }

    #[test]
    fn canonical_chat_phases_map_exhaustively_to_buddy_activities() {
        let expected = [
            GuiActivity::ChatWaiting,
            GuiActivity::ChatReceiving,
            GuiActivity::ChatFinalizing,
            GuiActivity::ChatComplete,
            GuiActivity::ChatCancelled,
            GuiActivity::ChatFailed,
        ];

        assert_eq!(
            ChatStreamPhase::ALL.map(GuiActivity::from),
            expected,
            "every canonical stream phase must retain its Buddy activity"
        );
    }

    #[test]
    fn chat_lifecycle_moods_and_captions_are_distinct() {
        let phases = [
            GuiActivity::ChatWaiting,
            GuiActivity::ChatReceiving,
            GuiActivity::ChatFinalizing,
            GuiActivity::ChatComplete,
            GuiActivity::ChatCancelled,
            GuiActivity::ChatFailed,
        ];

        for (index, activity) in phases.iter().enumerate() {
            let (mood, caption) = activity.mood();
            for other in &phases[index + 1..] {
                let (other_mood, other_caption) = other.mood();
                assert_ne!(mood, other_mood, "{activity:?} and {other:?}");
                assert_ne!(caption, other_caption, "{activity:?} and {other:?}");
            }
        }
    }
}
