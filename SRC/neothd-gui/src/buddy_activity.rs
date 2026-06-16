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

// Some variants are wired to live GUI events today (chat, channel-test, kanban,
// autonomy, memory-forget, settings writes); the rest are forward-infra for
// daemon-pushed activity that has no GUI click-source yet (background memory
// recall, audit verification, consent gates, channel ingress, provider
// fallback). Mirrors the core's `domain_events` forward-infra pattern — the
// vocabulary is complete + tested now; the daemon→GUI push that fires the
// remaining ones lands when the gui-stream activity channel does.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuiActivity {
    /// Calm default — gently breathing, ready.
    Idle,

    // ── Chat ─────────────────────────────────────────────────────────
    ChatThinking,
    ChatStreaming,
    ChatDone,
    ChatError,

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

    // ── Generic settings write ───────────────────────────────────────
    SettingsApplied,
    SettingsError,
}

impl GuiActivity {
    /// Map to the Buddy `(mood, caption)`. The mood strings MUST be ones the
    /// Slint `Buddy` component understands (see `buddy.slint` `hue()` + the
    /// per-mood overlays). `every_activity_maps_to_a_rendered_mood` pins this.
    pub fn mood(self) -> (&'static str, &'static str) {
        match self {
            GuiActivity::Idle => ("idle", "ready"),

            GuiActivity::ChatThinking => ("thinking", "thinking…"),
            GuiActivity::ChatStreaming => ("working", "on it"),
            GuiActivity::ChatDone => ("success", "done ✓"),
            GuiActivity::ChatError => ("error", "error"),

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

            GuiActivity::SettingsApplied => ("success", "saved"),
            GuiActivity::SettingsError => ("alert", "action failed"),
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
        "idle", "thinking", "searching", "analyzing", "working", "memory",
        "learning", "audit", "success", "happy", "excited", "consent", "alert",
        "problem", "secure", "connected", "connecting", "loading", "intense",
        "cracking", "notification", "parallel", "agents", "sleeping", "error",
        "danger",
    ];

    const ALL: &[GuiActivity] = &[
        GuiActivity::Idle,
        GuiActivity::ChatThinking,
        GuiActivity::ChatStreaming,
        GuiActivity::ChatDone,
        GuiActivity::ChatError,
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
        GuiActivity::SettingsApplied,
        GuiActivity::SettingsError,
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
    fn chat_lifecycle_moods_are_distinct() {
        assert_ne!(GuiActivity::ChatThinking.mood().0, GuiActivity::ChatStreaming.mood().0);
        assert_ne!(GuiActivity::ChatDone.mood().0, GuiActivity::ChatError.mood().0);
    }
}
