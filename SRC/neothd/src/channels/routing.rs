//! GOLD-FEAT-13 — per-purpose channel ROUTING for proactive / unsolicited
//! sends. Operator picks WHICH channel each proactive `source` goes to,
//! with a default, a dedicated failure channel, and a fallback to the
//! existing sidecar ledger.
//!
//! ## Why a side-file, not `freedom.yaml`
//!
//! The routing config persists to `~/.neoth/channel_routing.json` (atomic
//! tmp+rename, mirroring `proactive_queue.json`) rather than a field on
//! `FreedomConfig`. This keeps the feature ENTIRELY out of `config/mod.rs`
//! (the GOLD-ARCH-04 decomposition zone, actively touched by a parallel
//! workstream) — zero collision surface. It migrates into `freedom.yaml`
//! when ARCH-04 lands; the on-disk shape is forward-compatible.
//!
//! ## Routing model (research-grounded)
//!
//! Synthesised from a 2026-06-13 deep-read of three agent systems
//! (`REVIEWS/_gold_audit/research/channels_routing_synthesis_2026-06-13.md`):
//! - **Hermes** `HomeChannel` (per-channel destination) → [`ChannelDestinations`].
//! - **OpenClaw** `failureDestination` (route failure alerts to a dedicated
//!   channel) → [`ChannelRouting::failure_channel`].
//! - **OpenHuman** fallback chain (routed → default → sidecar) →
//!   [`ChannelRouting::resolve_channel`] returning `None` so the caller keeps
//!   the existing sidecar behaviour.
//! - The per-`source` map is RICHER than any of the three (none does
//!   per-purpose routing at config) — it is the "welche channel für was"
//!   the operator asked for.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Per-channel outbound destination — the "home channel", i.e. WHERE on a
/// given channel a proactive message lands. All optional + `serde(default)`
/// so a partially-filled routing file is valid. Telegram additionally falls
/// back to `config.telegram_user_id` at the resolution site when unset here.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelDestinations {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telegram_chat_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slack_channel_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discord_channel_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub whatsapp_recipient: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keet_topic: Option<String>,
}

impl ChannelDestinations {
    /// The configured destination for the canonical channel name, if any.
    /// Accepts the WhatsApp sub-kinds (`whatsapp_business`/`whatsapp_baileys`)
    /// as aliases of `whatsapp`.
    pub fn for_channel(&self, channel: &str) -> Option<&str> {
        match channel {
            "telegram" => self.telegram_chat_id.as_deref(),
            "slack" => self.slack_channel_id.as_deref(),
            "discord" => self.discord_channel_id.as_deref(),
            "whatsapp" | "whatsapp_business" | "whatsapp_baileys" => {
                self.whatsapp_recipient.as_deref()
            }
            "keet" => self.keet_topic.as_deref(),
            _ => None,
        }
    }

    /// Set the destination for the canonical channel name. Returns `false`
    /// for an unrecognised channel (caller can warn). Used by `neoth
    /// proactive route --channel X --dest Y`.
    pub fn set_for_channel(&mut self, channel: &str, id: String) -> bool {
        match channel {
            "telegram" => self.telegram_chat_id = Some(id),
            "slack" => self.slack_channel_id = Some(id),
            "discord" => self.discord_channel_id = Some(id),
            "whatsapp" | "whatsapp_business" | "whatsapp_baileys" => {
                self.whatsapp_recipient = Some(id)
            }
            "keet" => self.keet_topic = Some(id),
            _ => return false,
        }
        true
    }
}

/// GOLD-FEAT-13 routing config. Persisted to `~/.neoth/channel_routing.json`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelRouting {
    /// Default proactive channel (canonical name) when no per-source match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_channel: Option<String>,
    /// Per-`source` overrides, e.g. `{"coding_session":"discord"}`. The
    /// `ProactiveItem.source` tag is the routing key.
    #[serde(default)]
    pub by_source: HashMap<String, String>,
    /// Channel for failure/error alerts (e.g. a `coding_session` that ended
    /// with blocked tasks). Falls back to `default_channel`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_channel: Option<String>,
    /// Per-channel outbound destinations.
    #[serde(default)]
    pub destinations: ChannelDestinations,
}

/// The filename inside `~/.neoth/` that persists the routing config.
pub const CHANNEL_ROUTING_FILE: &str = "channel_routing.json";

impl ChannelRouting {
    /// Resolve the channel a proactive item should target. Priority:
    /// (1) per-`source` override, (2) `failure_channel` when `is_failure`,
    /// (3) `default_channel`. `None` ⇒ no routing rule applies → the caller
    /// keeps the item's own channel / sidecar-only behaviour (the fallback
    /// chain's terminal). Returns the canonical channel NAME, not a
    /// destination — destination resolution is a separate step so the
    /// autonomy gate + recipient-own-id invariant stay at the send site.
    pub fn resolve_channel(&self, source: &str, is_failure: bool) -> Option<String> {
        if let Some(ch) = self.by_source.get(source) {
            return Some(ch.clone());
        }
        if is_failure {
            if let Some(ch) = &self.failure_channel {
                return Some(ch.clone());
            }
        }
        self.default_channel.clone()
    }

    /// Load from `path`. A missing or empty file is a fresh default config
    /// (routing is opt-in); a real IO/parse error propagates.
    pub fn load_from(path: &Path) -> Result<Self> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
        };
        if bytes.is_empty() {
            return Ok(Self::default());
        }
        serde_json::from_slice(&bytes).context("parse channel_routing.json")
    }

    /// Atomic tmp+rename save (mirrors `ProactiveQueue::save_to`).
    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create parent dir for {}", path.display()))?;
        }
        let bytes = serde_json::to_vec_pretty(self).context("serialise channel routing")?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &bytes).with_context(|| format!("write tmp {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("rename into {}", path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routing() -> ChannelRouting {
        let mut by_source = HashMap::new();
        by_source.insert("coding_session".to_string(), "discord".to_string());
        ChannelRouting {
            default_channel: Some("telegram".to_string()),
            by_source,
            failure_channel: Some("slack".to_string()),
            destinations: ChannelDestinations {
                discord_channel_id: Some("987654321".to_string()),
                slack_channel_id: Some("C0B0QV5434G".to_string()),
                ..Default::default()
            },
        }
    }

    #[test]
    fn resolve_prefers_per_source_over_default() {
        let r = routing();
        assert_eq!(
            r.resolve_channel("coding_session", false).as_deref(),
            Some("discord"),
            "per-source override wins"
        );
    }

    #[test]
    fn resolve_falls_back_to_default_for_unmapped_source() {
        let r = routing();
        assert_eq!(
            r.resolve_channel("g_01_mini", false).as_deref(),
            Some("telegram"),
            "unmapped source → default"
        );
    }

    #[test]
    fn resolve_uses_failure_channel_when_failure_and_no_source_override() {
        let r = routing();
        // a source with no by_source entry, flagged failure → failure_channel
        assert_eq!(
            r.resolve_channel("reflection", true).as_deref(),
            Some("slack"),
            "failure routes to failure_channel"
        );
    }

    #[test]
    fn resolve_per_source_beats_failure_channel() {
        let r = routing();
        // coding_session HAS a by_source entry → it wins even on failure
        assert_eq!(
            r.resolve_channel("coding_session", true).as_deref(),
            Some("discord"),
            "explicit per-source mapping beats the failure channel"
        );
    }

    #[test]
    fn resolve_returns_none_when_unconfigured() {
        let r = ChannelRouting::default();
        assert_eq!(
            r.resolve_channel("coding_session", false),
            None,
            "no routing configured → None → caller keeps sidecar behaviour"
        );
        assert_eq!(r.resolve_channel("anything", true), None);
    }

    #[test]
    fn destinations_resolve_by_canonical_name_with_whatsapp_aliases() {
        let r = routing();
        assert_eq!(r.destinations.for_channel("discord"), Some("987654321"));
        assert_eq!(r.destinations.for_channel("slack"), Some("C0B0QV5434G"));
        assert_eq!(r.destinations.for_channel("telegram"), None, "unset → None");
        // whatsapp sub-kinds alias to the same recipient slot
        let mut r2 = ChannelRouting::default();
        r2.destinations.whatsapp_recipient = Some("+15551234567".to_string());
        assert_eq!(r2.destinations.for_channel("whatsapp_business"), Some("+15551234567"));
        assert_eq!(r2.destinations.for_channel("whatsapp_baileys"), Some("+15551234567"));
    }

    #[test]
    fn load_missing_file_is_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("channel_routing.json");
        let r = ChannelRouting::load_from(&path).expect("missing file → default");
        assert_eq!(r, ChannelRouting::default());
    }

    #[test]
    fn save_then_load_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CHANNEL_ROUTING_FILE);
        let original = routing();
        original.save_to(&path).expect("save");
        let loaded = ChannelRouting::load_from(&path).expect("load");
        assert_eq!(loaded, original, "routing config survives a save/load roundtrip");
    }

    #[test]
    fn set_for_channel_sets_known_and_rejects_unknown() {
        let mut d = ChannelDestinations::default();
        assert!(d.set_for_channel("discord", "123".into()));
        assert_eq!(d.discord_channel_id.as_deref(), Some("123"));
        assert!(d.set_for_channel("whatsapp_business", "+15551234567".into()));
        assert_eq!(d.whatsapp_recipient.as_deref(), Some("+15551234567"));
        assert!(
            !d.set_for_channel("nonsense", "x".into()),
            "unknown channel name → false (caller warns)"
        );
    }
}
