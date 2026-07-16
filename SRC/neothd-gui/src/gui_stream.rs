//! Daemon→GUI activity bus — the Buddy's live nervous system.
//!
//! Spawns `neothd wal follow --types …` as a long-lived child process and
//! tails its JSONL stdout: one line per NEW WAL frame. Each recognized
//! event maps to a [`GuiActivity`] which drives the Buddy orb's mood +
//! caption. An idle-revert thread drops the orb back to `idle` after a
//! quiet period so a burst of activity reads as a pulse, not a latch.
//!
//! Fail-silent by design: no daemon binary / no WAL dir / a dead child
//! never disturbs the GUI — the follower retries with backoff forever.

use std::io::BufRead as _;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

use crate::buddy_activity::GuiActivity;

/// Event types the follower subscribes to. Must stay a subset of the
/// mapping in [`wal_event_to_activity`] — the daemon-side filter merely
/// trims the stream; the mapping is the source of truth.
const FOLLOW_TYPES: &str = "0x00,0x1C,0x1D,0x1E,0x32,0x40,0x41,0x42,0x43,0x44,0x45,0x46,\
     0x60,0x61,0x62,0x63,0x64,0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7A,0x7B,\
     0x7C,0x7D,0x7E,0x7F,0xBE,0xBF,0xF4";

/// Seconds without a WAL event before the orb reverts to idle.
const IDLE_AFTER_SECS: u64 = 8;

/// Map one followed WAL event to a Buddy activity. `None` = ignore.
/// EXTENDED (0x00) frames carry their identity in the subtype byte —
/// only the FEAT-05 self-edit lifecycle is interesting here.
pub fn wal_event_to_activity(event_type: u8, subtype: u8) -> Option<GuiActivity> {
    Some(match event_type {
        0x00 => match subtype {
            0x01 | 0x02 | 0x05 => GuiActivity::SelfReprogramming,
            _ => return None,
        },
        0x1C..=0x1E | 0xBE | 0xBF => GuiActivity::SelfImproving,
        0x32 => GuiActivity::ChannelIngress,
        0x40..=0x46 => GuiActivity::CronRunning,
        0x60..=0x64 => GuiActivity::CouncilDeliberating,
        0x70..=0x7B => GuiActivity::AgentParallel,
        0x7C..=0x7F => GuiActivity::LoopRunning,
        0xF4 => GuiActivity::Dreaming,
        _ => return None,
    })
}

/// Parse one JSONL line from `wal follow` into an activity.
pub fn wal_line_to_activity(line: &str) -> Option<GuiActivity> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let et = v.get("event_type")?.as_u64()? as u8;
    let sub = v.get("subtype").and_then(|s| s.as_u64()).unwrap_or(0) as u8;
    wal_event_to_activity(et, sub)
}

/// Millisecond wall-clock — cheap shared "last event" stamp.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Start the follower + idle-revert threads. Call once after window
/// setup; both threads hold only a weak handle and die with the app.
pub fn spawn_wal_follower(window: slint::Weak<crate::MainWindow>) {
    let last_event_ms: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));

    // Idle revert — only touches the orb if THIS bus set it last
    // (tracked via last_event_ms; 0 = bus never fired, leave the orb
    // to the GUI's own click-sourced activities).
    {
        let last = last_event_ms.clone();
        let weak = window.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(1));
                let stamp = last.load(Ordering::Relaxed);
                if stamp == 0 {
                    continue;
                }
                if now_ms().saturating_sub(stamp) >= IDLE_AFTER_SECS * 1000 {
                    last.store(0, Ordering::Relaxed);
                    let w = weak.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(win) = w.upgrade() {
                            let (mood, cap) = GuiActivity::Idle.mood();
                            win.set_buddy_mood(mood.into());
                            win.set_buddy_caption(cap.into());
                        }
                    });
                }
            }
        });
    }

    // Reader — respawn the child with backoff; fail-silent throughout.
    std::thread::spawn(move || {
        loop {
            let child = crate::which_neothd().and_then(|bin| {
                let mut c = crate::spawn_neothd_plain(&bin);
                c.args(["wal", "follow", "--types", FOLLOW_TYPES])
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::null());
                c.spawn().ok()
            });
            let Some(mut child) = child else {
                // No daemon binary — the GUI works fine without the bus.
                std::thread::sleep(Duration::from_secs(30));
                continue;
            };
            if let Some(stdout) = child.stdout.take() {
                for line in std::io::BufReader::new(stdout).lines() {
                    let Ok(line) = line else { break };
                    let Some(act) = wal_line_to_activity(&line) else {
                        continue;
                    };
                    last_event_ms.store(now_ms(), Ordering::Relaxed);
                    let weak = window.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(win) = weak.upgrade() {
                            let (mood, cap) = act.mood();
                            win.set_buddy_mood(mood.into());
                            win.set_buddy_caption(cap.into());
                        }
                    });
                }
            }
            let _ = child.wait();
            std::thread::sleep(Duration::from_secs(5));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_covers_the_advertised_bands() {
        assert_eq!(wal_event_to_activity(0xF4, 0), Some(GuiActivity::Dreaming));
        assert_eq!(
            wal_event_to_activity(0x62, 0),
            Some(GuiActivity::CouncilDeliberating)
        );
        assert_eq!(
            wal_event_to_activity(0xBE, 0),
            Some(GuiActivity::SelfImproving)
        );
        assert_eq!(
            wal_event_to_activity(0x1D, 0),
            Some(GuiActivity::SelfImproving)
        );
        assert_eq!(
            wal_event_to_activity(0x32, 0),
            Some(GuiActivity::ChannelIngress)
        );
        assert_eq!(
            wal_event_to_activity(0x41, 0),
            Some(GuiActivity::CronRunning)
        );
        assert_eq!(
            wal_event_to_activity(0x77, 0),
            Some(GuiActivity::AgentParallel)
        );
        assert_eq!(
            wal_event_to_activity(0x7C, 0),
            Some(GuiActivity::LoopRunning)
        );
    }

    #[test]
    fn extended_frames_only_map_self_edit_subtypes() {
        assert_eq!(
            wal_event_to_activity(0x00, 0x01),
            Some(GuiActivity::SelfReprogramming)
        );
        assert_eq!(
            wal_event_to_activity(0x00, 0x05),
            Some(GuiActivity::SelfReprogramming)
        );
        assert_eq!(wal_event_to_activity(0x00, 0x03), None);
        assert_eq!(wal_event_to_activity(0x00, 0x00), None);
    }

    #[test]
    fn unmapped_types_are_ignored() {
        assert_eq!(wal_event_to_activity(0x50, 0), None);
        assert_eq!(wal_event_to_activity(0xFF, 0), None);
    }

    #[test]
    fn jsonl_parse_tolerates_garbage() {
        assert_eq!(
            wal_line_to_activity(r#"{"event_type":244,"subtype":0,"name":"dream_composed"}"#),
            Some(GuiActivity::Dreaming)
        );
        assert_eq!(wal_line_to_activity("not json"), None);
        assert_eq!(wal_line_to_activity(r#"{"subtype":1}"#), None);
        assert_eq!(wal_line_to_activity(""), None);
    }
}
