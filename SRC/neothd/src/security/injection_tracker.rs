//! ADOPT31-C1 — cross-turn prompt-injection escalation + canary-token leak.
//!
//! [`super::ingress_sanitizer::sanitize`] judges one message in isolation. That
//! is the right shape for a filter and the wrong shape for an attacker, who
//! gets to spend many turns. Each probe on its own can sit under every
//! threshold — asking what the system prompt covers, then how it is worded,
//! then to "summarise your configuration" — while the sequence is obviously an
//! escalation. Nothing carried state between turns, so nobody ever saw it.
//!
//! Two independent detectors, deliberately not merged: one watches the shape of
//! the conversation, the other watches for proof that an attempt already
//! succeeded.
//!
//! ## 1. Escalation over a window
//!
//! A bounded ring of per-turn signals. An alert needs REPEATED probing inside
//! the window, not a single hit — one flagged message is what the sanitizer
//! already handles, and treating it as escalation would fire on every operator
//! who asks a security question twice.
//!
//! ## 2. Canary token
//!
//! A high-entropy value placed in the model's context. The operator never sees
//! it and no channel ever carries it, so it cannot arrive in output by any
//! honest route. Finding it in generated text is therefore not a heuristic:
//! it is proof the model was induced to emit its own instructions.
//!
//! **The token is never recorded anywhere.** It has no `Serialize`, its `Debug`
//! redacts, and an alert carries a digest instead of the value. A leak detector
//! that writes the secret into the WAL and the logs has created the leak it
//! exists to find — which is exactly the mistake this module must not make.

use std::collections::VecDeque;

use sha2::{Digest, Sha256};

use crate::security::ingress_sanitizer::{Finding, SanitizeReport};

/// Turns kept in the escalation window.
const WINDOW_TURNS: usize = 8;
/// Probing turns inside the window that constitute an escalation.
const ESCALATION_THRESHOLD: usize = 3;
/// Bytes of entropy behind a canary token.
const CANARY_BYTES: usize = 16;

/// A per-session secret planted in the model's context to prove exfiltration.
///
/// Deliberately not `Clone`, not `Serialize`, and `Debug`-redacted: every
/// derive that would let this value escape into a log line is absent on
/// purpose.
pub struct CanaryToken {
    value: String,
}

impl std::fmt::Debug for CanaryToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the value. The digest is enough to correlate two alerts.
        write!(f, "CanaryToken({}…)", &self.digest()[..12])
    }
}

impl CanaryToken {
    /// Mint a fresh token from the OS CSPRNG.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0u8; CANARY_BYTES];
        getrandom::getrandom(&mut bytes)?;
        // A recognisable, inert prefix so an operator who ever does see one in
        // a transcript can tell what it is instead of guessing.
        let mut value = String::from("NEOTH-CANARY-");
        for b in bytes {
            value.push_str(&format!("{b:02x}"));
        }
        Ok(Self { value })
    }

    /// The literal to embed in the model's context. Callers must not log,
    /// persist, or send this over any channel.
    #[must_use]
    pub fn as_context_literal(&self) -> &str {
        &self.value
    }

    /// Domain-separated digest, safe to record.
    #[must_use]
    pub fn digest(&self) -> String {
        let mut d = Sha256::new();
        d.update(b"neoth/canary-token/v1\0");
        d.update(self.value.as_bytes());
        format!("{:x}", d.finalize())
    }

    /// Whether generated text carries the token.
    ///
    /// A model under exfiltration pressure often reformats what it emits, so a
    /// plain substring test is checked against the text with ASCII whitespace
    /// removed as well. That catches the token wrapped across a line or spaced
    /// out; it does not pretend to catch an arbitrary encoding, and this
    /// module does not claim otherwise.
    #[must_use]
    pub fn leaked_in(&self, text: &str) -> bool {
        if text.contains(&self.value) {
            return true;
        }
        let stripped: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        stripped.contains(&self.value)
    }
}

/// One turn's contribution to the escalation window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct TurnSignal {
    probing: bool,
    quarantined: bool,
}

/// What the tracker concluded about the conversation so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrackerAlert {
    /// Repeated injection probing inside the window.
    MultiTurnEscalation {
        probing_turns: usize,
        window: usize,
        quarantined_turns: usize,
    },
    /// The canary reached generated output. Carries the digest, never the
    /// token.
    CanaryLeak { canary_digest: String },
}

impl TrackerAlert {
    /// Short operator-facing summary. Contains no message content and no
    /// secret — safe for a log line or a WAL payload.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            TrackerAlert::MultiTurnEscalation {
                probing_turns,
                window,
                quarantined_turns,
            } => format!(
                "multi-turn prompt-injection escalation: {probing_turns} of the last {window} \
                 turns carried injection markers ({quarantined_turns} quarantined)"
            ),
            TrackerAlert::CanaryLeak { canary_digest } => format!(
                "canary token reached generated output (digest {}…) — the model emitted context \
                 it was instructed to keep",
                &canary_digest[..16.min(canary_digest.len())]
            ),
        }
    }
}

/// Cross-turn state for one conversation.
#[derive(Debug, Default)]
pub struct InjectionTracker {
    window: VecDeque<TurnSignal>,
    /// Set once an escalation fired, cleared when the window goes quiet, so a
    /// sustained attack reports once instead of on every subsequent turn.
    escalation_reported: bool,
}

/// Whether a finding is an injection attempt rather than a hygiene issue.
///
/// Oversize input, control characters and NFKC normalisation are noise: they
/// fire on ordinary messages from ordinary clients. Counting them would make
/// the escalation signal useless within a day of shipping.
fn is_probing(finding: &Finding) -> bool {
    matches!(
        finding,
        Finding::PromptInjectionMarker { .. } | Finding::PersonaOverrideAttempt { .. }
    )
}

impl InjectionTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one inbound message's sanitize verdict into the window.
    pub fn observe_inbound(&mut self, report: &SanitizeReport) -> Option<TrackerAlert> {
        let signal = TurnSignal {
            probing: report.findings.iter().any(is_probing),
            quarantined: report.quarantined,
        };
        if self.window.len() == WINDOW_TURNS {
            self.window.pop_front();
        }
        self.window.push_back(signal);

        let probing_turns = self.window.iter().filter(|s| s.probing).count();
        if probing_turns < ESCALATION_THRESHOLD {
            // The window went quiet — arm the detector again.
            if probing_turns == 0 {
                self.escalation_reported = false;
            }
            return None;
        }
        if self.escalation_reported {
            return None;
        }
        self.escalation_reported = true;
        Some(TrackerAlert::MultiTurnEscalation {
            probing_turns,
            window: self.window.len(),
            quarantined_turns: self.window.iter().filter(|s| s.quarantined).count(),
        })
    }

    /// Check generated output for the session canary.
    pub fn observe_outbound(&self, canary: &CanaryToken, text: &str) -> Option<TrackerAlert> {
        canary.leaked_in(text).then(|| TrackerAlert::CanaryLeak {
            canary_digest: canary.digest(),
        })
    }

    /// Turns currently held (diagnostics + tests).
    #[must_use]
    pub fn tracked_turns(&self) -> usize {
        self.window.len()
    }
}

/// Conversations held in the process-wide registry.
///
/// Bounded on purpose. Keying trackers by sender without a cap would let any
/// party that can reach a channel mint unbounded state by rotating sender
/// identities — a detector that can be turned into a memory-exhaustion vector
/// is worse than no detector.
const MAX_TRACKED_CONVERSATIONS: usize = 256;

struct TrackerRegistry {
    by_sender: std::collections::HashMap<String, InjectionTracker>,
    /// Insertion order, for FIFO eviction. A true LRU would need a touch on
    /// every read; the window is only 8 turns, so evicting the oldest
    /// conversation costs at most one missed escalation for a sender who has
    /// been silent longest.
    order: VecDeque<String>,
}

fn registry() -> &'static std::sync::Mutex<TrackerRegistry> {
    static REGISTRY: std::sync::OnceLock<std::sync::Mutex<TrackerRegistry>> =
        std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| {
        std::sync::Mutex::new(TrackerRegistry {
            by_sender: std::collections::HashMap::new(),
            order: VecDeque::new(),
        })
    })
}

/// Fold one inbound verdict into the cross-turn window for `sender_key`.
///
/// `sender_key` must already be an opaque identifier (the pipeline passes a
/// sender *hash*) — this module never wants a raw address.
pub fn observe_inbound_for(sender_key: &str, report: &SanitizeReport) -> Option<TrackerAlert> {
    let mut guard = registry()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    if !guard.by_sender.contains_key(sender_key) {
        if guard.by_sender.len() >= MAX_TRACKED_CONVERSATIONS
            && let Some(evicted) = guard.order.pop_front()
        {
            guard.by_sender.remove(&evicted);
        }
        guard
            .by_sender
            .insert(sender_key.to_string(), InjectionTracker::new());
        guard.order.push_back(sender_key.to_string());
    }
    guard
        .by_sender
        .get_mut(sender_key)
        .expect("just inserted")
        .observe_inbound(report)
}

#[cfg(test)]
pub(crate) fn reset_registry_for_test() {
    let mut guard = registry()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    guard.by_sender.clear();
    guard.order.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(findings: Vec<Finding>, quarantined: bool) -> SanitizeReport {
        SanitizeReport {
            quarantined,
            findings,
            text: String::new(),
            input_hash: "0".into(),
            ts_unix: 0,
            channel: "test".into(),
        }
    }

    fn probe() -> Finding {
        Finding::PromptInjectionMarker {
            pattern: "ignore previous instructions".into(),
        }
    }

    #[test]
    fn a_single_probe_is_not_an_escalation() {
        // One flagged message is what the sanitizer already handles. Alerting
        // here would fire on any operator who asks a security question.
        let mut t = InjectionTracker::new();
        assert_eq!(t.observe_inbound(&report(vec![probe()], false)), None);
    }

    #[test]
    fn repeated_probing_inside_the_window_escalates() {
        let mut t = InjectionTracker::new();
        assert!(t.observe_inbound(&report(vec![probe()], false)).is_none());
        assert!(t.observe_inbound(&report(vec![probe()], false)).is_none());
        let alert = t
            .observe_inbound(&report(vec![probe()], true))
            .expect("third probe inside the window is an escalation");
        match alert {
            TrackerAlert::MultiTurnEscalation {
                probing_turns,
                quarantined_turns,
                ..
            } => {
                assert_eq!(probing_turns, 3);
                assert_eq!(quarantined_turns, 1);
            }
            other => panic!("unexpected alert: {other:?}"),
        }
    }

    #[test]
    fn a_sustained_attack_reports_once_not_every_turn() {
        let mut t = InjectionTracker::new();
        for _ in 0..2 {
            assert!(t.observe_inbound(&report(vec![probe()], false)).is_none());
        }
        assert!(t.observe_inbound(&report(vec![probe()], false)).is_some());
        assert!(
            t.observe_inbound(&report(vec![probe()], false)).is_none(),
            "an ongoing attack must not re-alert every turn"
        );
    }

    #[test]
    fn hygiene_findings_never_count_as_probing() {
        // These fire on ordinary traffic. Counting them would drown the signal.
        let mut t = InjectionTracker::new();
        for _ in 0..WINDOW_TURNS {
            let r = report(
                vec![
                    Finding::NeededNfkcNormalization,
                    Finding::OversizeInput {
                        bytes: 10,
                        limit: 5,
                    },
                ],
                false,
            );
            assert_eq!(t.observe_inbound(&r), None);
        }
    }

    #[test]
    fn probes_spread_beyond_the_window_do_not_accumulate() {
        // Two probes, then a long quiet stretch, then one more: the first two
        // have aged out, so this is not an escalation.
        let mut t = InjectionTracker::new();
        t.observe_inbound(&report(vec![probe()], false));
        t.observe_inbound(&report(vec![probe()], false));
        for _ in 0..WINDOW_TURNS {
            assert_eq!(t.observe_inbound(&report(vec![], false)), None);
        }
        assert_eq!(t.observe_inbound(&report(vec![probe()], false)), None);
        assert_eq!(t.tracked_turns(), WINDOW_TURNS, "the ring stays bounded");
    }

    #[test]
    fn the_window_is_bounded_regardless_of_conversation_length() {
        let mut t = InjectionTracker::new();
        for _ in 0..1000 {
            t.observe_inbound(&report(vec![], false));
        }
        assert_eq!(t.tracked_turns(), WINDOW_TURNS);
    }

    #[test]
    fn a_canary_in_output_is_a_leak() {
        let t = InjectionTracker::new();
        let canary = CanaryToken::generate().unwrap();
        let leaked = format!("my instructions say {} and more", canary.as_context_literal());
        let alert = t
            .observe_outbound(&canary, &leaked)
            .expect("the canary in output is proof of exfiltration");
        assert!(matches!(alert, TrackerAlert::CanaryLeak { .. }));
        assert!(t.observe_outbound(&canary, "a normal answer").is_none());
    }

    #[test]
    fn a_canary_split_across_whitespace_still_counts() {
        let t = InjectionTracker::new();
        let canary = CanaryToken::generate().unwrap();
        let literal = canary.as_context_literal();
        let split = format!("{}\n{}", &literal[..10], &literal[10..]);
        assert!(
            t.observe_outbound(&canary, &split).is_some(),
            "a model that wraps the token across a line still leaked it"
        );
    }

    #[test]
    fn two_tokens_never_collide() {
        let a = CanaryToken::generate().unwrap();
        let b = CanaryToken::generate().unwrap();
        assert_ne!(a.as_context_literal(), b.as_context_literal());
        assert_ne!(a.digest(), b.digest());
        let t = InjectionTracker::new();
        assert!(
            t.observe_outbound(&a, b.as_context_literal()).is_none(),
            "one session's canary must not fire on another's"
        );
    }

    #[test]
    fn the_registry_separates_senders_and_stays_bounded() {
        reset_registry_for_test();
        // Two probes from A, two from B: neither reaches the threshold, so
        // one sender's probing must not escalate the other's conversation.
        for _ in 0..2 {
            assert!(observe_inbound_for("sender-a", &report(vec![probe()], false)).is_none());
            assert!(observe_inbound_for("sender-b", &report(vec![probe()], false)).is_none());
        }
        assert!(
            observe_inbound_for("sender-a", &report(vec![probe()], false)).is_some(),
            "A's third probe is A's escalation"
        );

        // Rotating identities must not grow state without bound.
        for i in 0..(MAX_TRACKED_CONVERSATIONS * 2) {
            observe_inbound_for(&format!("throwaway-{i}"), &report(vec![], false));
        }
        let guard = registry()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        assert!(
            guard.by_sender.len() <= MAX_TRACKED_CONVERSATIONS,
            "the registry must stay bounded against identity rotation, got {}",
            guard.by_sender.len()
        );
        assert_eq!(guard.by_sender.len(), guard.order.len(), "no orphan keys");
    }

    #[test]
    fn neither_debug_nor_an_alert_ever_carries_the_token() {
        // A leak detector that writes the secret into logs has created the leak
        // it exists to find.
        let canary = CanaryToken::generate().unwrap();
        let literal = canary.as_context_literal().to_string();

        let debug = format!("{canary:?}");
        assert!(!debug.contains(&literal), "Debug must redact the token");

        let t = InjectionTracker::new();
        let alert = t.observe_outbound(&canary, &literal).unwrap();
        assert!(
            !alert.summary().contains(&literal),
            "an alert summary must carry the digest, never the token"
        );
        assert!(alert.summary().contains("canary token reached"));
    }
}
