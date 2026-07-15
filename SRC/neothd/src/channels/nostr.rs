//! GOLD-FEAT-10 — Nostr channel adapter (RECEIVE + SEND), behind the
//! `nostr-channel` cargo feature. Uses `nostr-sdk` — a tokio-native client that
//! owns relay connection management, the WSS transport, and the NIP-44/NIP-59
//! cryptography behind NIP-17 private direct messages.
//!
//! [`NostrChannel::run`] builds a client signed by the operator's key, connects
//! to the configured relays, subscribes to gift-wrap events (kind 1059)
//! addressed to the operator, unwraps each into its inner rumor, feeds the DM
//! into the pipeline `handler`, and sends any reply back as a NIP-17 private
//! message to the original sender.
//!
//! ## Why a published `Client`, not a fresh connection per send
//!
//! Like the IRC adapter, the receive loop owns the connected client and
//! publishes a clone into a `OnceCell`; [`NostrChannel::send_text`] /
//! [`send_proactive`] send through that clone (the `nostr-sdk` `Client` is
//! internally reference-counted, so a clone shares the same relay pool). A
//! proactive send therefore only works once the receive loop is live (the
//! daemon spawns it at startup) — a send before then returns a clear
//! `Transport` error rather than opening a throwaway connection.
//!
//! ## Restart catch-up + de-duplication
//!
//! Gift-wrap OUTER timestamps are randomized (up to ~2 days back) to resist
//! timing analysis. A plain `since(now)` subscription therefore loses messages
//! received while the daemon was offline, while filtering on the INNER rumor at
//! each startup loses the same messages by construction. NEOTH keeps a durable
//! cursor instead: first boot subscribes live-only, later boots overlap the last
//! completed relay scan by the full NIP-59 timestamp-tweak window and de-duplicate
//! stable outer event IDs. Cursor claims are persisted before dispatch, giving
//! restart-safe at-most-once delivery instead of duplicate LLM turns/replies.
//!
//! ## Operator prerequisite
//!
//! A Nostr secret key (`nsec1…` or hex) + a comma-separated relay list in
//! `credentials.yaml`. NEOTH dials OUT to the relays, so no public URL is
//! needed. Text only; media / NIP-17 file attachments are documented follow-ups.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use async_trait::async_trait;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::secret::SecretString;

use super::nostr_api::{map_nostr_dm, nostr_text_chunks};
use super::{Channel, ChannelError, MessageId, PipelineHandler};

fn parse_keys(secret_key: &SecretString) -> Result<Keys> {
    Keys::parse(secret_key.expose()).map_err(|_| {
        anyhow::anyhow!("invalid Nostr secret key (expected a valid nsec1 key or 64-char hex)")
    })
}

fn normalize_relay_urls(relays_csv: &str) -> Result<Vec<String>> {
    let mut relays = std::collections::BTreeSet::new();
    for relay in relays_csv
        .split(',')
        .map(str::trim)
        .filter(|relay| !relay.is_empty())
    {
        let parsed = reqwest::Url::parse(relay)
            .map_err(|_| anyhow::anyhow!("invalid Nostr relay URL `{relay}`"))?;
        if parsed.scheme() != "wss" || parsed.host_str().is_none() {
            anyhow::bail!("Nostr relay `{relay}` must be an absolute wss:// URL");
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            anyhow::bail!("Nostr relay URLs must not contain credentials");
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            anyhow::bail!("Nostr relay URLs must not contain a query or fragment");
        }
        relays.insert(parsed.to_string());
    }
    if relays.is_empty() {
        anyhow::bail!("Nostr needs at least one wss:// relay URL");
    }
    Ok(relays.into_iter().collect())
}

/// Validate exactly the key and relay contract consumed by the live adapter.
/// The returned CSV is canonical and safe to persist; key parse failures are
/// intentionally static so operator-visible errors can never echo the secret.
pub(crate) fn validate_configuration(
    secret_key: &SecretString,
    relays_csv: &str,
) -> Result<String> {
    let _ = parse_keys(secret_key)?;
    Ok(normalize_relay_urls(relays_csv)?.join(","))
}

/// Connect to the configured relay pool without subscribing or publishing.
/// The probe proves key parsing plus live WebSocket reachability while leaving
/// the inbox and relay event state untouched.
pub async fn probe_relays(secret_key: &SecretString, relays_csv: &str) -> Result<String> {
    let keys = parse_keys(secret_key)?;
    let public_key = keys.public_key().to_hex();
    let relays = normalize_relay_urls(relays_csv)?;
    let client = Client::builder().signer(keys).build();
    for relay in &relays {
        client
            .add_relay(relay.as_str())
            .await
            .with_context(|| format!("add Nostr relay {relay}"))?;
    }
    let outcome = client.try_connect(super::readiness::PROBE_TIMEOUT).await;
    client.disconnect().await;
    classify_relay_probe(&public_key, outcome.success.len(), outcome.failed.len())
}

fn classify_relay_probe(public_key: &str, connected: usize, failed: usize) -> Result<String> {
    if connected == 0 {
        anyhow::bail!("Nostr could not connect to any configured relay ({failed} failed)");
    }
    Ok(format!(
        "Nostr identity {public_key} reached {connected} relay(s); {failed} failed"
    ))
}

/// NIP-59 randomizes gift-wrap timestamps backwards by at most two days.
/// Keep one extra second so an inclusive/exclusive relay boundary cannot lose
/// an event exactly at the edge.
const GIFT_WRAP_OVERLAP_SECS: u64 = 172_801;
/// Accept modest sender clock skew around the first-enable boundary without
/// reopening arbitrary pre-install history on the first catch-up.
const INITIAL_CLOCK_SKEW_SECS: u64 = 300;
/// Defensive disk bound. Normal pruning retains only the two-day overlap; this
/// cap protects an open channel from an unbounded spam-created cursor file.
const MAX_CURSOR_EVENT_IDS: usize = 50_000;
const CURSOR_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NostrCursorState {
    version: u8,
    identity_pubkey: String,
    initialized_at_unix: u64,
    completed_scan_unix: u64,
    /// Stable outer gift-wrap event ID -> randomized outer created_at.
    processed_event_ids: BTreeMap<String, u64>,
}

impl NostrCursorState {
    fn new(identity_pubkey: String, now: u64) -> Self {
        Self {
            version: CURSOR_VERSION,
            identity_pubkey,
            initialized_at_unix: now,
            completed_scan_unix: now,
            processed_event_ids: BTreeMap::new(),
        }
    }

    fn load_or_initialize(path: &Path, identity_pubkey: &str, now: u64) -> Result<(Self, bool)> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let state = Self::new(identity_pubkey.to_string(), now);
                state.persist(path)?;
                return Ok((state, true));
            }
            Err(e) => {
                return Err(e).with_context(|| format!("read Nostr cursor {}", path.display()));
            }
        };
        let state: Self = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse Nostr cursor {}", path.display()))?;
        if state.version != CURSOR_VERSION {
            anyhow::bail!(
                "unsupported Nostr cursor version {} in {} (expected {})",
                state.version,
                path.display(),
                CURSOR_VERSION
            );
        }
        if state.identity_pubkey != identity_pubkey {
            // A rotated key is a different inbox. Reusing the old identity's
            // cursor could suppress the new inbox, so establish a clean live
            // boundary and atomically replace the old state.
            let state = Self::new(identity_pubkey.to_string(), now);
            state.persist(path)?;
            return Ok((state, true));
        }
        Ok((state, false))
    }

    fn persist(&self, path: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self).context("serialize Nostr cursor")?;
        crate::util::atomic_write::atomic_write(path, &bytes)
            .with_context(|| format!("persist Nostr cursor {}", path.display()))
    }

    /// Claim an event durably before any policy/pipeline/reply side effect.
    /// Returns false for an already-claimed relay replay.
    fn claim(&mut self, path: &Path, event_id: String, outer_created_at: u64) -> Result<bool> {
        if self.processed_event_ids.contains_key(&event_id) {
            return Ok(false);
        }
        self.processed_event_ids
            .insert(event_id.clone(), outer_created_at);
        if let Err(e) = self.persist(path) {
            self.processed_event_ids.remove(&event_id);
            return Err(e);
        }
        Ok(true)
    }

    fn complete_scan(&mut self, path: &Path, scan_started_at: u64) -> Result<()> {
        self.completed_scan_unix = self.completed_scan_unix.max(scan_started_at);
        let retain_after = self
            .completed_scan_unix
            .saturating_sub(GIFT_WRAP_OVERLAP_SECS);
        self.processed_event_ids
            .retain(|_, outer_created_at| *outer_created_at >= retain_after);

        if self.processed_event_ids.len() > MAX_CURSOR_EVENT_IDS {
            let mut by_age: Vec<(String, u64)> = self
                .processed_event_ids
                .iter()
                .map(|(id, ts)| (id.clone(), *ts))
                .collect();
            by_age.sort_unstable_by_key(|(_, ts)| *ts);
            let remove_count = by_age.len() - MAX_CURSOR_EVENT_IDS;
            for (id, _) in by_age.into_iter().take(remove_count) {
                self.processed_event_ids.remove(&id);
            }
        }
        self.persist(path)
    }
}

/// Nostr adapter. Holds the operator's signing key + the relay list + the live
/// client handle (published by the receive loop once it connects).
pub struct NostrChannel {
    secret_key: SecretString,
    relays: Vec<String>,
    client: tokio::sync::OnceCell<Client>,
    /// D2 — operator sender allowlist (a 64-char hex pubkey). `None` ⇒ open.
    allowed_pubkey: Option<String>,
    /// D2 — WAL writer for the `0x3B CHANNEL_GATE_REJECTED` audit on a drop.
    gate_writer: Option<crate::wal::writer::WalWriterHandle>,
    /// Durable restart cursor. Required for a live adapter; injected from the
    /// daemon's actual (possibly non-default) NEOTH home.
    cursor_path: Option<PathBuf>,
}

impl NostrChannel {
    /// Build the adapter. Construction is cheap + does no I/O — the connection
    /// happens in [`Self::run`]. `relays_csv` is a comma-separated list of WSS
    /// relay URLs (e.g. `wss://relay.damus.io,wss://nos.lol`).
    pub fn new(secret_key: SecretString, relays_csv: impl AsRef<str>) -> Self {
        let relays: Vec<String> = relays_csv
            .as_ref()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        Self {
            secret_key,
            relays,
            client: tokio::sync::OnceCell::new(),
            allowed_pubkey: None,
            gate_writer: None,
            cursor_path: None,
        }
    }

    /// D2 — bind the operator sender allowlist + the gate's audit writer. An
    /// unset allowlist (`None`) leaves the channel open (any sender).
    pub fn with_allowlist(
        mut self,
        allowed_pubkey: Option<String>,
        gate_writer: crate::wal::writer::WalWriterHandle,
    ) -> Self {
        self.allowed_pubkey = allowed_pubkey;
        self.gate_writer = Some(gate_writer);
        self
    }

    /// Bind the durable restart cursor to the daemon's real home directory.
    pub fn with_cursor_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.cursor_path = Some(path.into());
        self
    }

    /// Parse the operator's secret key (accepts `nsec1…` bech32 or 64-char hex).
    fn keys(&self) -> Result<Keys> {
        parse_keys(&self.secret_key)
    }
}

#[async_trait]
impl Channel for NostrChannel {
    fn name(&self) -> &'static str {
        "nostr"
    }

    /// Connect to the relays, subscribe to inbound gift-wrapped DMs, publish the
    /// client handle, then stream + unwrap NIP-17 messages into the pipeline
    /// until the daemon aborts the spawned task. A fatal key/connect error
    /// returns `Err` (the spawn loop logs it, no restart-spin on a broken
    /// config); transient relay drops are handled by the SDK's relay pool.
    async fn run(&self, handler: PipelineHandler) -> Result<()> {
        let keys = self.keys()?;
        let relays = normalize_relay_urls(&self.relays.join(","))?;
        let my_pubkey = keys.public_key();
        let cursor_path = self
            .cursor_path
            .as_deref()
            .context("nostr cursor path not configured")?;
        let scan_started_at = crate::time::now_unix_secs();
        let (mut cursor, first_boot) = NostrCursorState::load_or_initialize(
            cursor_path,
            &my_pubkey.to_hex(),
            scan_started_at,
        )?;
        let client = Client::builder().signer(keys).build();
        for relay in &relays {
            client
                .add_relay(relay.as_str())
                .await
                .with_context(|| format!("add nostr relay {relay}"))?;
        }
        client.connect().await;
        // Publish the (ref-counted) client so `send_text` can send while the
        // loop runs.
        let _ = self.client.set(client.clone());

        // Create the broadcast receiver BEFORE subscribing; otherwise a fast
        // relay can emit stored events/EOSE before a receiver exists.
        let mut notifications = client.notifications();
        // First enable is intentionally live-only. On later runs, query from
        // the last fully completed scan minus the full NIP-59 backdate window.
        let mut filter = Filter::new().kind(Kind::GiftWrap).pubkey(my_pubkey);
        if first_boot {
            filter = filter.limit(0);
        } else {
            filter = filter.since(Timestamp::from(
                cursor
                    .completed_scan_unix
                    .saturating_sub(GIFT_WRAP_OVERLAP_SECS),
            ));
        }
        let subscription = client
            .subscribe(filter, None)
            .await
            .context("nostr subscribe to gift wraps")?;
        if subscription.success.is_empty() {
            anyhow::bail!(
                "nostr subscription failed on every relay ({} failures)",
                subscription.failed.len()
            );
        }
        if !subscription.failed.is_empty() {
            warn!(
                failed_relays = subscription.failed.len(),
                live_relays = subscription.success.len(),
                "nostr subscription partially degraded"
            );
        }
        let subscription_id = subscription.val;
        let mut awaiting_eose: HashSet<RelayUrl> = subscription.success;
        info!(
            relays = awaiting_eose.len(),
            catch_up = !first_boot,
            "nostr adapter live"
        );

        while let Ok(notification) = notifications.recv().await {
            let event = match notification {
                RelayPoolNotification::Message {
                    relay_url,
                    message: RelayMessage::EndOfStoredEvents(id),
                } if id.as_ref() == &subscription_id => {
                    awaiting_eose.remove(&relay_url);
                    if awaiting_eose.is_empty() && cursor.completed_scan_unix < scan_started_at {
                        cursor.complete_scan(cursor_path, scan_started_at)?;
                        info!(
                            completed_scan_unix = cursor.completed_scan_unix,
                            "nostr catch-up cursor advanced"
                        );
                    }
                    continue;
                }
                RelayPoolNotification::Event {
                    subscription_id: id,
                    event,
                    ..
                } if id == subscription_id => event,
                _ => continue,
            };
            if event.kind != Kind::GiftWrap {
                continue;
            }
            let outer_id = event.id.to_hex();
            if !cursor.claim(cursor_path, outer_id.clone(), event.created_at.as_secs())? {
                continue;
            }
            let unwrapped = match client.unwrap_gift_wrap(&event).await {
                Ok(u) => u,
                Err(e) => {
                    warn!(error = %e, "nostr gift-wrap unwrap failed; skipping");
                    continue;
                }
            };
            let sender = unwrapped.sender;
            if sender == my_pubkey {
                continue; // never answer our own NIP-17 sent-copy
            }
            // D2 — drop + audit a sender not on the operator allowlist before
            // the pipeline sees the message (open when None).
            if super::sender_blocked_by_allowlist(
                self.allowed_pubkey.as_deref(),
                &sender.to_hex(),
                self.gate_writer.as_ref(),
                "nostr",
            )
            .await
            {
                continue;
            }
            let mut rumor = unwrapped.rumor;
            if rumor.kind != Kind::PrivateDirectMessage {
                warn!(
                    kind = rumor.kind.as_u16(),
                    "nostr gift-wrap contained a non-DM rumor; skipping"
                );
                continue;
            }
            let rumor_ts = rumor.created_at.as_secs();
            if rumor_ts.saturating_add(INITIAL_CLOCK_SKEW_SECS) < cursor.initialized_at_unix {
                continue; // never import arbitrary pre-enable history
            }
            let mut inbound = match map_nostr_dm(&sender.to_hex(), &rumor.content, rumor_ts) {
                Some(inbound) => inbound,
                None => continue,
            };
            // The inner rumor ID is stable across gift wraps and is the useful
            // provider correlation ID for WAL/edit/de-dup observability.
            inbound.message_id = Some(rumor.id().to_hex());
            match handler(inbound).await {
                Ok(Some(out)) => {
                    for chunk in nostr_text_chunks(&out.text) {
                        if let Err(e) = client.send_private_msg(sender, chunk, []).await {
                            warn!(error = %e, "nostr DM reply failed (dropped)");
                            break;
                        }
                    }
                }
                Ok(None) => {} // pipeline chose to stay silent
                Err(e) => warn!(error = %e, "nostr pipeline handler errored; skipping message"),
            }
        }
        Ok(())
    }

    /// Send a NIP-17 private message to `chat_id` (the recipient's pubkey, hex or
    /// `npub1…`) via the live client. Long text is split into relay-safe chunks.
    /// Returns a `Transport` error if the receive loop has not connected yet.
    async fn send_text(
        &self,
        chat_id: &str,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        let client = self.client.get().ok_or_else(|| {
            ChannelError::Transport(
                "nostr not connected (the receive loop must be live to send)".into(),
            )
        })?;
        let recipient = PublicKey::parse(chat_id)
            .map_err(|e| ChannelError::Transport(format!("invalid nostr recipient pubkey: {e}")))?;
        for chunk in nostr_text_chunks(text) {
            client
                .send_private_msg(recipient, chunk, [])
                .await
                .map_err(|e| ChannelError::Transport(format!("nostr send: {e}")))?;
        }
        Ok(MessageId("sent".to_string()))
    }

    /// Proactive send delegates to [`Self::send_text`] — a daemon-initiated DM is
    /// identical to a reply. The operator proactive gate is the caller's
    /// responsibility per the C-11 trait contract.
    async fn send_proactive(
        &self,
        chat_id: &str,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        self.send_text(chat_id, text).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ch() -> NostrChannel {
        NostrChannel::new(
            SecretString::from("nsec1exampledummykeydummy"),
            "wss://relay.damus.io, wss://nos.lol ,",
        )
    }

    #[test]
    fn adapter_reports_nostr_name() {
        assert_eq!(ch().name(), "nostr");
    }

    #[test]
    fn new_parses_relay_csv_trimming_blanks() {
        let c = ch();
        assert_eq!(
            c.relays,
            vec!["wss://relay.damus.io", "wss://nos.lol"],
            "trims spaces + drops the trailing empty"
        );
    }

    #[test]
    fn configuration_uses_real_key_parser_and_normalizes_secure_relays() {
        let key = SecretString::from("11".repeat(32));
        let relays = validate_configuration(
            &key,
            " WSS://Relay.Example.com, wss://relay.example.com/room, wss://relay.example.com ",
        )
        .unwrap();
        assert_eq!(
            relays,
            "wss://relay.example.com/,wss://relay.example.com/room"
        );
        assert!(validate_configuration(&key, "ws://relay.example.com").is_err());
        assert!(validate_configuration(&key, "https://relay.example.com").is_err());
    }

    #[test]
    fn invalid_key_error_never_contains_secret() {
        let secret = "nsec1-not-a-real-key-secret-material";
        let error = validate_configuration(&SecretString::from(secret), "wss://relay.example.com")
            .unwrap_err()
            .to_string();
        assert!(!error.contains(secret));
        assert!(error.contains("invalid Nostr secret key"));
    }

    #[test]
    fn relay_probe_requires_at_least_one_live_relay_without_secret_output() {
        let detail = classify_relay_probe("public-key", 2, 1).unwrap();
        assert!(detail.contains("public-key"));
        assert!(detail.contains("2 relay"));

        let secret = "nostr-super-secret";
        let error = classify_relay_probe(secret, 0, 3).unwrap_err().to_string();
        assert!(!error.contains(secret));
        assert!(error.contains("3 failed"));
    }

    #[test]
    fn cursor_initializes_atomically_and_reloads_for_same_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nostr-cursor.json");
        let (created, first_boot) =
            NostrCursorState::load_or_initialize(&path, "pubkey-a", 1_000).unwrap();
        assert!(first_boot);
        assert_eq!(created.initialized_at_unix, 1_000);
        assert!(path.exists());

        let (reloaded, first_boot) =
            NostrCursorState::load_or_initialize(&path, "pubkey-a", 2_000).unwrap();
        assert!(!first_boot);
        assert_eq!(reloaded.initialized_at_unix, 1_000);
        assert_eq!(reloaded.completed_scan_unix, 1_000);
    }

    #[test]
    fn cursor_rotation_starts_a_new_identity_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nostr-cursor.json");
        let (mut old, _) = NostrCursorState::load_or_initialize(&path, "pubkey-a", 1_000).unwrap();
        assert!(old.claim(&path, "event-a".into(), 900).unwrap());

        let (rotated, first_boot) =
            NostrCursorState::load_or_initialize(&path, "pubkey-b", 2_000).unwrap();
        assert!(first_boot);
        assert_eq!(rotated.identity_pubkey, "pubkey-b");
        assert_eq!(rotated.initialized_at_unix, 2_000);
        assert!(rotated.processed_event_ids.is_empty());
    }

    #[test]
    fn cursor_claim_is_durable_and_duplicate_safe() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nostr-cursor.json");
        let (mut state, _) =
            NostrCursorState::load_or_initialize(&path, "pubkey-a", 1_000).unwrap();
        assert!(state.claim(&path, "event-a".into(), 950).unwrap());
        assert!(!state.claim(&path, "event-a".into(), 950).unwrap());

        let (mut reloaded, _) =
            NostrCursorState::load_or_initialize(&path, "pubkey-a", 2_000).unwrap();
        assert!(!reloaded.claim(&path, "event-a".into(), 950).unwrap());
    }

    #[test]
    fn completed_scan_prunes_only_outside_the_nip59_overlap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nostr-cursor.json");
        let now = GIFT_WRAP_OVERLAP_SECS + 10_000;
        let mut state = NostrCursorState::new("pubkey-a".into(), 1);
        state.processed_event_ids.insert("expired".into(), 9_998);
        state.processed_event_ids.insert("edge".into(), 9_999);
        state.processed_event_ids.insert("recent".into(), now);
        state.persist(&path).unwrap();

        state.complete_scan(&path, now).unwrap();
        assert!(!state.processed_event_ids.contains_key("expired"));
        assert!(state.processed_event_ids.contains_key("edge"));
        assert!(state.processed_event_ids.contains_key("recent"));
    }

    #[test]
    fn malformed_cursor_fails_closed_instead_of_replaying_history() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nostr-cursor.json");
        std::fs::write(&path, b"not-json").unwrap();
        let err = NostrCursorState::load_or_initialize(&path, "pubkey-a", 1_000).unwrap_err();
        assert!(err.to_string().contains("parse Nostr cursor"));
    }

    #[test]
    fn live_adapter_requires_explicit_cursor_binding() {
        assert!(ch().cursor_path.is_none());
        let c = ch().with_cursor_path("custom-home/channel-state/nostr.json");
        assert_eq!(
            c.cursor_path.as_deref(),
            Some(Path::new("custom-home/channel-state/nostr.json"))
        );
    }

    #[tokio::test]
    async fn send_before_connect_is_a_clear_transport_error() {
        let c = ch();
        let err = c
            .send_text(
                "npub1sg6plzptd64u62a878hep2kev88swjh3tw00gjsfl8f237lmu63q0uf63m",
                "hi",
            )
            .await
            .unwrap_err();
        match err {
            ChannelError::Transport(m) => assert!(m.contains("not connected")),
            other => panic!("expected a not-connected Transport error, got {other:?}"),
        }
    }
}
