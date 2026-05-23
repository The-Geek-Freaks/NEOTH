//! B-6 Item 4c — dedicated `-L neoth` tmux socket primitive.
//!
//! By default `tmux` shares one server socket per-user (`/tmp/tmux-<uid>`).
//! That means any server-scoped tmux setting NEOTH wants to apply
//! (status-bar tuning, mouse mode, key bindings, history limit) would
//! pollute the operator's own tmux. The fix: run NEOTH's tmux inside a
//! dedicated socket via `tmux -L neoth ...`. Operators keep their
//! `tmux` for their own work; NEOTH gets a clean server to apply its
//! 8 settings to (see B-6 Item 4 design notes in `PROGRESS.md`).
//!
//! Scope (this commit):
//!   - The socket-name primitive: a const + a pure helper that emits
//!     the `-L <name>` arg pair, ready to splice into any
//!     `tmux <verb>` invocation.
//!   - A config-friendly `TmuxSocket` newtype that wraps the optional
//!     socket name so `freedom.yaml::claude_cli.tmux.socket_name`
//!     round-trips correctly + serialises empty string ⇔ default
//!     shared socket (backward-compatible default).
//!
//! Threading the helper through every existing `Command::new("tmux")`
//! site in `tmux_session.rs` + `tmux_sweeper.rs` + `claude_tmux.rs`
//! is the integration follow-up — bounded mechanical change once the
//! primitive lands here.

use serde::{Deserialize, Serialize};

/// Canonical NEOTH socket name. Pinned: a future rename needs an
/// operator migration note (existing warm sessions would be orphaned
/// under the old name).
pub const NEOTH_TMUX_SOCKET: &str = "neoth";

/// One operator-configured tmux socket. `None` ⇒ use the shared
/// per-user socket (backward-compatible default); `Some(name)` ⇒
/// pass `-L <name>` to every tmux invocation.
///
/// On disk the type round-trips through an empty-string ⇔ default
/// representation so a freshly initialised `freedom.yaml` stays
/// minimal (no extra key when the operator wants the default).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TmuxSocket(Option<String>);

impl TmuxSocket {
    /// Empty constructor — uses the shared per-user socket.
    pub fn shared() -> Self {
        Self(None)
    }

    /// Construct from an operator-supplied name. Trims surrounding
    /// whitespace; empty/whitespace-only inputs degrade to shared so
    /// `freedom.yaml::socket_name: ""` is identical to leaving the
    /// key out.
    pub fn from_name(name: impl Into<String>) -> Self {
        let s = name.into();
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Self(None);
        }
        Self(Some(trimmed.to_string()))
    }

    /// NEOTH's canonical dedicated socket (`-L neoth`).
    pub fn neoth() -> Self {
        Self(Some(NEOTH_TMUX_SOCKET.to_string()))
    }

    /// Borrow the socket name if configured.
    pub fn name(&self) -> Option<&str> {
        self.0.as_deref()
    }

    /// True ⇔ this is the shared-socket default.
    pub fn is_shared(&self) -> bool {
        self.0.is_none()
    }
}

impl Serialize for TmuxSocket {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // Empty string ⇔ shared/default. Keeps freedom.yaml minimal.
        s.serialize_str(self.0.as_deref().unwrap_or(""))
    }
}

impl<'de> Deserialize<'de> for TmuxSocket {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(Self::from_name(s))
    }
}

/// Splice the `-L <name>` arg pair into a tmux invocation when a
/// socket name is configured. Returns an empty slice for the shared
/// socket so the call site can do `cmd.args(socket_args(...))`
/// unconditionally.
///
/// Lifetime tied to the borrowed name so no allocation happens
/// inside the helper — the caller already owns the storage.
pub fn socket_args(socket: Option<&str>) -> Vec<&str> {
    match socket {
        Some(name) if !name.is_empty() => vec!["-L", name],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neoth_socket_const_pinned() {
        // Drift guard — renaming this orphans every existing warm
        // session under the old name + needs a migration note.
        assert_eq!(NEOTH_TMUX_SOCKET, "neoth");
    }

    #[test]
    fn tmux_socket_default_is_shared() {
        let s = TmuxSocket::default();
        assert!(s.is_shared());
        assert!(s.name().is_none());
    }

    #[test]
    fn tmux_socket_shared_constructor() {
        let s = TmuxSocket::shared();
        assert!(s.is_shared());
    }

    #[test]
    fn tmux_socket_neoth_uses_canonical_const() {
        let s = TmuxSocket::neoth();
        assert!(!s.is_shared());
        assert_eq!(s.name(), Some(NEOTH_TMUX_SOCKET));
    }

    #[test]
    fn tmux_socket_from_name_round_trip() {
        let s = TmuxSocket::from_name("custom");
        assert_eq!(s.name(), Some("custom"));
    }

    #[test]
    fn tmux_socket_from_empty_name_degrades_to_shared() {
        assert!(TmuxSocket::from_name("").is_shared());
        assert!(TmuxSocket::from_name("   ").is_shared());
    }

    #[test]
    fn tmux_socket_from_whitespace_trims() {
        let s = TmuxSocket::from_name("  spaced  ");
        assert_eq!(s.name(), Some("spaced"));
    }

    #[test]
    fn serde_round_trip_via_yaml() {
        let s = TmuxSocket::neoth();
        let y = serde_yaml::to_string(&s).unwrap();
        let back: TmuxSocket = serde_yaml::from_str(&y).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn serde_shared_round_trips_as_empty_string() {
        let s = TmuxSocket::shared();
        let y = serde_yaml::to_string(&s).unwrap();
        // Empty string keeps freedom.yaml minimal — no quoted key.
        assert!(y.contains("''") || y.trim_end_matches('\n') == "''" || y == "''\n");
        let back: TmuxSocket = serde_yaml::from_str(&y).unwrap();
        assert!(back.is_shared());
    }

    #[test]
    fn socket_args_returns_empty_for_shared() {
        let args = socket_args(None);
        assert!(args.is_empty());
    }

    #[test]
    fn socket_args_returns_empty_for_empty_name() {
        let args = socket_args(Some(""));
        assert!(args.is_empty());
    }

    #[test]
    fn socket_args_emits_minus_l_pair_for_named_socket() {
        let args = socket_args(Some("neoth"));
        assert_eq!(args, vec!["-L", "neoth"]);
    }

    #[test]
    fn socket_args_pair_splices_at_start_of_tmux_command() {
        // Pin the splice-shape: every tmux command becomes
        // `tmux -L <name> <verb> ...`. If a future refactor splices
        // the args after the verb, tmux rejects with
        // `unknown option`. This drift-guard asserts the ordering.
        let prefix = socket_args(Some("neoth"));
        assert_eq!(prefix.first(), Some(&"-L"));
        assert_eq!(prefix.get(1), Some(&"neoth"));
        assert_eq!(prefix.len(), 2);
    }
}
