//! Transport layer — encrypted egress for provider traffic.
//!
//! v0.1.x scope: Hysteria QUIC subprocess management. Future:
//! native socks/http/quic clients, tor adapter, custom transports.

pub mod hysteria;
/// TERMIX-01 — SSH tunnel config types. Unconditional so
/// `freedom.yaml::ssh_tunnels` parses + round-trips on every build; the
/// russh runtime lives in `ssh_tunnel` behind the feature.
pub mod ssh_config;
/// TERMIX-03 — inline SOCKS5 relay protocol (server handshake + client dialer;
/// pure tokio). The `ssh-tunnel` feature bridges it to an SSH channel.
pub mod ssh_socks5;
/// TERMIX-04 — SSH host-key TOFU store (pure rusqlite; the `ssh-tunnel` feature
/// modules consume it). Compiles + unit-tests on the default build.
pub mod ssh_tofu;
/// TERMIX-01 — SSH local-forward tunnel + TOFU-enforcing russh handler.
/// Behind the `ssh-tunnel` feature (pulls `russh` with the `ring` backend).
#[cfg(feature = "ssh-tunnel")]
pub mod ssh_tunnel;
/// TERMIX-02 — N-hop SSH jump-host chain (ProxyJump). `ssh-tunnel` feature.
#[cfg(feature = "ssh-tunnel")]
pub mod ssh_jump;
