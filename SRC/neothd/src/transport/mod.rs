//! Transport layer — encrypted egress for provider traffic.
//!
//! v0.1.x scope: Hysteria QUIC subprocess management. Future:
//! native socks/http/quic clients, tor adapter, custom transports.

pub mod hysteria;
/// TERMIX-04 — SSH host-key TOFU store (pure rusqlite; the `ssh-tunnel` feature
/// modules consume it). Compiles + unit-tests on the default build.
pub mod ssh_tofu;
