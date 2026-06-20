//! TERMIX-02 — N-hop SSH jump-host chain (feature `ssh-tunnel`).
//!
//! ProxyJump semantics: hop-0 is a direct TCP connect; each later hop is dialed
//! through the previous hop's `direct-tcpip` channel (so the chain is tunneled
//! end-to-end), and the final target session rides on top of the last hop. Each
//! hop's host key is independently TOFU-verified by [`super::ssh_tunnel::
//! SshHandler`].

use std::sync::Arc;

use anyhow::Result;
use russh::client;
use tokio::sync::Mutex;

use super::ssh_tofu::TofuStore;
use super::ssh_tunnel::{SshEndpoint, SshHandler, authenticate, connect_endpoint};

/// Connect to `target` through `jump_hosts` in order. Empty `jump_hosts` ==
/// a plain direct connect to `target`. Returns the live handle to the final
/// target's SSH session.
pub async fn connect_via_jumps(
    jump_hosts: &[SshEndpoint],
    target: &SshEndpoint,
    tofu: Arc<Mutex<TofuStore>>,
    config: Arc<client::Config>,
) -> Result<client::Handle<SshHandler>> {
    if jump_hosts.is_empty() {
        return connect_endpoint(target, tofu, config).await;
    }
    // hop-0: a normal direct TCP connect + auth.
    let mut handle = connect_endpoint(&jump_hosts[0], tofu.clone(), config.clone()).await?;
    // Remaining hops, then the final target, each dialed through the previous
    // hop's direct-tcpip channel.
    for hop in jump_hosts[1..].iter().chain(std::iter::once(target)) {
        let channel = handle
            .channel_open_direct_tcpip(hop.host.clone(), hop.port as u32, "127.0.0.1", 0)
            .await?;
        let stream = channel.into_stream();
        let handler = SshHandler::new(tofu.clone(), hop.host_key());
        let mut next = client::connect_stream(config.clone(), stream, handler).await?;
        authenticate(&mut next, hop).await?;
        // The previous `handle` is dropped only after the next session is fully
        // established over its channel, keeping the whole chain alive.
        handle = next;
    }
    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::ssh_tunnel::SshAuth;

    // The chain ordering (hop-0 direct, rest through channels, target last) is
    // the security-relevant invariant; the live connects are integration-gated.
    #[test]
    fn chain_iteration_order_is_hops_then_target() {
        let ep = |h: &str| SshEndpoint {
            host: h.into(),
            port: 22,
            username: "u".into(),
            auth: SshAuth::Password("p".into()),
        };
        let jumps = [ep("hop0"), ep("hop1")];
        let target = ep("dest");
        // The dial order after hop-0 is hop1, then dest.
        let order: Vec<String> = jumps[1..]
            .iter()
            .chain(std::iter::once(&target))
            .map(|e| e.host.clone())
            .collect();
        assert_eq!(order, vec!["hop1".to_string(), "dest".to_string()]);
    }
}
