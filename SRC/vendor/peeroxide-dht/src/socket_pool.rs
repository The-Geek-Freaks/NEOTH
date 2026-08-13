use std::net::SocketAddr;

use libudx::{Datagram, UdxRuntime, UdxSocket};
use tokio::sync::mpsc;

const HOLEPUNCH_MSG: &[u8] = &[0];
const HOLEPUNCH_TTL: u32 = 5;
const DEFAULT_TTL: u32 = 64;
const HOLEPUNCH_EVENT_QUEUE_CAPACITY: usize = 64;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SocketPoolError {
    #[error("udx error: {0}")]
    Udx(#[from] libudx::UdxError),
    #[error("invalid address: {0}")]
    AddrParse(#[from] std::net::AddrParseError),
}

pub type Result<T> = std::result::Result<T, SocketPoolError>;

pub struct SocketPool {
    host: String,
}

impl SocketPool {
    pub fn new(host: String) -> Self {
        Self { host }
    }

    pub async fn acquire(&self, runtime: &UdxRuntime) -> Result<SocketRef> {
        let socket = runtime.create_socket().await?;
        let addr: SocketAddr = format!("{}:0", self.host).parse()?;
        socket.bind(addr).await?;

        let (hp_tx, hp_rx) = mpsc::channel(HOLEPUNCH_EVENT_QUEUE_CAPACITY);
        let recv_rx = socket.recv_start()?;

        let recv_task = tokio::spawn(route_messages(recv_rx, hp_tx));

        Ok(SocketRef {
            socket,
            holepunch_rx: hp_rx,
            recv_task: Some(recv_task),
        })
    }
}

async fn route_messages(
    mut recv_rx: mpsc::Receiver<Datagram>,
    hp_tx: mpsc::Sender<HolepunchEvent>,
) {
    while let Some(dgram) = recv_rx.recv().await {
        if dgram.data.len() <= 1 {
            // Holepunch probes are already raw/unreliable. Coalesce overload by
            // dropping this signal rather than creating an unbounded task or a
            // warning for every probe; the peer's normal retry remains valid.
            let _ = hp_tx.try_send(HolepunchEvent { addr: dgram.addr });
        }
        // DHT messages (>1 byte) on holepunch sockets are dropped — only the
        // primary client/server sockets in io.rs handle DHT protocol traffic.
    }
}

#[derive(Debug)]
pub struct HolepunchEvent {
    pub addr: SocketAddr,
}

pub struct SocketRef {
    pub socket: UdxSocket,
    pub holepunch_rx: mpsc::Receiver<HolepunchEvent>,
    recv_task: Option<tokio::task::JoinHandle<()>>,
}

impl SocketRef {
    pub fn send_holepunch(&self, addr: SocketAddr, low_ttl: bool) -> Result<()> {
        let _ttl = if low_ttl { HOLEPUNCH_TTL } else { DEFAULT_TTL };
        // TODO: TTL support requires udx_socket_set_ttl which isn't exposed yet.
        self.socket.send_to(HOLEPUNCH_MSG, addr)?;
        Ok(())
    }

    pub fn send_holepunch_to(&self, host: &str, port: u16, low_ttl: bool) -> Result<()> {
        let addr: SocketAddr = format!("{host}:{port}").parse()?;
        self.send_holepunch(addr, low_ttl)
    }
}

impl Drop for SocketRef {
    fn drop(&mut self) {
        if let Some(handle) = self.recv_task.take() {
            // The route task owns the bounded receiver; dropping its JoinHandle
            // would detach it until a sender happens to disappear.
            handle.abort();
        }
    }
}

pub fn random_port() -> u16 {
    1000 + (rand::random::<f64>() * 64536.0) as u16
}

pub fn coerce_firewall(fw: u64) -> u64 {
    use crate::hyperdht_messages::{FIREWALL_CONSISTENT, FIREWALL_OPEN};
    if fw == FIREWALL_OPEN {
        FIREWALL_CONSISTENT
    } else {
        fw
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hyperdht_messages::{
        FIREWALL_CONSISTENT, FIREWALL_OPEN, FIREWALL_RANDOM, FIREWALL_UNKNOWN,
    };

    #[test]
    fn random_port_in_range() {
        for _ in 0..1000 {
            let p = random_port();
            assert!(p >= 1000);
        }
    }

    #[test]
    fn coerce_open_to_consistent() {
        assert_eq!(coerce_firewall(FIREWALL_OPEN), FIREWALL_CONSISTENT);
    }

    #[test]
    fn coerce_consistent_unchanged() {
        assert_eq!(coerce_firewall(FIREWALL_CONSISTENT), FIREWALL_CONSISTENT);
    }

    #[test]
    fn coerce_random_unchanged() {
        assert_eq!(coerce_firewall(FIREWALL_RANDOM), FIREWALL_RANDOM);
    }

    #[test]
    fn coerce_unknown_unchanged() {
        assert_eq!(coerce_firewall(FIREWALL_UNKNOWN), FIREWALL_UNKNOWN);
    }
}
