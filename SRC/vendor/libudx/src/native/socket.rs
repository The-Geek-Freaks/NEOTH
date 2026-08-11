use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

use crate::error::{Result, UdxError};

/// Maximum datagrams queued for the raw, unreliable consumer of a socket.
///
/// The receiver loop uses non-blocking delivery. A full raw queue drops only
/// that unreliable datagram so one slow raw consumer cannot stall unrelated
/// streams sharing the socket.
const RAW_DATAGRAM_QUEUE_CAPACITY: usize = 128;

/// Maximum wire packets awaiting one stream's reliability processor.
///
/// A full stream queue drops only that wire packet. Because dropped packets are
/// never delivered to the reliability processor, they are neither ACKed nor
/// SACKed and the peer's ordinary retransmission logic preserves correctness.
pub(crate) const STREAM_PACKET_QUEUE_CAPACITY: usize = 256;

/// Maximum datagrams accepted by the single writer task for one UDP socket.
const OUTBOUND_DATAGRAM_QUEUE_CAPACITY: usize = 512;

/// Largest UDP payload permitted by the operating-system UDP API.
const MAX_UDP_PAYLOAD: usize = 65_507;

/// Total payload bytes allowed to wait behind the one writer.
///
/// The packet-count channel alone is not an allocation bound: an attacker (or
/// a local caller) could otherwise fill 512 slots with maximum-sized payloads.
/// Raw and reliable packets share this reservation so a relay or retransmit
/// burst cannot evade the same socket-wide backpressure.
const EGRESS_BYTE_BUDGET: usize = 1_048_576;

/// Reliable UDX wire packets may not exceed the protocol's negotiated MTU
/// ceiling. This is intentionally stricter than the UDP API ceiling: relay
/// forwarding must not turn a single accepted UDP packet into 65 KiB of queued
/// reliable egress.
const MAX_RELIABLE_WIRE_PACKET: usize = super::stream::MTU_MAX;

/// Header-valid UDX traffic has protocol, not raw-datagram, semantics. Check
/// these bounds against the receive buffer before it is cloned into any queue.
fn admits_mapped_udx_packet(header: &super::header::Header, packet_len: usize) -> bool {
    packet_len <= MAX_RELIABLE_WIRE_PACKET && header.payload_offset() <= packet_len
}

/// An incoming unreliable datagram received on a UdxSocket.
#[derive(Debug, Clone)]
pub struct Datagram {
    /// Raw payload bytes.
    pub data: Vec<u8>,
    /// Source address of the datagram.
    pub addr: SocketAddr,
}

/// Work accepted by a socket's sole UDP writer.
///
/// This is crate-private so reliable stream paths can use the same bounded,
/// owned writer instead of creating a task for each wire packet.
#[derive(Debug)]
pub(crate) struct OutboundDatagram {
    pub(crate) data: Vec<u8>,
    pub(crate) addr: SocketAddr,
    _egress_byte_permit: Option<OwnedSemaphorePermit>,
}

/// Socket-owned admission handle for every outbound path.
///
/// The channel slot and byte permit remain owned by the queued datagram until
/// the sole writer consumes it. Keeping the permit in the message makes every
/// early-drop and socket-close path release the exact reservation automatically.
#[derive(Clone, Debug)]
pub(crate) struct OutboundSender {
    tx: mpsc::Sender<OutboundDatagram>,
    egress_bytes: Arc<Semaphore>,
}

#[derive(Default)]
struct SocketTasks {
    recv: Option<tokio::task::JoinHandle<()>>,
    writer: Option<tokio::task::JoinHandle<()>>,
}

struct UdxSocketInner {
    udp: OnceLock<Arc<tokio::net::UdpSocket>>,
    tasks: Mutex<SocketTasks>,
    streams: super::stream::StreamMap,
    fallback_tx: Arc<Mutex<Option<mpsc::Sender<Datagram>>>>,
    outbound_tx: OnceLock<OutboundSender>,
    egress_bytes: Arc<Semaphore>,
    closed: AtomicBool,
}

impl UdxSocketInner {
    fn new() -> Self {
        Self {
            udp: OnceLock::new(),
            tasks: Mutex::new(SocketTasks::default()),
            streams: Arc::new(Mutex::new(HashMap::new())),
            fallback_tx: Arc::new(Mutex::new(None)),
            outbound_tx: OnceLock::new(),
            egress_bytes: Arc::new(Semaphore::new(EGRESS_BYTE_BUDGET)),
            closed: AtomicBool::new(false),
        }
    }

    fn udp_arc(&self) -> Result<Arc<tokio::net::UdpSocket>> {
        if self.closed.load(Ordering::Acquire) {
            return Err(UdxError::RuntimeGone);
        }
        Ok(Arc::clone(self.udp.get().ok_or_else(|| {
            UdxError::Io(io::Error::other("socket not bound"))
        })?))
    }

    fn ensure_writer_loop(&self) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(UdxError::RuntimeGone);
        }
        if self.outbound_tx.get().is_some() {
            return Ok(());
        }

        let udp = self.udp_arc()?;
        let mut tasks = self.tasks.lock().unwrap_or_else(|e| e.into_inner());
        if self.outbound_tx.get().is_some() {
            return Ok(());
        }

        let (tx, mut rx) = mpsc::channel(OUTBOUND_DATAGRAM_QUEUE_CAPACITY);
        self.outbound_tx
            .set(OutboundSender {
                tx,
                egress_bytes: Arc::clone(&self.egress_bytes),
            })
            .map_err(|_| UdxError::RuntimeGone)?;
        tasks.writer = Some(tokio::spawn(async move {
            while let Some(datagram) = rx.recv().await {
                // UDP send errors are per-datagram and not actionable here.
                // Deliberately do not emit one warning per bad/overloaded peer.
                let _ = udp.send_to(&datagram.data, datagram.addr).await;
                // Dropping `datagram` here releases its socket-wide byte
                // reservation, whether it came from raw or reliable egress.
            }
        }));
        Ok(())
    }

    fn outbound_sender(&self) -> Result<OutboundSender> {
        self.ensure_writer_loop()?;
        self.outbound_tx.get().cloned().ok_or(UdxError::RuntimeGone)
    }

    fn ensure_recv_loop(&self) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(UdxError::RuntimeGone);
        }

        let mut tasks = self.tasks.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(handle) = tasks.recv.as_ref() {
            if !handle.is_finished() {
                return Ok(());
            }
        }

        let udp = self.udp_arc()?;
        let streams = Arc::clone(&self.streams);
        let fallback_tx = Arc::clone(&self.fallback_tx);

        tasks.recv = Some(tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            while let Ok((len, addr)) = udp.recv_from(&mut buf).await {
                if len >= super::header::HEADER_SIZE {
                    if let Ok(hdr) = super::header::Header::decode(&buf[..len]) {
                        // Do not allocate a full UDP datagram before UDX admission.
                        // Reliable UDX packets are MTU-bounded, and `data_offset`
                        // must refer to bytes actually received. A packet with a valid
                        // UDX header that violates either bound is malformed protocol
                        // traffic, not an application-level raw datagram.
                        if !admits_mapped_udx_packet(&hdr, len) {
                            continue;
                        }

                        let stream_tx = {
                            let guard = streams.lock().unwrap_or_else(|e| e.into_inner());
                            match guard.get(&hdr.remote_id) {
                                // A local stream ID is not an authentication token. Bind
                                // the route to the peer address fixed at connect time
                                // before copying, queueing, ACKing, relaying, or mutating
                                // reliability state. UDX has no authenticated migration
                                // transition, so a changed source is fail-closed.
                                Some(registration) if registration.accepts_source(addr) => {
                                    Some(registration.ingress())
                                }
                                // A mapped UDX route with the wrong source is not raw
                                // application traffic; drop it without side effects.
                                Some(_) => None,
                                // Preserve the historic raw fallback only for an unknown,
                                // otherwise valid, MTU-bounded UDX-looking datagram.
                                None => {
                                    drop(guard);
                                    let packet = buf[..len].to_vec();
                                    let raw_tx = fallback_tx
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner())
                                        .clone();
                                    if let Some(tx) = raw_tx {
                                        match tx.try_send(Datagram { data: packet, addr }) {
                                            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                                *fallback_tx
                                                    .lock()
                                                    .unwrap_or_else(|e| e.into_inner()) = None;
                                            }
                                        }
                                    }
                                    continue;
                                }
                            }
                        };

                        if let Some(tx) = stream_tx {
                            let packet = buf[..len].to_vec();
                            match tx.try_send(super::stream::IncomingPacket { data: packet, addr })
                            {
                                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    let stale = {
                                        let mut guard =
                                            streams.lock().unwrap_or_else(|e| e.into_inner());
                                        if guard.get(&hdr.remote_id).is_some_and(|current| {
                                            current.ingress().same_channel(&tx)
                                        }) {
                                            guard.remove(&hdr.remote_id)
                                        } else {
                                            None
                                        }
                                    };
                                    if let Some(registration) = stale {
                                        if let Some(handle) = registration.terminate() {
                                            handle.abort();
                                        }
                                    }
                                }
                            }
                            continue;
                        }

                        // `Some(_)` above means a source-mismatched mapped stream.
                        // It must not fall through to the raw queue.
                        continue;
                    }
                }

                let packet = buf[..len].to_vec();
                let raw_tx = fallback_tx
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                if let Some(tx) = raw_tx {
                    // Raw datagrams are unreliable. A full queue drops only this
                    // packet, preserving reader progress for every other route.
                    match tx.try_send(Datagram { data: packet, addr }) {
                        Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            let mut guard = fallback_tx.lock().unwrap_or_else(|e| e.into_inner());
                            if guard
                                .as_ref()
                                .is_some_and(|current| current.same_channel(&tx))
                            {
                                *guard = None;
                            }
                        }
                    }
                }
            }
        }));
        Ok(())
    }

    fn take_tasks(&self) -> Vec<tokio::task::JoinHandle<()>> {
        self.closed.store(true, Ordering::Release);
        let registrations =
            std::mem::take(&mut *self.streams.lock().unwrap_or_else(|e| e.into_inner()));
        *self.fallback_tx.lock().unwrap_or_else(|e| e.into_inner()) = None;

        let mut tasks = self.tasks.lock().unwrap_or_else(|e| e.into_inner());
        [tasks.recv.take(), tasks.writer.take()]
            .into_iter()
            .flatten()
            .chain(
                registrations
                    .into_values()
                    .filter_map(|stream| stream.terminate()),
            )
            .collect()
    }

    fn abort_tasks(&self) {
        for handle in self.take_tasks() {
            handle.abort();
        }
    }

    #[cfg(test)]
    fn active_task_count(&self) -> usize {
        let tasks = self.tasks.lock().unwrap_or_else(|e| e.into_inner());
        usize::from(tasks.recv.is_some()) + usize::from(tasks.writer.is_some())
    }
}

impl Drop for UdxSocketInner {
    fn drop(&mut self) {
        self.abort_tasks();
    }
}

/// A UDP socket used for UDX stream transport and unreliable datagrams.
///
/// UdxSocket is a cheap-clone handle. Every clone shares one bounded reader
/// and one bounded writer; close closes that shared transport and makes all
/// remaining clones fail closed.
///
/// Incoming packets are demultiplexed: UDX stream packets (identified by
/// header magic + stream ID) are routed to their UdxStream, while non-UDX
/// packets are delivered as Datagram values via recv_start.
#[derive(Clone)]
pub struct UdxSocket {
    inner: Arc<UdxSocketInner>,
}

impl UdxSocket {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(UdxSocketInner::new()),
        }
    }

    /// Bind the socket to a local address. Returns an error if already bound.
    pub async fn bind(&self, addr: SocketAddr) -> Result<()> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(UdxError::RuntimeGone);
        }
        let socket = tokio::net::UdpSocket::bind(addr).await?;
        self.inner
            .udp
            .set(Arc::new(socket))
            .map_err(|_| UdxError::Io(io::Error::other("socket already bound")))?;
        self.inner.ensure_writer_loop()
    }

    /// Return the local address this socket is bound to.
    pub async fn local_addr(&self) -> Result<SocketAddr> {
        let udp = self.inner.udp_arc()?;
        Ok(udp.local_addr()?)
    }

    /// Obtain the socket's sole bounded writer for internal reliable paths.
    pub(crate) fn outbound_sender(&self) -> Result<OutboundSender> {
        self.inner.outbound_sender()
    }

    /// Register a stream to receive packets addressed to local_id.
    pub(crate) fn register_stream(
        &self,
        local_id: u32,
        registration: super::stream::StreamRegistration,
    ) -> Result<()> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(UdxError::RuntimeGone);
        }
        let previous = self
            .inner
            .streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(local_id, registration);
        // A replacement must not leave its predecessor alive. In particular,
        // an old processor must not retain pending writes or later tear down
        // this newly inserted route.
        if let Some(old) = previous {
            if let Some(handle) = old.terminate() {
                handle.abort();
            }
        }
        self.inner.ensure_recv_loop()
    }

    pub(crate) fn streams_ref(&self) -> super::stream::StreamMap {
        Arc::clone(&self.inner.streams)
    }

    /// Send an unreliable datagram to addr.
    ///
    /// This method never creates a task per datagram. It fails with WouldBlock
    /// when the socket's finite raw egress queue is saturated; callers may drop,
    /// retry, or apply their own rate limit.
    pub fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<()> {
        self.inner.outbound_sender()?.try_send_raw(data, addr)
    }

    /// Begin receiving non-stream datagrams on this socket.
    ///
    /// Replacing an existing raw receiver closes the previous receiver; this
    /// preserves the historical one-consumer API while making its memory bound
    /// explicit.
    pub fn recv_start(&self) -> Result<mpsc::Receiver<Datagram>> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(UdxError::RuntimeGone);
        }
        let (tx, rx) = mpsc::channel(RAW_DATAGRAM_QUEUE_CAPACITY);
        *self
            .inner
            .fallback_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(tx);
        self.inner.ensure_recv_loop()?;
        Ok(rx)
    }

    /// Close the shared socket transport and await reader/writer termination.
    ///
    /// All clone handles become closed after this call. Dropping without calling
    /// close still aborts the owned tasks as a final safety fallback.
    pub async fn close(self) -> Result<()> {
        let tasks = self.inner.take_tasks();
        for handle in &tasks {
            handle.abort();
        }
        for handle in tasks {
            let _ = handle.await;
        }
        Ok(())
    }
}

/// Queue a reliable protocol packet through a socket-owned writer.
///
/// Reliable stream processors await capacity instead of discarding a packet.
/// When the socket is closed, the caller receives a fail-closed error and can
/// terminate its stream deterministically.
pub(crate) async fn send_reliable(
    tx: &OutboundSender,
    data: Vec<u8>,
    addr: SocketAddr,
) -> Result<()> {
    tx.send_reliable(data, addr).await
}

impl OutboundSender {
    /// Reserve raw egress capacity before copying a caller-owned slice.
    fn try_send_raw(&self, data: &[u8], addr: SocketAddr) -> Result<()> {
        if data.len() > MAX_UDP_PAYLOAD {
            return Err(UdxError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP payload exceeds 65,507 bytes",
            )));
        }

        // Both reservations are acquired before copying caller data. On a
        // full queue the byte permit is dropped immediately, and vice versa.
        let byte_permit = self.try_reserve_bytes(data.len())?;
        let channel_permit = self
            .tx
            .clone()
            .try_reserve_owned()
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => UdxError::Io(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "UDX raw egress queue is full",
                )),
                mpsc::error::TrySendError::Closed(_) => UdxError::RuntimeGone,
            })?;
        channel_permit.send(OutboundDatagram {
            data: data.to_vec(),
            addr,
            _egress_byte_permit: byte_permit,
        });
        Ok(())
    }

    /// Queue a protocol packet through the sole writer.
    ///
    /// Reliable callers wait for the same byte and slot budgets as raw egress.
    /// The strict wire limit applies before waiting, so relay input that cannot
    /// be represented as UDX is dropped and never reaches ACK/SACK processing.
    async fn send_reliable(&self, data: Vec<u8>, addr: SocketAddr) -> Result<()> {
        if data.len() > MAX_RELIABLE_WIRE_PACKET {
            return Err(UdxError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDX reliable wire packet exceeds MTU ceiling",
            )));
        }
        let byte_permit = self.reserve_bytes(data.len()).await?;
        let channel_permit = self
            .tx
            .clone()
            .reserve_owned()
            .await
            .map_err(|_| UdxError::RuntimeGone)?;
        channel_permit.send(OutboundDatagram {
            data,
            addr,
            _egress_byte_permit: byte_permit,
        });
        Ok(())
    }

    fn try_reserve_bytes(&self, len: usize) -> Result<Option<OwnedSemaphorePermit>> {
        if len == 0 {
            return Ok(None);
        }
        Arc::clone(&self.egress_bytes)
            .try_acquire_many_owned(len as u32)
            .map(Some)
            .map_err(|_| {
                UdxError::Io(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "UDX egress byte budget is exhausted",
                ))
            })
    }

    async fn reserve_bytes(&self, len: usize) -> Result<Option<OwnedSemaphorePermit>> {
        if len == 0 {
            return Ok(None);
        }
        Arc::clone(&self.egress_bytes)
            .acquire_many_owned(len as u32)
            .await
            .map(Some)
            .map_err(|_| UdxError::RuntimeGone)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use tokio::time::{sleep, timeout};

    use super::*;
    use crate::UdxRuntime;

    fn loopback() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    #[test]
    fn oversized_mapped_udx_packet_is_dropped_before_route_copy_or_ack() {
        let header = super::super::header::Header {
            type_flags: super::super::header::FLAG_DATA,
            data_offset: 0,
            remote_id: 77,
            recv_window: 0,
            seq: 1,
            ack: 1,
        };

        assert!(
            !admits_mapped_udx_packet(&header, MAX_RELIABLE_WIRE_PACKET + 1),
            "a valid UDX header above the MTU must be discarded before it can be copied, routed, or ACKed"
        );
        assert!(
            !admits_mapped_udx_packet(&header, super::super::header::HEADER_SIZE - 1),
            "a header whose payload offset lies beyond the wire packet must not enter a stream queue"
        );
    }

    #[tokio::test]
    async fn raw_queue_saturates_then_drains_and_accepts_new_datagrams() {
        let runtime = UdxRuntime::new().expect("runtime");
        let sender = runtime.create_socket().await.expect("sender");
        let receiver = runtime.create_socket().await.expect("receiver");
        sender.bind(loopback()).await.expect("bind sender");
        receiver.bind(loopback()).await.expect("bind receiver");
        let receiver_addr = receiver.local_addr().await.expect("receiver addr");
        let mut raw_rx = receiver.recv_start().expect("raw receiver");

        // The bounded receiver stops its owned reader after this finite amount.
        // Loopback datagrams already in the kernel are then consumed only as the
        // application drains, so the marker below cannot overtake them.
        for byte in 0..(RAW_DATAGRAM_QUEUE_CAPACITY * 3) {
            let _ = sender.send_to(&[byte as u8], receiver_addr);
        }
        sleep(Duration::from_millis(20)).await;

        let mut drained = 0usize;
        while drained < RAW_DATAGRAM_QUEUE_CAPACITY {
            timeout(Duration::from_secs(1), raw_rx.recv())
                .await
                .expect("queued datagram arrives")
                .expect("receiver stays open");
            drained += 1;
        }

        let marker = [0xA5, 0x5A];
        // A single bounded writer may briefly be full; retry only that explicit
        // overload condition, never spawn work per retry.
        loop {
            match sender.send_to(&marker, receiver_addr) {
                Ok(()) => break,
                Err(UdxError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => {
                    tokio::task::yield_now().await;
                }
                Err(error) => panic!("unexpected send error: {error}"),
            }
        }

        let observed_marker = timeout(Duration::from_secs(2), async {
            loop {
                if raw_rx.recv().await.expect("receiver open").data == marker {
                    break;
                }
            }
        })
        .await;
        assert!(
            observed_marker.is_ok(),
            "post-drain marker must be delivered"
        );

        sender.close().await.expect("close sender");
        receiver.close().await.expect("close receiver");
    }

    #[tokio::test]
    async fn close_aborts_the_owned_reader_and_writer_tasks() {
        let runtime = UdxRuntime::new().expect("runtime");
        let socket = runtime.create_socket().await.expect("socket");
        socket.bind(loopback()).await.expect("bind");
        let _raw_rx = socket.recv_start().expect("raw receiver");
        assert_eq!(socket.inner.active_task_count(), 2);

        socket.close().await.expect("close");
        assert_eq!(socket.inner.active_task_count(), 0);
    }

    #[tokio::test]
    async fn raw_egress_admission_is_bounded_and_recovers_after_drop() {
        let socket = UdxSocket::new();
        let (tx, mut rx) = mpsc::channel(2);
        socket
            .inner
            .outbound_tx
            .set(OutboundSender {
                tx,
                // A raw UDP payload cannot be larger than 65,507 bytes, so
                // use that finite test budget rather than an unreachable 1 MiB
                // single packet.
                egress_bytes: Arc::new(Semaphore::new(MAX_UDP_PAYLOAD)),
            })
            .expect("install deterministic writer");
        let addr = loopback();

        socket
            .send_to(&vec![0xAA; MAX_UDP_PAYLOAD], addr)
            .expect("first packet reserves the whole byte budget");
        let byte_error = socket
            .send_to(&[0xBB], addr)
            .expect_err("second packet exceeds byte budget before copying");
        assert!(matches!(
            byte_error,
            UdxError::Io(ref error) if error.kind() == io::ErrorKind::WouldBlock
        ));

        let first = rx.recv().await.expect("queued packet");
        drop(first); // releases its owned byte reservation exactly once
        socket
            .send_to(&[0xCC], addr)
            .expect("byte reservation recovers when writer drops packet");

        // Fill the channel independently to prove slot reservation comes before
        // copying a new caller buffer and is returned when the receiver drains.
        socket
            .send_to(&[0xDD], addr)
            .expect("second writer slot is still available");
        let queue_error = socket
            .send_to(&[0xEE], addr)
            .expect_err("bounded writer channel must reject saturation");
        assert!(matches!(
            queue_error,
            UdxError::Io(ref error) if error.kind() == io::ErrorKind::WouldBlock
        ));
        drop(rx.recv().await.expect("post-recovery packet"));
        socket
            .send_to(&[0xFF], addr)
            .expect("writer slot recovers after drain");
    }

    #[tokio::test]
    async fn reliable_egress_shares_byte_budget_with_raw_egress() {
        let (tx, mut rx) = mpsc::channel(2);
        let sender = OutboundSender {
            tx,
            egress_bytes: Arc::new(Semaphore::new(MAX_RELIABLE_WIRE_PACKET)),
        };
        let addr = loopback();

        send_reliable(&sender, vec![0xA5; MAX_RELIABLE_WIRE_PACKET], addr)
            .await
            .expect("reliable packet reserves the common budget");
        let error = sender
            .try_send_raw(&[0x5A], addr)
            .expect_err("raw egress cannot bypass reliable byte reservation");
        assert!(matches!(
            error,
            UdxError::Io(ref error) if error.kind() == io::ErrorKind::WouldBlock
        ));

        drop(rx.recv().await.expect("reliable packet is queued"));
        sender
            .try_send_raw(&[0x5A], addr)
            .expect("byte reservation returns when reliable writer item drops");
    }

    #[tokio::test]
    async fn reliable_egress_rejects_oversized_relay_packet_before_admission() {
        let (tx, mut rx) = mpsc::channel(1);
        let sender = OutboundSender {
            tx,
            egress_bytes: Arc::new(Semaphore::new(EGRESS_BYTE_BUDGET)),
        };
        let error = send_reliable(
            &sender,
            vec![0xFF; MAX_RELIABLE_WIRE_PACKET + 1],
            loopback(),
        )
        .await
        .expect_err("oversized reliable packet must not reserve a writer slot");
        assert!(matches!(
            error,
            UdxError::Io(ref error) if error.kind() == io::ErrorKind::InvalidInput
        ));
        assert!(rx.try_recv().is_err(), "rejected packet was never queued");
    }

    #[test]
    fn raw_egress_rejects_oversize_payload_before_socket_setup() {
        let socket = UdxSocket::new();
        let error = socket
            .send_to(&vec![0u8; MAX_UDP_PAYLOAD + 1], loopback())
            .expect_err("UDP API payload cap is fail-closed");
        assert!(matches!(
            error,
            UdxError::Io(ref error) if error.kind() == io::ErrorKind::InvalidInput
        ));
    }
}
