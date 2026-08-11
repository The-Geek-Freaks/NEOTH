use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::{mpsc, oneshot};

use super::congestion::CaState;
use super::header::{
    FLAG_DATA, FLAG_DESTROY, FLAG_END, FLAG_HEARTBEAT, FLAG_SACK, HEADER_SIZE, Header, SackRange,
    decode_sack, encode_sack,
};
use super::socket::{OutboundSender, STREAM_PACKET_QUEUE_CAPACITY, send_reliable};
use crate::error::{Result, UdxError};

// ── Constants ────────────────────────────────────────────────────────────────

/// Default receive window size (4 MB, matches C libudx).
pub(crate) const DEFAULT_RWND: u32 = 4_194_304;

/// Maximum payload per UDP packet (1200 - 20 byte header).
pub(crate) const MAX_PAYLOAD: usize = 1200 - HEADER_SIZE;

/// Starting MTU (bytes) — matches C libudx `UDX_MTU_BASE`.
pub(crate) const MTU_BASE: usize = 1200;

/// Maximum MTU (bytes) — matches C libudx `UDX_MTU_MAX`.
pub(crate) const MTU_MAX: usize = 1500;

/// Probe size increment (bytes).
pub(crate) const MTU_STEP: usize = 32;

/// Failed probes before settling on current MTU.
pub(crate) const MTU_MAX_PROBES: u32 = 3;

/// Initial retransmission timeout (ms) — matches C libudx.
const INITIAL_RTO_MS: u32 = 1_000;

/// Maximum retransmission timeout (ms) — matches C libudx `UDX_RTO_MAX_MS`.
const MAX_RTO_MS: u32 = 30_000;

/// Maximum consecutive RTO timeouts before stream failure.
const MAX_RTO_TIMEOUTS: u32 = 6;

/// Heartbeat interval when stream is idle (ms).
const HEARTBEAT_INTERVAL_MS: u64 = 1_000;

/// Maximum number of SACK ranges to include in an ACK packet.
const MAX_SACK_RANGES: usize = 50;

/// Maximum accepted RTT sample (ms) — prevents outlier corruption.
const MAX_RTT_MS: u32 = 30_000;

/// Far-future duration used to effectively disable a timer.
const FAR_FUTURE: std::time::Duration = std::time::Duration::from_secs(86_400);

/// Per-stream application events retained before the consumer reads them.
///
/// Payloads have already passed the UDX ingress queue. We only acknowledge a
/// DATA packet after every resulting event has entered this bounded queue.
const STREAM_READ_QUEUE_CAPACITY: usize = 128;

/// Maximum wire packets staged for transmission by one stream.
///
/// The queue is an explicit allocation boundary: a stream may retain at most
/// this many MTU-bounded packets before its processor consumes them.
pub(crate) const STREAM_SEND_QUEUE_CAPACITY: usize = 256;

/// Maximum out-of-order payload retained for one stream. This makes the
/// advertised four-megabyte receive window a real allocation bound.
const MAX_RECV_BUFFER_BYTES: usize = DEFAULT_RWND as usize;

/// Maximum out-of-order packets retained for one stream.
///
/// The byte limit alone is not sufficient: empty DATA/END packets have no
/// payload cost but still allocate a map entry. Keep this in line with the
/// other per-stream ingress/staging boundaries and use the same window for
/// forward sequence admission.
const MAX_RECV_BUFFER_PACKETS: usize = STREAM_SEND_QUEUE_CAPACITY;

// ── MTU Probing State ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MtuState {
    Base,
    Search,
    SearchComplete,
}

// ── Sequence number comparison ───────────────────────────────────────────────

/// Returns true if sequence number `a` is strictly after `b` (handles u32 wraparound).
#[inline]
fn seq_after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b)) as i32 > 0
}

// ── Packet types ─────────────────────────────────────────────────────────────

pub(crate) struct IncomingPacket {
    pub data: Vec<u8>,
    #[allow(dead_code)]
    pub addr: SocketAddr,
}

pub(crate) enum StreamEvent {
    Data(Vec<u8>),
    End,
}

// ── Reliability types ────────────────────────────────────────────────────────

/// A sent packet stored in the outgoing buffer for potential retransmission.
struct SentPacket {
    /// Full wire-format packet bytes (header + payload).
    packet: Vec<u8>,
    /// When this packet was (last) sent — for RTT measurement on first send.
    time_sent: Instant,
    /// Number of times this packet has been retransmitted.
    retransmit_count: u32,
    /// Whether this packet has been selectively acknowledged via SACK.
    sacked: bool,
    /// Whether this packet was sent as an MTU probe (oversized via data_offset padding).
    is_mtu_probe: bool,
    /// Whether this packet has been detected as lost (SACK gap analysis).
    lost: bool,
    rate_info: Option<super::congestion::rate::PacketRateInfo>,
}

/// A received out-of-order packet buffered until gaps are filled.
struct RecvdPacket {
    payload: Vec<u8>,
    flags: u8,
}

struct QueuedPacket {
    packet: Vec<u8>,
    seq: u32,
    remote_addr: SocketAddr,
}

/// Tracks a pending write awaiting remote acknowledgement.
pub(crate) struct PendingWrite {
    pub(crate) ack_threshold: u32,
    pub(crate) tx: Option<oneshot::Sender<Result<()>>>,
}

/// Notification from the send path to the processor task.
pub(crate) enum StreamNotify {
    DataQueued,
    Shutdown,
}

type WriteSenders = Vec<Option<oneshot::Sender<Result<()>>>>;
type AckedRateInfo = Vec<(u32, super::congestion::rate::PacketRateInfo)>;
pub(crate) type StreamMap = Arc<Mutex<std::collections::HashMap<u32, StreamRegistration>>>;

/// Socket-owned registration for one reliability processor.
///
/// Keeping shutdown state next to the ingress route means closing the shared
/// socket closes every mapped stream; no processor or pending acknowledgement
/// can outlive that transport.
pub(crate) struct StreamRegistration {
    ingress: mpsc::Sender<IncomingPacket>,
    inner: Arc<Mutex<StreamInner>>,
    processor: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl StreamRegistration {
    pub(crate) fn new(
        ingress: mpsc::Sender<IncomingPacket>,
        inner: Arc<Mutex<StreamInner>>,
        processor: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    ) -> Self {
        Self {
            ingress,
            inner,
            processor,
        }
    }

    pub(crate) fn ingress(&self) -> mpsc::Sender<IncomingPacket> {
        self.ingress.clone()
    }

    /// Return whether a UDP source is the peer pinned when this stream was
    /// connected. Stream IDs are predictable routing labels, not credentials;
    /// packet admission must be source-bound before the socket queues a packet.
    ///
    /// UDX currently has no authenticated address-migration handshake. Any
    /// source change therefore remains fail-closed instead of silently moving a
    /// live route to an attacker-selected address.
    pub(crate) fn accepts_source(&self, source: SocketAddr) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .accepts_packet_from(source)
    }

    pub(crate) fn matches_inner(&self, inner: &Arc<Mutex<StreamInner>>) -> bool {
        Arc::ptr_eq(&self.inner, inner)
    }

    pub(crate) fn terminate(&self) -> Option<tokio::task::JoinHandle<()>> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.terminate();
        if let Some(tx) = inner.close_tx.take() {
            let _ = tx.send(());
        }
        drop(inner);
        self.processor
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }
}

/// Remove a route only when it still belongs to this exact stream instance.
///
/// Local IDs are reusable. A stale processor or dropped old handle must never
/// erase a replacement stream that has already claimed the same ID.
pub(crate) fn unregister_stream_if_current(
    streams: &StreamMap,
    local_id: u32,
    inner: &Arc<Mutex<StreamInner>>,
) {
    let mut map = streams.lock().unwrap_or_else(|e| e.into_inner());
    if map
        .get(&local_id)
        .is_some_and(|registration| registration.matches_inner(inner))
    {
        map.remove(&local_id);
    }
}

// ── StreamInner ──────────────────────────────────────────────────────────────

pub(crate) struct StreamInner {
    // ── Connection identity ──
    pub(crate) remote_id: u32,
    pub(crate) remote_addr: Option<SocketAddr>,
    pub(crate) connected: bool,
    /// True once `prepare_end()` has been called (FIN queued).
    ended: bool,

    // ── Send state ──
    pub(crate) next_seq: u32,
    pub(crate) pending_writes: Vec<PendingWrite>,
    /// Sent packets awaiting ACK, keyed by sequence number.
    outgoing: BTreeMap<u32, SentPacket>,

    // ── Receive state ──
    pub(crate) next_remote_seq: u32,
    /// Highest cumulative ACK received from remote.
    remote_acked: u32,
    /// Out-of-order receive buffer, keyed by sequence number.
    recv_buf: BTreeMap<u32, RecvdPacket>,
    /// Exact payload bytes currently held in the out-of-order receive buffer.
    recv_buf_bytes: usize,

    // ── RTT estimation (Jacobson/Karels, matching C libudx constants) ──
    srtt: u32,
    rttvar: u32,
    rto: u32,
    rto_timeouts: u32,

    // ── Flow control ──
    /// Remote's last advertised receive window.
    send_rwnd: u32,

    // ── MTU probing state ──
    pub(crate) mtu_state: MtuState,
    pub(crate) mtu: usize,
    pub(crate) mtu_probe_size: usize,
    pub(crate) mtu_probe_count: u32,
    pub(crate) mtu_probe_wanted: bool,
    pub(crate) mtu_max: usize,

    // ── IO ──
    pub(crate) outbound_tx: Option<OutboundSender>,
    pub(crate) read_tx: Option<mpsc::Sender<StreamEvent>>,
    close_tx: Option<oneshot::Sender<()>>,
    pub(crate) notify_tx: Option<mpsc::Sender<StreamNotify>>,

    // ── Congestion control (BBR) ──
    pub(crate) congestion: super::congestion::CongestionController,
    send_queue: VecDeque<QueuedPacket>,
    reserved_send_slots: usize,

    // ── Relay ──
    relay_target: Option<Arc<Mutex<StreamInner>>>,
}

impl StreamInner {
    /// See [`StreamRegistration::accepts_source`]. This duplicate processor-side
    /// check keeps a packet injected after socket routing from mutating stream
    /// state before an explicit authenticated migration mechanism exists.
    fn accepts_packet_from(&self, source: SocketAddr) -> bool {
        self.connected && self.remote_addr == Some(source)
    }

    // ── Stream termination ──────────────────────────────────────────────────

    /// Drain all pending writes with `StreamClosed`, mark the stream
    /// disconnected, and drop `notify_tx` so future sends fail fast.
    /// Idempotent — safe to call more than once.
    pub(super) fn terminate(&mut self) {
        self.connected = false;
        self.notify_tx = None;
        self.read_tx = None;
        self.send_queue.clear();
        self.reserved_send_slots = 0;
        self.recv_buf.clear();
        self.recv_buf_bytes = 0;
        self.outgoing.clear();

        for mut pw in self.pending_writes.drain(..) {
            if let Some(tx) = pw.tx.take() {
                let _ = tx.send(Err(UdxError::StreamClosed));
            }
        }
    }

    // ── MTU ──────────────────────────────────────────────────────────────────

    pub(crate) fn max_payload(&self) -> usize {
        self.mtu - HEADER_SIZE
    }

    /// Inflate a DATA packet to `mtu_probe_size` by inserting zero padding after the header.
    /// Sets `data_offset` so the receiver skips the padding via `payload_offset()`.
    /// Returns `true` if the packet was successfully probeified.
    fn mtu_probeify_packet(&mut self, packet: &mut Vec<u8>) -> bool {
        if packet.len() < HEADER_SIZE {
            return false;
        }
        let target_size = self.mtu_probe_size;
        if target_size <= packet.len() {
            return false;
        }

        let padding = target_size - packet.len();
        // data_offset is u8 — can only pad up to 255 bytes.
        // This naturally limits probing to nearly-full packets (matching C libudx).
        if padding > 255 {
            return false;
        }
        // Insert padding between header and payload: shift payload right
        let payload = packet[HEADER_SIZE..].to_vec();
        packet.truncate(HEADER_SIZE);
        packet.extend(std::iter::repeat_n(0u8, padding));
        packet.extend_from_slice(&payload);

        // Set data_offset in header byte [3]
        packet[3] = padding as u8;

        self.mtu_probe_wanted = false;
        tracing::trace!(probe_size = target_size, padding, "mtu: probeify");
        true
    }

    fn on_mtu_probe_acked(&mut self) {
        let old_mtu = self.mtu;
        self.mtu = self.mtu_probe_size;
        self.mtu_probe_count = 0;
        self.mtu_probe_size += MTU_STEP;

        if self.mtu_probe_size > self.mtu_max {
            self.mtu_probe_size = self.mtu_max;
        }

        if self.mtu >= self.mtu_max {
            self.mtu_state = MtuState::SearchComplete;
        } else {
            self.mtu_probe_wanted = true;
        }

        self.congestion.on_mtu_change(old_mtu, self.mtu);
        tracing::debug!(old_mtu, new_mtu = self.mtu, state = ?self.mtu_state, "mtu: probe acked");
    }

    // ── Write preparation ────────────────────────────────────────────────────

    pub(crate) fn prepare_write(&mut self, data_len: usize) -> Result<WritePrep> {
        if !self.connected {
            return Err(UdxError::Io(std::io::Error::other("stream not connected")));
        }
        if self.ended {
            return Err(UdxError::Io(std::io::Error::other(
                "stream already shut down",
            )));
        }
        let writer = self.outbound_tx.clone().ok_or(UdxError::StreamClosed)?;
        let remote_addr = self.remote_addr.ok_or(UdxError::StreamClosed)?;
        let remote_id = self.remote_id;

        let max_payload = self.max_payload();
        let chunk_count = if data_len == 0 {
            1
        } else {
            data_len.div_ceil(max_payload)
        };
        if chunk_count > STREAM_SEND_QUEUE_CAPACITY
            || self
                .send_queue
                .len()
                .saturating_add(self.reserved_send_slots)
                + chunk_count
                > STREAM_SEND_QUEUE_CAPACITY
        {
            return Err(UdxError::Io(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "UDX stream send queue is full",
            )));
        }
        let first_seq = self.next_seq;
        let ack_threshold = first_seq + chunk_count as u32;
        self.next_seq = ack_threshold;
        self.reserved_send_slots += chunk_count;
        let current_ack = self.next_remote_seq;

        let (ack_tx, ack_rx) = oneshot::channel();
        self.pending_writes.push(PendingWrite {
            ack_threshold,
            tx: Some(ack_tx),
        });

        Ok(WritePrep {
            writer,
            remote_addr,
            remote_id,
            first_seq,
            current_ack,
            ack_rx,
            reserved_packets: chunk_count,
        })
    }

    pub(crate) fn prepare_end(&mut self) -> Result<WritePrep> {
        if !self.connected {
            return Err(UdxError::Io(std::io::Error::other("stream not connected")));
        }
        if self.ended {
            return Err(UdxError::Io(std::io::Error::other(
                "stream already shut down",
            )));
        }
        let writer = self.outbound_tx.clone().ok_or(UdxError::StreamClosed)?;
        let remote_addr = self.remote_addr.ok_or(UdxError::StreamClosed)?;
        let remote_id = self.remote_id;

        if self
            .send_queue
            .len()
            .saturating_add(self.reserved_send_slots)
            >= STREAM_SEND_QUEUE_CAPACITY
        {
            return Err(UdxError::Io(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "UDX stream send queue is full",
            )));
        }
        self.ended = true;
        let seq = self.next_seq;
        self.next_seq = seq + 1;
        self.reserved_send_slots += 1;
        let current_ack = self.next_remote_seq;

        let (ack_tx, ack_rx) = oneshot::channel();
        self.pending_writes.push(PendingWrite {
            ack_threshold: seq + 1,
            tx: Some(ack_tx),
        });

        Ok(WritePrep {
            writer,
            remote_addr,
            remote_id,
            first_seq: seq,
            current_ack,
            ack_rx,
            reserved_packets: 1,
        })
    }

    // ── Outgoing packet registration ─────────────────────────────────────────

    /// Store a sent packet in the outgoing buffer for potential retransmission.
    pub(crate) fn register_sent(&mut self, seq: u32, packet: Vec<u8>, is_mtu_probe: bool) {
        let now = Instant::now();
        let inflight = self.inflight();
        let rate_info = self.congestion.on_packet_sent(seq, inflight, now);
        tracing::trace!(
            seq,
            is_mtu_probe,
            "register_sent: packet placed in outgoing"
        );
        self.outgoing.insert(
            seq,
            SentPacket {
                packet,
                time_sent: now,
                retransmit_count: 0,
                sacked: false,
                is_mtu_probe,
                lost: false,
                rate_info: Some(rate_info),
            },
        );
    }

    pub(crate) fn inflight(&self) -> u32 {
        self.outgoing
            .values()
            .filter(|p| !p.sacked && !p.lost)
            .count() as u32
    }

    pub(crate) fn queue_for_send(
        &mut self,
        packets: Vec<(u32, Vec<u8>)>,
        remote_addr: SocketAddr,
        reserved_packets: usize,
    ) -> Result<()> {
        let count = packets.len();
        if count != reserved_packets
            || reserved_packets > self.reserved_send_slots
            || self.send_queue.len().saturating_add(count) > STREAM_SEND_QUEUE_CAPACITY
        {
            return Err(UdxError::Io(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "UDX stream send queue is full",
            )));
        }
        self.reserved_send_slots -= reserved_packets;
        for (seq, packet) in packets {
            self.send_queue.push_back(QueuedPacket {
                packet,
                seq,
                remote_addr,
            });
        }
        tracing::trace!(
            count,
            queue_len = self.send_queue.len(),
            "queue_for_send: packets staged"
        );
        if let Some(ref tx) = self.notify_tx {
            // DataQueued is only a wake-up; a coalesced full notification is
            // harmless because the processor observes send_queue itself.
            let _ = tx.try_send(StreamNotify::DataQueued);
        }
        Ok(())
    }

    pub(crate) fn send_idle(&self) -> bool {
        self.outgoing.is_empty() && self.send_queue.is_empty()
    }

    // ── RTT estimation (Jacobson/Karels) ─────────────────────────────────────

    /// Update the RTT estimator with a new sample.
    ///
    /// Uses standard constants matching C libudx:
    ///   α = 1/8 (SRTT smoothing)
    ///   β = 1/4 (RTTVAR smoothing)
    ///   K = 4   (RTO multiplier for RTTVAR)
    ///   G = 1000ms (minimum RTO granularity)
    fn update_rtt(&mut self, rtt_ms: u32) {
        let rtt = rtt_ms.min(MAX_RTT_MS);
        if self.srtt == 0 {
            // First sample
            self.srtt = rtt;
            self.rttvar = rtt / 2;
        } else {
            let delta = self.srtt.abs_diff(rtt);
            // RTTVAR <- (3/4) * RTTVAR + (1/4) * |SRTT - R|
            self.rttvar = (3 * self.rttvar + delta) / 4;
            // SRTT <- (7/8) * SRTT + (1/8) * R
            self.srtt = (7 * self.srtt + rtt) / 8;
        }
        // RTO <- SRTT + max(G, K * RTTVAR) where K=4, G=1000ms
        self.rto = (self.srtt + 4 * self.rttvar).clamp(1_000, MAX_RTO_MS);
    }

    // ── ACK processing ───────────────────────────────────────────────────────

    /// Process a cumulative ACK from the remote peer.
    ///
    /// Removes ACKed packets from the outgoing buffer, measures RTT from the
    /// earliest non-retransmitted packet, resets the RTO timeout counter, and
    /// returns completed write senders plus rate info for congestion control.
    ///
    /// Congestion control is NOT called here — the caller must combine this
    /// rate info with SACK rate info and loss count, then call `congestion.on_ack`.
    fn on_cumulative_ack(&mut self, ack: u32) -> (WriteSenders, AckedRateInfo) {
        if !seq_after(ack, self.remote_acked) {
            return (Vec::new(), Vec::new());
        }

        self.remote_acked = ack;

        // Efficient BTreeMap split: remove all entries with key < ack
        let to_keep = self.outgoing.split_off(&ack);
        let removed = std::mem::replace(&mut self.outgoing, to_keep);

        let mut rtt_measured = false;
        let mut acked_rate_info: Vec<(u32, super::congestion::rate::PacketRateInfo)> = Vec::new();
        for (&seq, pkt) in &removed {
            if !rtt_measured && pkt.retransmit_count == 0 {
                let elapsed = pkt.time_sent.elapsed().as_millis() as u32;
                self.update_rtt(elapsed);
                rtt_measured = true;
            }
            if let Some(ref info) = pkt.rate_info {
                acked_rate_info.push((seq, *info));
            }
            if pkt.is_mtu_probe && self.mtu_state == MtuState::Search {
                self.on_mtu_probe_acked();
            }
        }

        // Successful ACK resets timeout counter
        self.rto_timeouts = 0;

        // Complete pending writes whose ack_threshold <= ack
        let mut completed = Vec::new();
        self.pending_writes.retain_mut(|pw| {
            if pw.ack_threshold <= ack {
                completed.push(pw.tx.take());
                false
            } else {
                true
            }
        });
        (completed, acked_rate_info)
    }

    // ── SACK processing ──────────────────────────────────────────────────────

    /// Process SACK ranges from the remote peer. Marks selectively acknowledged
    /// packets and returns rate info from newly sacked packets for congestion control.
    fn on_sack(
        &mut self,
        ranges: &[SackRange],
    ) -> Vec<(u32, super::congestion::rate::PacketRateInfo)> {
        let mut sack_rate_info = Vec::new();
        let Some((&first_sent, _)) = self.outgoing.first_key_value() else {
            return sack_rate_info;
        };
        let Some((&last_sent, _)) = self.outgoing.last_key_value() else {
            return sack_rate_info;
        };

        for range in ranges {
            // Ranges are half-open and deliberately non-wrapping. A reversed
            // range, a wrap-around encoding, or one wholly outside the finite
            // sent-key window is irrelevant/malformed and must not trigger a
            // potentially 2^32-long integer walk.
            if range.start >= range.end || range.end <= first_sent || range.start > last_sent {
                continue;
            }

            let start = range.start.max(first_sent);
            let end = range.end.min(last_sent.saturating_add(1));
            if start >= end {
                continue;
            }

            // Iterate only extant outgoing entries. Work is bounded by the
            // stream's finite outgoing map, independent of an attacker range.
            for (&seq, pkt) in self.outgoing.range_mut(start..end) {
                if !pkt.sacked {
                    pkt.sacked = true;
                    if let Some(ref info) = pkt.rate_info {
                        sack_rate_info.push((seq, *info));
                    }
                }
            }
        }
        sack_rate_info
    }

    // ── Loss detection ───────────────────────────────────────────────────────

    /// Detect lost packets via SACK gap analysis: any non-sacked, non-lost
    /// packet with a sequence number below the highest SACKed sequence is
    /// declared lost. Returns the number of newly detected losses.
    ///
    /// This is a simplified approximation of the C libudx RACK-based loss
    /// detection. It captures the essential behavior (packets below the
    /// highest SACK are considered lost) without the full timing state.
    fn detect_losses(&mut self) -> u32 {
        let highest_sacked = self
            .outgoing
            .iter()
            .filter(|(_, pkt)| pkt.sacked)
            .map(|(&seq, _)| seq)
            .max();

        let Some(highest_sacked) = highest_sacked else {
            return 0;
        };

        let lost_seqs: Vec<u32> = self
            .outgoing
            .iter()
            .filter(|&(&seq, pkt)| !pkt.sacked && !pkt.lost && seq_after(highest_sacked, seq))
            .map(|(&seq, _)| seq)
            .collect();

        for &seq in &lost_seqs {
            if let Some(pkt) = self.outgoing.get_mut(&seq) {
                pkt.lost = true;
            }
        }

        let was_open = self.congestion.ca_state == CaState::Open;

        for &seq in &lost_seqs {
            self.congestion.on_packet_lost(seq);
        }

        // Record the recovery boundary: when all packets up to high_seq
        // are ACK'd, we can exit Recovery → Open.
        if was_open && self.congestion.ca_state == CaState::Recovery {
            if let Some(&max_seq) = self.outgoing.keys().last() {
                self.congestion.high_seq = max_seq;
            }
        }

        lost_seqs.len() as u32
    }

    // ── Receive buffering ────────────────────────────────────────────────────

    /// Handle an incoming DATA or END packet.
    ///
    /// In-order packets are delivered immediately. Out-of-order packets are
    /// buffered. When gaps are filled, consecutive buffered packets are drained
    /// and delivered in order. Returns events to deliver to the application.
    ///
    /// A single packet may carry both FLAG_DATA and FLAG_END (C libudx combines
    /// the last data chunk with the end marker). In that case two events are
    /// produced: Data followed by End.
    /// Returns `None` when an out-of-order packet is rejected. The caller must
    /// not ACK or SACK that packet so its sender retains it for retransmission.
    fn receive_data(&mut self, seq: u32, payload: Vec<u8>, flags: u8) -> Option<Vec<StreamEvent>> {
        let mut events = Vec::new();

        // Duplicate or already-received packet — ignore
        if seq < self.next_remote_seq {
            return Some(events);
        }

        if seq == self.next_remote_seq {
            // In-order: deliver directly
            push_events(&mut events, payload, flags);
            self.next_remote_seq = seq + 1;

            // Drain consecutive buffered packets
            while let Some(recvd) = self.recv_buf.remove(&self.next_remote_seq) {
                self.recv_buf_bytes = self.recv_buf_bytes.saturating_sub(recvd.payload.len());
                push_events(&mut events, recvd.payload, recvd.flags);
                self.next_remote_seq += 1;
            }
        } else {
            // Out-of-order: retain only the concrete receive window. Refusing
            // excess data also means it is not SACKed, so the remote peer keeps
            // it for normal retransmission instead of us ACKing-and-losing it.
            if self.recv_buf.contains_key(&seq) {
                return Some(events);
            }

            let forward_distance = seq.wrapping_sub(self.next_remote_seq);
            if forward_distance > MAX_RECV_BUFFER_PACKETS as u32
                || self.recv_buf.len() >= MAX_RECV_BUFFER_PACKETS
                || self.recv_buf_bytes.saturating_add(payload.len()) > MAX_RECV_BUFFER_BYTES
            {
                return None;
            }

            self.recv_buf_bytes += payload.len();
            self.recv_buf.insert(seq, RecvdPacket { payload, flags });
        }

        Some(events)
    }

    // ── SACK generation ──────────────────────────────────────────────────────

    /// Compute SACK ranges from the out-of-order receive buffer.
    /// Returns contiguous ranges of received sequence numbers that are
    /// beyond the cumulative ACK point.
    fn sack_ranges(&self) -> Vec<SackRange> {
        if self.recv_buf.is_empty() {
            return Vec::new();
        }

        let mut ranges = Vec::new();
        let mut iter = self.recv_buf.keys();

        if let Some(&first) = iter.next() {
            let mut start = first;
            let mut end = first + 1;

            for &seq in iter {
                if seq == end {
                    // Extend current range
                    end = seq + 1;
                } else {
                    // Gap found: close current range, start new one
                    ranges.push(SackRange { start, end });
                    if ranges.len() >= MAX_SACK_RANGES {
                        return ranges;
                    }
                    start = seq;
                    end = seq + 1;
                }
            }
            ranges.push(SackRange { start, end });
        }
        ranges
    }

    // ── Retransmission ───────────────────────────────────────────────────────

    /// Collect packets that need retransmission (not SACKed, still in outgoing).
    /// Updates retransmit_count and time_sent for each retransmitted packet.
    /// For MTU probes: strips padding, marks failure, and may transition to SearchComplete.
    fn packets_to_retransmit(&mut self) -> Vec<Vec<u8>> {
        let now = Instant::now();
        let mut retransmits = Vec::new();
        let mut probe_failed = false;
        for pkt in self.outgoing.values_mut() {
            if !pkt.sacked {
                if pkt.is_mtu_probe {
                    strip_probe_padding(&mut pkt.packet);
                    pkt.is_mtu_probe = false;
                    probe_failed = true;
                }
                retransmits.push(pkt.packet.clone());
                pkt.retransmit_count += 1;
                pkt.time_sent = now;
            }
        }
        if probe_failed {
            self.mtu_probe_count += 1;
            tracing::debug!(
                failures = self.mtu_probe_count,
                max = MTU_MAX_PROBES,
                "mtu: probe failed (retransmit)"
            );
            if self.mtu_probe_count >= MTU_MAX_PROBES {
                self.mtu_state = MtuState::SearchComplete;
                self.mtu_probe_wanted = false;
            } else {
                self.mtu_probe_wanted = true;
            }
        }
        retransmits
    }

    /// Fast retransmit: collect only packets marked as lost (SACK-detected).
    fn fast_retransmit(&mut self) -> Vec<Vec<u8>> {
        let now = Instant::now();
        let mut retransmits = Vec::new();
        let mut probe_failed = false;
        for pkt in self.outgoing.values_mut() {
            if pkt.lost && !pkt.sacked {
                if pkt.is_mtu_probe {
                    strip_probe_padding(&mut pkt.packet);
                    pkt.is_mtu_probe = false;
                    probe_failed = true;
                }
                retransmits.push(pkt.packet.clone());
                pkt.retransmit_count += 1;
                pkt.time_sent = now;
                pkt.lost = false;
            }
        }
        if probe_failed {
            self.mtu_probe_count += 1;
            tracing::debug!(
                failures = self.mtu_probe_count,
                max = MTU_MAX_PROBES,
                "mtu: probe failed (fast retransmit)"
            );
            if self.mtu_probe_count >= MTU_MAX_PROBES {
                self.mtu_state = MtuState::SearchComplete;
                self.mtu_probe_wanted = false;
            } else {
                self.mtu_probe_wanted = true;
            }
        }
        retransmits
    }
}

/// Strip MTU probe padding from a packet: remove zero bytes between header and payload,
/// reset data_offset to 0.
fn strip_probe_padding(packet: &mut Vec<u8>) {
    if packet.len() < HEADER_SIZE {
        return;
    }
    let data_offset = packet[3] as usize;
    if data_offset == 0 {
        return;
    }
    let payload_start = HEADER_SIZE + data_offset;
    if payload_start <= packet.len() {
        let payload = packet[payload_start..].to_vec();
        packet.truncate(HEADER_SIZE);
        packet.extend_from_slice(&payload);
    }
    packet[3] = 0;
}

/// Push stream events for a received packet. When both FLAG_DATA and FLAG_END
/// are set (combined packet), pushes Data then End.
fn push_events(events: &mut Vec<StreamEvent>, payload: Vec<u8>, flags: u8) {
    let has_data = flags & FLAG_DATA != 0;
    let has_end = flags & FLAG_END != 0;

    if has_data && !payload.is_empty() {
        events.push(StreamEvent::Data(payload));
    } else if has_data {
        // Empty data packet (e.g., keepalive DATA) — skip
    } else if !has_end {
        // Neither DATA nor END — shouldn't happen, but guard
        return;
    }

    if has_end {
        events.push(StreamEvent::End);
    }
}

/// Extract a DATA/END payload only after validating the header-derived offset.
/// Invalid offsets are malformed wire data, not empty payloads.
fn payload_from_packet(packet: &[u8], payload_start: usize) -> Option<Vec<u8>> {
    packet.get(payload_start..).map(<[u8]>::to_vec)
}

// ── WritePrep ────────────────────────────────────────────────────────────────

pub(crate) struct WritePrep {
    pub writer: OutboundSender,
    pub remote_addr: SocketAddr,
    pub remote_id: u32,
    pub first_seq: u32,
    pub current_ack: u32,
    pub ack_rx: oneshot::Receiver<Result<()>>,
    pub reserved_packets: usize,
}

// ── UdxStream ────────────────────────────────────────────────────────────────

/// A reliable, ordered, bidirectional byte stream over UDP.
///
/// Implements the UDX protocol with BBR congestion control, SACK-based
/// recovery, and RTT-driven retransmission. Multiple streams can share
/// a single [`super::socket::UdxSocket`] via stream ID multiplexing.
pub struct UdxStream {
    local_id: u32,
    pub(crate) inner: Arc<Mutex<StreamInner>>,
    processor: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    incoming_tx: Option<mpsc::Sender<IncomingPacket>>,
    incoming_rx: Mutex<Option<mpsc::Receiver<IncomingPacket>>>,
    pub(crate) read_rx: Option<mpsc::Receiver<StreamEvent>>,
    #[allow(dead_code)]
    close_rx: Option<oneshot::Receiver<()>>,
    socket_streams: Mutex<Option<StreamMap>>,
    owns_processor: bool,
}

impl UdxStream {
    pub(crate) fn new(local_id: u32) -> Self {
        let (read_tx, read_rx) = mpsc::channel(STREAM_READ_QUEUE_CAPACITY);
        let (close_tx, close_rx) = oneshot::channel();
        let (incoming_tx, incoming_rx) = mpsc::channel(STREAM_PACKET_QUEUE_CAPACITY);

        let inner = StreamInner {
            remote_id: 0,
            remote_addr: None,
            connected: false,
            ended: false,
            next_seq: 0,
            pending_writes: Vec::new(),
            outgoing: BTreeMap::new(),
            next_remote_seq: 0,
            remote_acked: 0,
            recv_buf: BTreeMap::new(),
            recv_buf_bytes: 0,
            srtt: 0,
            rttvar: 0,
            rto: INITIAL_RTO_MS,
            rto_timeouts: 0,
            send_rwnd: DEFAULT_RWND,
            mtu_state: MtuState::Base,
            mtu: MTU_BASE,
            mtu_probe_size: MTU_BASE + MTU_STEP,
            mtu_probe_count: 0,
            mtu_probe_wanted: false,
            mtu_max: MTU_MAX,
            outbound_tx: None,
            read_tx: Some(read_tx),
            close_tx: Some(close_tx),
            notify_tx: None,
            congestion: super::congestion::CongestionController::new(
                crate::native::stream::MAX_PAYLOAD as u32,
                INITIAL_RTO_MS,
            ),
            send_queue: VecDeque::new(),
            reserved_send_slots: 0,
            relay_target: None,
        };

        Self {
            local_id,
            inner: Arc::new(Mutex::new(inner)),
            processor: Arc::new(Mutex::new(None)),
            incoming_tx: Some(incoming_tx),
            incoming_rx: Mutex::new(Some(incoming_rx)),
            read_rx: Some(read_rx),
            close_rx: Some(close_rx),
            socket_streams: Mutex::new(None),
            owns_processor: true,
        }
    }

    /// Consume this stream and return a tokio-compatible async I/O adapter.
    pub fn into_async_stream(mut self) -> super::async_stream::UdxAsyncStream {
        // The async adapter becomes the sole handle-level owner. The shared
        // registration still holds the same processor cell for socket close.
        self.owns_processor = false;
        let socket_streams = self
            .socket_streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        let Some(read_rx) = self.read_rx.take() else {
            return super::async_stream::UdxAsyncStream::new(
                Arc::clone(&self.inner),
                mpsc::channel(STREAM_READ_QUEUE_CAPACITY).1,
                Arc::clone(&self.processor),
                socket_streams,
                self.local_id,
            );
        };
        super::async_stream::UdxAsyncStream::new(
            Arc::clone(&self.inner),
            read_rx,
            Arc::clone(&self.processor),
            socket_streams,
            self.local_id,
        )
    }

    /// Returns the current effective MTU (Maximum Transmission Unit) in bytes.
    pub fn effective_mtu(&self) -> usize {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.mtu
    }

    /// Connect to a remote stream identified by `remote_id` at `remote_addr`.
    pub async fn connect(
        &self,
        socket: &super::socket::UdxSocket,
        remote_id: u32,
        remote_addr: SocketAddr,
    ) -> Result<()> {
        let outbound_tx = socket.outbound_sender()?;
        let (notify_tx, notify_rx) = mpsc::channel(64);

        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.remote_id = remote_id;
            inner.remote_addr = Some(remote_addr);
            inner.outbound_tx = Some(outbound_tx);
            inner.connected = true;
            inner.notify_tx = Some(notify_tx);
        }

        let tx = self
            .incoming_tx
            .as_ref()
            .ok_or_else(|| UdxError::Io(std::io::Error::other("stream already consumed")))?
            .clone();
        let incoming_rx = self
            .incoming_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(|| UdxError::Io(std::io::Error::other("processor already started")))?;
        let inner = Arc::clone(&self.inner);
        let inner_for_cleanup = Arc::clone(&self.inner);
        let streams_for_cleanup = socket.streams_ref();
        let local_id_for_cleanup = self.local_id;
        let handle = tokio::spawn(async move {
            process_incoming(inner, incoming_rx, notify_rx).await;
            unregister_stream_if_current(
                &streams_for_cleanup,
                local_id_for_cleanup,
                &inner_for_cleanup,
            );
        });
        *self.processor.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
        let stream_map = socket.streams_ref();
        if let Err(error) = socket.register_stream(
            self.local_id,
            StreamRegistration::new(tx, Arc::clone(&self.inner), Arc::clone(&self.processor)),
        ) {
            if let Some(handle) = self.processor.lock().ok().and_then(|mut g| g.take()) {
                handle.abort();
            }
            self.inner
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .terminate();
            return Err(error);
        }
        *self
            .socket_streams
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(stream_map);

        tracing::debug!(
            local_id = self.local_id,
            remote_id,
            ?remote_addr,
            "stream connected"
        );
        Ok(())
    }

    /// Write `data` reliably. Resolves when the remote peer ACKs all packets.
    pub async fn write(&self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return self.write_batch(data).await;
        }
        let max_batch_bytes = {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.max_payload() * STREAM_SEND_QUEUE_CAPACITY
        };
        for batch in data.chunks(max_batch_bytes) {
            self.write_batch(batch).await?;
        }
        Ok(())
    }

    async fn write_batch(&self, data: &[u8]) -> Result<()> {
        let prep = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.prepare_write(data.len())?
        };

        send_data_packets(
            &self.inner,
            &prep.writer,
            prep.remote_addr,
            prep.remote_id,
            prep.first_seq,
            prep.current_ack,
            prep.reserved_packets,
            data,
        )
        .await?;

        prep.ack_rx.await.map_err(|_| UdxError::StreamClosed)?
    }

    /// Read the next message. Returns `None` on EOF or stream close.
    pub async fn read(&mut self) -> Result<Option<Vec<u8>>> {
        let rx = self.read_rx.as_mut().ok_or(UdxError::StreamClosed)?;
        match rx.recv().await {
            Some(StreamEvent::Data(d)) => Ok(Some(d)),
            Some(StreamEvent::End) => {
                self.read_rx = None;
                Ok(None)
            }
            None => {
                self.read_rx = None;
                Ok(None)
            }
        }
    }

    /// Send a write-end (FIN) and wait for the remote peer to ACK it.
    pub async fn shutdown(&self) -> Result<()> {
        let prep = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.prepare_end()?
        };

        let header = Header {
            type_flags: FLAG_END,
            data_offset: 0,
            remote_id: prep.remote_id,
            recv_window: DEFAULT_RWND,
            seq: prep.first_seq,
            ack: prep.current_ack,
        };
        let packet = header.encode();

        {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.queue_for_send(
                vec![(prep.first_seq, packet.to_vec())],
                prep.remote_addr,
                prep.reserved_packets,
            )?;
        }

        prep.ack_rx.await.map_err(|_| UdxError::StreamClosed)?
    }

    /// Set up packet-level relay forwarding to `destination`.
    ///
    /// Both streams must be on the same runtime. Relayed packets bypass
    /// congestion control — only the `remote_id` header field is rewritten.
    pub fn relay_to(&self, destination: &UdxStream) -> Result<()> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.relay_target = Some(Arc::clone(&destination.inner));
        tracing::debug!("relay_to configured");
        Ok(())
    }

    /// Destroy the stream, sending a DESTROY packet to the remote peer.
    pub async fn destroy(mut self) -> Result<()> {
        let destroy_info = {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if inner.connected {
                inner
                    .outbound_tx
                    .clone()
                    .zip(inner.remote_addr)
                    .map(|(writer, addr)| {
                        let header = Header {
                            type_flags: FLAG_DESTROY,
                            data_offset: 0,
                            remote_id: inner.remote_id,
                            recv_window: 0,
                            seq: inner.next_seq,
                            ack: inner.next_remote_seq,
                        };
                        (writer, addr, header)
                    })
            } else {
                None
            }
        };

        if let Some((writer, addr, header)) = destroy_info {
            let _ = send_reliable(&writer, header.encode().to_vec(), addr).await;
        }

        let processor_handle = self.processor.lock().ok().and_then(|mut g| g.take());
        if let Some(handle) = processor_handle {
            handle.abort();
            let _ = handle.await;
        }

        self.incoming_tx = None;

        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.terminate();
            if let Some(tx) = inner.close_tx.take() {
                let _ = tx.send(());
            }
        }

        if let Some(streams) = self
            .socket_streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            unregister_stream_if_current(&streams, self.local_id, &self.inner);
        }

        tracing::debug!(local_id = self.local_id, "stream destroyed");
        Ok(())
    }
}

impl Drop for UdxStream {
    fn drop(&mut self) {
        if self.owns_processor {
            if let Ok(mut guard) = self.processor.lock() {
                if let Some(handle) = guard.take() {
                    handle.abort();
                }
            }
            self.inner
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .terminate();
        }
        if let Ok(mut guard) = self.socket_streams.lock() {
            if let Some(streams) = guard.take() {
                unregister_stream_if_current(&streams, self.local_id, &self.inner);
            }
        }
    }
}

// ── Processor task (reliability engine) ──────────────────────────────────────

async fn process_incoming(
    inner: Arc<Mutex<StreamInner>>,
    mut incoming_rx: mpsc::Receiver<IncomingPacket>,
    mut notify_rx: mpsc::Receiver<StreamNotify>,
) {
    use tokio::time::{self, Duration, Instant as TokioInstant};

    let mut shutting_down = false;

    // RTO timer starts far in the future (no data in flight initially).
    let rto_sleep = time::sleep(FAR_FUTURE);
    tokio::pin!(rto_sleep);

    let pacing_sleep = time::sleep(FAR_FUTURE);
    tokio::pin!(pacing_sleep);

    let mut keepalive = time::interval(Duration::from_millis(HEARTBEAT_INTERVAL_MS));
    keepalive.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            // ── Incoming packet processing ───────────────────────────
            packet = incoming_rx.recv() => {
                let Some(packet) = packet else { break };

                // Socket routing applies the same source check before it queues
                // packets. Keep this defense in depth here so no injected or
                // stale queued packet can ACK, SACK, relay, deliver DATA, or
                // DESTROY a stream from an unpinned address.
                if !inner
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .accepts_packet_from(packet.addr)
                {
                    continue;
                }

                // ── Relay fast-path ──────────────────────────────
                let relay_info = {
                    let guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                    guard.relay_target.as_ref().map(|target| {
                        let tgt = target.lock().unwrap_or_else(|e| e.into_inner());
                        (tgt.remote_id, tgt.remote_addr, tgt.outbound_tx.clone())
                    })
                };

                if let Some((dest_remote_id, dest_addr, dest_writer)) = relay_info {
                    let mut fwd = packet.data;
                    if fwd.len() >= 8 {
                        fwd[4..8].copy_from_slice(&dest_remote_id.to_le_bytes());
                    }
                    let destroys_relay = fwd.len() > 2 && fwd[2] & FLAG_DESTROY != 0;
                    if let (Some(writer), Some(addr)) = (dest_writer, dest_addr) {
                        let _ = send_reliable(&writer, fwd, addr).await;
                    }
                    if destroys_relay {
                        tracing::debug!("relay: DESTROY received, closing relay stream");
                        let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(tx) = guard.close_tx.take() {
                            let _ = tx.send(());
                        }
                        break;
                    }
                    continue;
                }

                let header = match Header::decode(&packet.data) {
                    Ok(h) => h,
                    Err(_) => continue,
                };

                tracing::trace!(
                    flags = header.type_flags,
                    seq = header.seq,
                    ack = header.ack,
                    data_offset = header.data_offset,
                    "process_incoming: received packet"
                );

                // ── ACK + SACK processing ────────────────────────────
                let has_ack = header.ack > 0;
                let has_sack = header.has_flag(FLAG_SACK) && header.data_offset > 0;

                if has_ack || has_sack {
                    // Decode SACK ranges from wire format (outside lock)
                    let sack_ranges = if has_sack {
                        let sack_end = header.payload_offset();
                        if sack_end <= packet.data.len() {
                            decode_sack(&packet.data[HEADER_SIZE..sack_end]).ok()
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    let (completed, outgoing_empty, fast_retransmits, writer_for_retransmit, addr_for_retransmit) = {
                        let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                        guard.send_rwnd = header.recv_window;

                        let (write_completions, mut acked_rate_info) = if has_ack {
                            guard.on_cumulative_ack(header.ack)
                        } else {
                            (Vec::new(), Vec::new())
                        };

                        if let Some(ref ranges) = sack_ranges {
                            let sack_info = guard.on_sack(ranges);
                            acked_rate_info.extend(sack_info);
                        }

                        let lost_count = guard.detect_losses();

                        if !acked_rate_info.is_empty() || lost_count > 0 {
                            let inflight = guard.inflight();
                            let now = Instant::now();
                            guard.congestion.on_ack(&acked_rate_info, lost_count, inflight, now);
                        }

                        let retransmits = guard.fast_retransmit();
                        let writer = guard.outbound_tx.clone();
                        let addr = guard.remote_addr;

                        let empty = guard.outgoing.is_empty();
                        (write_completions, empty, retransmits, writer, addr)
                    };

                    // Notify completed writes (outside lock)
                    for tx in completed.into_iter().flatten() {
                        let _ = tx.send(Ok(()));
                    }

                    // Fast retransmit lost packets (outside lock)
                    if let (Some(writer), Some(addr)) = (writer_for_retransmit, addr_for_retransmit) {
                        for packet_bytes in fast_retransmits {
                            let _ = send_reliable(&writer, packet_bytes, addr).await;
                        }
                    }

                    // Reset RTO timer based on outgoing state
                    if outgoing_empty {
                        rto_sleep.as_mut().reset(TokioInstant::now() + FAR_FUTURE);
                    } else {
                        let rto = inner.lock().unwrap_or_else(|e| e.into_inner()).rto as u64;
                        rto_sleep.as_mut().reset(
                            TokioInstant::now() + Duration::from_millis(rto),
                        );
                    }

                    {
                        let guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                        if !guard.send_queue.is_empty() {
                            drop(guard);
                            pacing_sleep.as_mut().reset(TokioInstant::now());
                        }
                    }
                } else {
                    // No ACK/SACK — still update recv window
                    let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                    guard.send_rwnd = header.recv_window;
                }

                // ── DATA / END processing (unified — handles combined DATA+END packets) ──
                let is_data = header.has_flag(FLAG_DATA);
                let is_end = header.has_flag(FLAG_END);
                if is_data || is_end {
                    let payload_start = header.payload_offset();
                    let Some(payload) = payload_from_packet(&packet.data, payload_start) else {
                        tracing::debug!(
                            payload_start,
                            packet_len = packet.data.len(),
                            "stream: rejected malformed DATA/END payload offset"
                        );
                        continue;
                    };
                    let recv_flags = (if is_data { FLAG_DATA } else { 0 })
                        | (if is_end { FLAG_END } else { 0 });

                    let (events, read_tx, writer, remote_addr, remote_id, ack_val, sack_ranges) = {
                        let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                        let Some(events) = guard.receive_data(header.seq, payload, recv_flags) else {
                            // Do not emit ACK/SACK for a packet we refused to retain:
                            // otherwise the sender can discard data we never buffered.
                            continue;
                        };
                        let sacks = guard.sack_ranges();
                        let ack_val = guard.next_remote_seq;
                        (
                            events,
                            guard.read_tx.clone(),
                            guard.outbound_tx.clone(),
                            guard.remote_addr,
                            guard.remote_id,
                            ack_val,
                            sacks,
                        )
                    };
                    let Some(read_tx) = read_tx else {
                        break;
                    };
                    let mut delivered = true;
                    for event in events {
                        if read_tx.send(event).await.is_err() {
                            delivered = false;
                            break;
                        }
                    }
                    if !delivered {
                        inner.lock().unwrap_or_else(|e| e.into_inner()).terminate();
                        break;
                    }
                    send_ack(&writer, remote_addr, remote_id, ack_val, &sack_ranges).await;
                }

                // ── DESTROY processing ───────────────────────────────
                if header.has_flag(FLAG_DESTROY) {
                    let read_tx = {
                        let guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                        guard.read_tx.clone()
                    };
                    if let Some(read_tx) = read_tx {
                        let _ = read_tx.send(StreamEvent::End).await;
                    }
                    let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(tx) = guard.close_tx.take() {
                        let _ = tx.send(());
                    }
                    break;
                }

                // ── HEARTBEAT response ───────────────────────────────
                if header.has_flag(FLAG_HEARTBEAT) {
                    let (writer, remote_addr, remote_id, ack_val) = {
                        let guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                        (
                            guard.outbound_tx.clone(),
                            guard.remote_addr,
                            guard.remote_id,
                            guard.next_remote_seq,
                        )
                    };
                    send_ack(&writer, remote_addr, remote_id, ack_val, &[]).await;
                }
            }

            Some(notify) = notify_rx.recv() => {
                match notify {
                    StreamNotify::DataQueued => {
                        pacing_sleep.as_mut().reset(TokioInstant::now());
                    }
                    StreamNotify::Shutdown => {
                        shutting_down = true;
                        pacing_sleep.as_mut().reset(TokioInstant::now());
                    }
                }
            }

            _ = &mut pacing_sleep => {
                let (packets_to_send, should_arm_rto, new_rto_ms) = {
                    let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                    let mut batch: Vec<(Vec<u8>, SocketAddr)> = Vec::new();
                    let was_outgoing_empty = guard.outgoing.is_empty();

                    while !guard.send_queue.is_empty() {
                        let inflight = guard.inflight() + batch.len() as u32;
                        let queued_bytes = guard.send_queue.iter()
                            .map(|q| q.packet.len())
                            .sum::<usize>();
                        guard.congestion.check_app_limited(queued_bytes, inflight);

                        if !guard.congestion.can_send(inflight, guard.send_rwnd) {
                            break;
                        }

                        let Some(front) = guard.send_queue.front() else {
                            break;
                        };
                        let packet_len = front.packet.len() as u32;

                        let now = std::time::Instant::now();
                        let delay = guard.congestion.pacing_delay(packet_len, now);
                        if delay > std::time::Duration::ZERO {
                            pacing_sleep.as_mut().reset(TokioInstant::now() + delay);
                            break;
                        }

                        let Some(queued) = guard.send_queue.pop_front() else {
                            break;
                        };
                        let mut packet = queued.packet;

                        let is_data = packet.len() >= HEADER_SIZE && packet[2] & FLAG_DATA != 0;
                        if is_data && guard.mtu_state == MtuState::Base {
                            guard.mtu_state = MtuState::Search;
                            guard.mtu_probe_wanted = true;
                        }

                        let is_mtu_probe = if is_data
                            && guard.mtu_state == MtuState::Search
                            && guard.mtu_probe_wanted
                        {
                            guard.mtu_probeify_packet(&mut packet)
                        } else {
                            false
                        };

                        guard.register_sent(queued.seq, packet.clone(), is_mtu_probe);
                        guard.congestion.pacing.try_consume(
                            packet.len() as u32, std::time::Instant::now(),
                        );
                        batch.push((packet, queued.remote_addr));
                    }

                    let should_arm = was_outgoing_empty && !guard.outgoing.is_empty();
                    let rto = guard.rto as u64;
                    (batch, should_arm, rto)
                };

                let writer = {
                    let guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                    guard.outbound_tx.clone()
                };
                if let Some(writer) = writer {
                    for (pkt, addr) in packets_to_send {
                        let _ = send_reliable(&writer, pkt, addr).await;
                    }
                }

                if should_arm_rto {
                    rto_sleep.as_mut().reset(
                        TokioInstant::now() + Duration::from_millis(new_rto_ms),
                    );
                }

                let has_more = !inner.lock().unwrap_or_else(|e| e.into_inner()).send_queue.is_empty();
                if shutting_down && !has_more {
                    break;
                }
                if has_more {
                    pacing_sleep.as_mut().reset(TokioInstant::now() + Duration::from_millis(1));
                } else {
                    pacing_sleep.as_mut().reset(TokioInstant::now() + FAR_FUTURE);
                }
            }

            _ = &mut rto_sleep => {
                let (retransmits, writer, remote_addr, new_rto, should_close) = {
                    let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());

                    if guard.outgoing.is_empty() {
                        // False alarm — nothing to retransmit
                        rto_sleep.as_mut().reset(TokioInstant::now() + FAR_FUTURE);
                        continue;
                    }

                    guard.rto_timeouts += 1;

                    if guard.rto_timeouts >= MAX_RTO_TIMEOUTS {
                        // Exceeded max timeouts — fail the stream
                        (Vec::new(), None, None, 0u64, true)
                    } else {
                        guard.congestion.on_rto();
                        if let Some(&max_seq) = guard.outgoing.keys().last() {
                            guard.congestion.high_seq = max_seq;
                        }
                        guard.rto = (guard.rto * 2).min(MAX_RTO_MS);
                        let retransmits = guard.packets_to_retransmit();
                        let rto = guard.rto as u64;
                        (retransmits, guard.outbound_tx.clone(), guard.remote_addr, rto, false)
                    }
                };

                if should_close {
                    // Fail all pending writes with timeout error
                    let pending: Vec<_> = {
                        let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                        guard.pending_writes.drain(..).collect()
                    };
                    for mut pw in pending {
                        if let Some(tx) = pw.tx.take() {
                            let _ = tx.send(Err(UdxError::Io(
                                std::io::Error::new(
                                    std::io::ErrorKind::TimedOut,
                                    "RTO timeout exceeded",
                                ),
                            )));
                        }
                    }
                    tracing::warn!("stream failed: exceeded max RTO timeouts");
                    break;
                }

                // Retransmit unACKed/unSACKed packets
                if let (Some(writer), Some(addr)) = (writer, remote_addr) {
                    tracing::debug!(
                        count = retransmits.len(),
                        rto_ms = new_rto,
                        "retransmitting packets"
                    );
                    for packet_bytes in retransmits {
                        let _ = send_reliable(&writer, packet_bytes, addr).await;
                    }
                }

                // Schedule next RTO check
                rto_sleep.as_mut().reset(
                    TokioInstant::now() + Duration::from_millis(new_rto),
                );
            }

            // ── Keepalive heartbeat ──────────────────────────────────
            _ = keepalive.tick() => {
                let (should_send, writer, addr, remote_id, ack_val) = {
                    let guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                    if guard.connected && guard.outgoing.is_empty() && guard.relay_target.is_none() {
                        (
                            true,
                            guard.outbound_tx.clone(),
                            guard.remote_addr,
                            guard.remote_id,
                            guard.next_remote_seq,
                        )
                    } else {
                        (false, None, None, 0, 0)
                    }
                };

                if should_send {
                    if let (Some(writer), Some(addr)) = (writer, addr) {
                        let header = Header {
                            type_flags: FLAG_HEARTBEAT,
                            data_offset: 0,
                            remote_id,
                            recv_window: DEFAULT_RWND,
                            seq: 0,
                            ack: ack_val,
                        };
                        let _ = send_reliable(&writer, header.encode().to_vec(), addr).await;
                    }
                }
            }
        }
    }

    inner.lock().unwrap_or_else(|e| e.into_inner()).terminate();
}

// ── Packet building ──────────────────────────────────────────────────────────

/// Build a wire-format DATA packet (header + payload).
pub(crate) fn build_data_packet(remote_id: u32, seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
    let header = Header {
        type_flags: FLAG_DATA,
        data_offset: 0,
        remote_id,
        recv_window: DEFAULT_RWND,
        seq,
        ack,
    };
    let mut packet = Vec::with_capacity(HEADER_SIZE + payload.len());
    packet.extend_from_slice(&header.encode());
    packet.extend_from_slice(payload);
    packet
}

// ── send_data_packets ────────────────────────────────────────────────────────

/// Build, register, and send DATA packets for a write.
///
/// Packets are stored in the outgoing buffer *before* being sent on the wire,
/// ensuring the retransmission engine can resend them if ACKs don't arrive.
pub(crate) async fn send_data_packets(
    inner: &Arc<Mutex<StreamInner>>,
    _writer: &OutboundSender,
    remote_addr: SocketAddr,
    remote_id: u32,
    first_seq: u32,
    current_ack: u32,
    reserved_packets: usize,
    data: &[u8],
) -> Result<()> {
    let max_payload = inner
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .max_payload();
    let chunks: Vec<&[u8]> = if data.is_empty() {
        vec![&[]]
    } else {
        data.chunks(max_payload).collect()
    };

    let mut packets: Vec<(u32, Vec<u8>)> = Vec::with_capacity(chunks.len());
    for (i, chunk) in chunks.iter().enumerate() {
        let seq = first_seq + i as u32;
        packets.push((seq, build_data_packet(remote_id, seq, current_ack, chunk)));
    }

    {
        let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
        if guard.outgoing.is_empty() && guard.send_queue.is_empty() {
            guard
                .congestion
                .on_transmit_start(std::time::Instant::now());
        }
        guard.queue_for_send(packets, remote_addr, reserved_packets)?;
    }
    Ok(())
}

// ── send_ack ─────────────────────────────────────────────────────────────────

/// Send an ACK packet, optionally including SACK ranges.
///
/// When `sack_ranges` is non-empty, the packet includes FLAG_SACK with
/// the SACK data encoded after the header (using `data_offset` to indicate
/// the extra bytes).
async fn send_ack(
    writer: &Option<OutboundSender>,
    remote_addr: Option<SocketAddr>,
    remote_id: u32,
    ack: u32,
    sack_ranges: &[SackRange],
) {
    if let (Some(writer), Some(addr)) = (writer.as_ref(), remote_addr) {
        if sack_ranges.is_empty() {
            // Pure ACK — just the 20-byte header
            let header = Header {
                type_flags: 0,
                data_offset: 0,
                remote_id,
                recv_window: DEFAULT_RWND,
                seq: 0,
                ack,
            };
            let _ = send_reliable(writer, header.encode().to_vec(), addr).await;
        } else {
            // ACK with SACK ranges
            let sack_byte_len = sack_ranges.len() * 8;
            let header = Header {
                type_flags: FLAG_SACK,
                data_offset: sack_byte_len as u8,
                remote_id,
                recv_window: DEFAULT_RWND,
                seq: 0,
                ack,
            };

            let mut packet = Vec::with_capacity(HEADER_SIZE + sack_byte_len);
            let header_bytes = header.encode();
            packet.extend_from_slice(&header_bytes);
            let mut sack_buf = vec![0u8; sack_byte_len];
            encode_sack(sack_ranges, &mut sack_buf);
            packet.extend_from_slice(&sack_buf);

            let _ = send_reliable(writer, packet, addr).await;
        }
    }
}

#[cfg(test)]
mod bounded_transport_tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;
    use crate::UdxRuntime;

    fn loopback() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    #[tokio::test]
    async fn bounded_read_queue_backpressures_then_roundtrips_after_drain() {
        let runtime = UdxRuntime::new().expect("runtime");
        let left_socket = runtime.create_socket().await.expect("left socket");
        let right_socket = runtime.create_socket().await.expect("right socket");
        left_socket.bind(loopback()).await.expect("bind left");
        right_socket.bind(loopback()).await.expect("bind right");
        let left_addr = left_socket.local_addr().await.expect("left address");
        let right_addr = right_socket.local_addr().await.expect("right address");

        let left = runtime.create_stream(101).await.expect("left stream");
        let mut right = runtime.create_stream(202).await.expect("right stream");
        left.connect(&left_socket, 202, right_addr)
            .await
            .expect("connect left");
        right
            .connect(&right_socket, 101, left_addr)
            .await
            .expect("connect right");

        // More packets than the bounded application queue. The right-side
        // processor cannot ACK all packets until the consumer drains them.
        let payload = vec![0xC7; MAX_PAYLOAD * (STREAM_READ_QUEUE_CAPACITY + 32)];
        let write = left.write(&payload);
        tokio::pin!(write);
        assert!(
            timeout(Duration::from_millis(100), &mut write)
                .await
                .is_err(),
            "write must not complete before the saturated reader accepts data"
        );

        let mut received = Vec::with_capacity(payload.len());
        while received.len() < payload.len() {
            let chunk = timeout(Duration::from_secs(5), right.read())
                .await
                .expect("right reader makes progress")
                .expect("stream read succeeds")
                .expect("data before eof");
            received.extend_from_slice(&chunk);
        }

        timeout(Duration::from_secs(5), &mut write)
            .await
            .expect("write completes after drain")
            .expect("remote ACK succeeds");
        assert_eq!(received, payload);

        drop(write);
        left.destroy().await.expect("destroy left");
        right.destroy().await.expect("destroy right");
        left_socket.close().await.expect("close left socket");
        right_socket.close().await.expect("close right socket");
    }

    #[test]
    fn stale_route_cleanup_cannot_remove_a_replacement_stream() {
        let old = UdxStream::new(77);
        let replacement = UdxStream::new(77);
        let streams: StreamMap = Arc::new(Mutex::new(std::collections::HashMap::new()));

        let old_registration = StreamRegistration::new(
            old.incoming_tx.as_ref().expect("old ingress").clone(),
            Arc::clone(&old.inner),
            Arc::clone(&old.processor),
        );
        let replacement_registration = StreamRegistration::new(
            replacement
                .incoming_tx
                .as_ref()
                .expect("replacement ingress")
                .clone(),
            Arc::clone(&replacement.inner),
            Arc::clone(&replacement.processor),
        );
        streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(77, old_registration);
        streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(77, replacement_registration);

        unregister_stream_if_current(&streams, 77, &old.inner);
        assert!(
            streams
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&77)
                .is_some_and(|route| route.matches_inner(&replacement.inner))
        );

        unregister_stream_if_current(&streams, 77, &replacement.inner);
        assert!(streams.lock().unwrap_or_else(|e| e.into_inner()).is_empty());
    }
}

#[cfg(test)]
mod mtu_tests {
    use super::*;

    fn make_stream_inner() -> StreamInner {
        let (read_tx, _read_rx) = mpsc::channel(STREAM_READ_QUEUE_CAPACITY);
        StreamInner {
            remote_id: 0,
            remote_addr: None,
            connected: false,
            next_seq: 0,
            pending_writes: Vec::new(),
            outgoing: BTreeMap::new(),
            next_remote_seq: 0,
            remote_acked: 0,
            recv_buf: BTreeMap::new(),
            recv_buf_bytes: 0,
            srtt: 0,
            rttvar: 0,
            rto: INITIAL_RTO_MS,
            rto_timeouts: 0,
            send_rwnd: DEFAULT_RWND,
            mtu_state: MtuState::Base,
            mtu: MTU_BASE,
            mtu_probe_size: MTU_BASE + MTU_STEP,
            mtu_probe_count: 0,
            mtu_probe_wanted: false,
            mtu_max: MTU_MAX,
            outbound_tx: None,
            read_tx: Some(read_tx),
            close_tx: None,
            notify_tx: None,
            congestion: crate::native::congestion::CongestionController::new(
                MAX_PAYLOAD as u32,
                INITIAL_RTO_MS,
            ),
            send_queue: VecDeque::new(),
            reserved_send_slots: 0,
            relay_target: None,
            ended: false,
        }
    }

    // T3: MTU state starts at BASE
    #[test]
    fn mtu_initial_state_is_base() {
        let inner = make_stream_inner();
        assert_eq!(inner.mtu_state, MtuState::Base);
        assert_eq!(inner.mtu, MTU_BASE);
        assert!(!inner.mtu_probe_wanted);
        assert_eq!(inner.mtu_probe_count, 0);
        assert_eq!(inner.mtu_probe_size, MTU_BASE + MTU_STEP);
        assert_eq!(inner.mtu_max, MTU_MAX);
    }

    #[test]
    fn out_of_order_empty_packets_are_bounded_by_entry_count() {
        let mut inner = make_stream_inner();

        for seq in 1..=MAX_RECV_BUFFER_PACKETS as u32 {
            assert!(
                inner.receive_data(seq, Vec::new(), FLAG_DATA).is_some(),
                "packet {seq} must fit in the bounded receive window"
            );
        }

        assert_eq!(inner.recv_buf.len(), MAX_RECV_BUFFER_PACKETS);
        assert_eq!(inner.recv_buf_bytes, 0, "empty packets consume no bytes");
        let sacks_before = inner.sack_ranges();

        assert!(
            inner
                .receive_data(MAX_RECV_BUFFER_PACKETS as u32 + 1, Vec::new(), FLAG_DATA)
                .is_none(),
            "an at-cap/out-of-window packet must be dropped without acknowledgement"
        );
        assert_eq!(inner.recv_buf.len(), MAX_RECV_BUFFER_PACKETS);
        assert_eq!(inner.recv_buf_bytes, 0);
        assert_eq!(
            inner.sack_ranges(),
            sacks_before,
            "rejected packets are not SACKed"
        );
    }

    #[test]
    fn malformed_payload_offset_is_not_treated_as_empty_data() {
        let header = Header {
            type_flags: FLAG_DATA | FLAG_END,
            data_offset: 1,
            remote_id: 7,
            recv_window: DEFAULT_RWND,
            seq: 0,
            ack: 0,
        };
        let packet = header.encode();

        assert!(
            payload_from_packet(&packet, header.payload_offset()).is_none(),
            "a header offset beyond the received wire packet is malformed"
        );
    }

    #[test]
    fn in_order_empty_end_still_delivers_end() {
        let mut inner = make_stream_inner();

        let events = inner
            .receive_data(0, Vec::new(), FLAG_END)
            .expect("in-order END is admitted");
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], StreamEvent::End));
        assert_eq!(inner.next_remote_seq, 1);
    }

    #[test]
    fn only_the_pinned_peer_source_can_admit_ack_data_or_destroy() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let expected = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 31_001);
        let forged = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 31_002);
        let mut inner = make_stream_inner();
        inner.connected = true;
        inner.remote_addr = Some(expected);
        inner.remote_id = 77;
        inner.next_remote_seq = 5;
        inner.remote_acked = 2;

        let inner = Arc::new(Mutex::new(inner));
        let (ingress, _incoming_rx) = mpsc::channel(STREAM_PACKET_QUEUE_CAPACITY);
        let registration =
            StreamRegistration::new(ingress, Arc::clone(&inner), Arc::new(Mutex::new(None)));

        let state_before = {
            let guard = inner.lock().unwrap_or_else(|e| e.into_inner());
            (
                guard.next_remote_seq,
                guard.remote_acked,
                guard.recv_buf.len(),
                guard.outgoing.len(),
            )
        };
        for type_flags in [0, FLAG_DATA, FLAG_DESTROY] {
            let header = Header {
                type_flags,
                data_offset: 0,
                remote_id: 77,
                recv_window: DEFAULT_RWND,
                seq: 9,
                ack: 9,
            };
            assert!(
                !registration.accepts_source(forged),
                "spoofed UDX packet flags {type_flags:#x} must be rejected before reliability state"
            );
            assert_eq!(header.remote_id, 77);
            let guard = inner.lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(
                (
                    guard.next_remote_seq,
                    guard.remote_acked,
                    guard.recv_buf.len(),
                    guard.outgoing.len(),
                ),
                state_before,
                "a rejected ACK/DATA/DESTROY must leave stream state unchanged"
            );
        }
        assert!(
            registration.accepts_source(expected),
            "the address pinned at connection setup remains admitted"
        );
    }

    #[test]
    fn sack_ranges_are_clamped_to_existing_outgoing_entries() {
        let mut inner = make_stream_inner();
        for seq in [10, 12, 14] {
            inner.outgoing.insert(
                seq,
                SentPacket {
                    packet: vec![0],
                    time_sent: Instant::now(),
                    retransmit_count: 0,
                    sacked: false,
                    is_mtu_probe: false,
                    lost: false,
                    rate_info: None,
                },
            );
        }

        let no_change = inner.on_sack(&[
            SackRange {
                start: u32::MAX,
                end: 0,
            },
            SackRange { start: 12, end: 12 },
            SackRange {
                start: 1_000,
                end: 2_000,
            },
        ]);
        assert!(no_change.is_empty());
        assert!(inner.outgoing.values().all(|packet| !packet.sacked));

        // This range spans almost the entire u32 space. Processing must visit
        // only the three BTreeMap keys that actually exist, never enumerate the
        // numeric range.
        let newly_sacked = inner.on_sack(&[SackRange {
            start: 0,
            end: u32::MAX,
        }]);
        assert!(
            newly_sacked.is_empty(),
            "test packets carry no rate samples"
        );
        assert!(inner.outgoing.values().all(|packet| packet.sacked));
        assert_eq!(inner.outgoing.len(), 3, "SACK cannot create stream state");
    }

    #[test]
    fn retransmit_keeps_the_exact_unacknowledged_wire_packet() {
        let mut inner = make_stream_inner();
        let original = build_data_packet(7, 11, 3, b"bounded-retransmit");
        inner.outgoing.insert(
            11,
            SentPacket {
                packet: original.clone(),
                time_sent: Instant::now(),
                retransmit_count: 0,
                sacked: false,
                is_mtu_probe: false,
                lost: false,
                rate_info: None,
            },
        );

        let retransmits = inner.packets_to_retransmit();
        assert_eq!(retransmits, vec![original]);
        assert_eq!(inner.outgoing[&11].retransmit_count, 1);
    }

    // T5: MTU probe failure falls back gracefully — retransmit strips padding and increments failure count
    #[test]
    fn mtu_probe_failure_fallback() {
        let mut inner = make_stream_inner();
        inner.mtu_state = MtuState::Search;
        inner.mtu = MTU_BASE;

        let payload = vec![0xABu8; MTU_BASE - HEADER_SIZE];
        let packet = build_data_packet(0, 0, 0, &payload);
        inner.outgoing.insert(
            0,
            SentPacket {
                packet,
                time_sent: Instant::now(),
                retransmit_count: 0,
                sacked: false,
                is_mtu_probe: true,
                lost: false,
                rate_info: None,
            },
        );

        let retransmits = inner.packets_to_retransmit();
        assert_eq!(retransmits.len(), 1);
        assert_eq!(inner.mtu_probe_count, 1);
        assert!(
            !inner.outgoing[&0].is_mtu_probe,
            "probe flag should be cleared after retransmit"
        );
        assert_eq!(
            inner.outgoing[&0].packet[3], 0,
            "data_offset should be reset"
        );
        assert_eq!(
            inner.mtu_state,
            MtuState::Search,
            "still searching after 1 failure"
        );
        assert!(
            inner.mtu_probe_wanted,
            "should want another probe after non-terminal failure"
        );
    }

    // T6: Probe uses data_offset padding — probeify inflates packet to probe size
    #[test]
    fn mtu_probe_uses_data_offset_padding() {
        let mut inner = make_stream_inner();
        inner.mtu_state = MtuState::Search;
        inner.mtu_probe_size = MTU_BASE + MTU_STEP;

        let payload = vec![0xCDu8; MTU_BASE - HEADER_SIZE];
        let mut packet = build_data_packet(0, 0, 0, &payload);
        let original_len = packet.len();
        assert_eq!(original_len, MTU_BASE);

        let ok = inner.mtu_probeify_packet(&mut packet);
        assert!(ok, "probeify should succeed for nearly-full packet");
        assert_eq!(
            packet.len(),
            MTU_BASE + MTU_STEP,
            "packet should be inflated to probe size"
        );
        assert_eq!(
            packet[3] as usize, MTU_STEP,
            "data_offset should equal padding size"
        );

        let payload_start = HEADER_SIZE + MTU_STEP;
        assert_eq!(
            &packet[payload_start..],
            &payload[..],
            "original payload should be intact after padding"
        );
    }

    // T7: Probe ACK advances MTU and scales congestion window
    #[test]
    fn mtu_probe_ack_advances_mtu() {
        let mut inner = make_stream_inner();
        inner.mtu_state = MtuState::Search;
        inner.mtu = MTU_BASE;
        inner.mtu_probe_size = MTU_BASE + MTU_STEP;

        inner.on_mtu_probe_acked();

        assert_eq!(inner.mtu, MTU_BASE + MTU_STEP);
        assert_eq!(inner.mtu_probe_count, 0);
        assert_eq!(inner.mtu_probe_size, MTU_BASE + 2 * MTU_STEP);
        assert!(inner.mtu_probe_wanted, "should want next probe");
        assert_eq!(
            inner.mtu_state,
            MtuState::Search,
            "still searching — haven't reached max"
        );
    }

    // T8: MTU_MAX_PROBES consecutive failures → SearchComplete
    #[test]
    fn mtu_max_probe_failures_completes_search() {
        let mut inner = make_stream_inner();
        inner.mtu_state = MtuState::Search;
        inner.mtu = MTU_BASE + MTU_STEP;

        for i in 0..MTU_MAX_PROBES {
            let payload = vec![0xEFu8; MTU_BASE - HEADER_SIZE];
            let packet = build_data_packet(0, i, 0, &payload);
            inner.outgoing.insert(
                i,
                SentPacket {
                    packet,
                    time_sent: Instant::now(),
                    retransmit_count: 0,
                    sacked: false,
                    is_mtu_probe: true,
                    lost: false,
                    rate_info: None,
                },
            );

            let _ = inner.packets_to_retransmit();
        }

        assert_eq!(inner.mtu_state, MtuState::SearchComplete);
        assert!(!inner.mtu_probe_wanted);
        assert_eq!(
            inner.mtu,
            MTU_BASE + MTU_STEP,
            "MTU frozen at last successful value"
        );
    }
}
