use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

use super::header::{FLAG_END, Header};
use super::stream::{
    DEFAULT_RWND, STREAM_SEND_QUEUE_CAPACITY, StreamEvent, StreamInner, StreamMap,
    build_data_packet, unregister_stream_if_current,
};
use crate::error::Result as UdxResult;

/// Adapter that implements [`tokio::io::AsyncRead`] and [`tokio::io::AsyncWrite`]
/// over a [`super::stream::UdxStream`].
///
/// Created via [`super::stream::UdxStream::into_async_stream`]. Higher layers
/// (e.g. SecretStream) wrap this for encrypted I/O.
pub struct UdxAsyncStream {
    inner: Arc<Mutex<StreamInner>>,
    read_rx: mpsc::Receiver<StreamEvent>,
    read_buf: Vec<u8>,
    read_pos: usize,
    read_eof: bool,
    pending_ack: Option<oneshot::Receiver<UdxResult<()>>>,
    processor: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    fin_queued: bool,
    socket_streams: Option<StreamMap>,
    local_id: u32,
}

impl UdxAsyncStream {
    pub(crate) fn new(
        inner: Arc<Mutex<StreamInner>>,
        read_rx: mpsc::Receiver<StreamEvent>,
        processor: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
        socket_streams: Option<StreamMap>,
        local_id: u32,
    ) -> Self {
        Self {
            inner,
            read_rx,
            read_buf: Vec::new(),
            read_pos: 0,
            read_eof: false,
            pending_ack: None,
            processor,
            fin_queued: false,
            socket_streams,
            local_id,
        }
    }
}

impl AsyncRead for UdxAsyncStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_eof {
            return Poll::Ready(Ok(()));
        }

        if self.read_pos < self.read_buf.len() {
            let remaining = &self.read_buf[self.read_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.read_pos += n;
            if self.read_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        match self.read_rx.poll_recv(cx) {
            Poll::Ready(Some(StreamEvent::Data(data))) => {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.read_buf = data;
                    self.read_pos = n;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(StreamEvent::End)) | Poll::Ready(None) => {
                self.read_eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for UdxAsyncStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(ref mut ack_rx) = self.pending_ack {
            match Pin::new(ack_rx).poll(cx) {
                Poll::Ready(Ok(result)) => {
                    self.pending_ack = None;
                    if let Err(e) = result {
                        return Poll::Ready(Err(io::Error::other(e.to_string())));
                    }
                }
                Poll::Ready(Err(_)) => {
                    self.pending_ack = None;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "UDX stream closed",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let (prep, max_payload, accepted_len) = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            // AsyncWrite is permitted to make a short write. One accepted
            // batch is deliberately bounded and the following call is ACK
            // gated by `pending_ack`, so a caller cannot create unbounded
            // staged packet vectors with a single giant buffer.
            let accepted_len = buf
                .len()
                .min(inner.max_payload() * STREAM_SEND_QUEUE_CAPACITY);
            let p = inner
                .prepare_write(accepted_len)
                .map_err(|e| io::Error::other(e.to_string()))?;
            let mp = inner.max_payload();
            (p, mp, accepted_len)
        };

        let remote_addr = prep.remote_addr;
        let remote_id = prep.remote_id;
        let first_seq = prep.first_seq;
        let current_ack = prep.current_ack;
        let mut packets = Vec::with_capacity(prep.reserved_packets);
        for (i, chunk) in buf[..accepted_len].chunks(max_payload).enumerate() {
            let seq = first_seq + i as u32;
            packets.push((seq, build_data_packet(remote_id, seq, current_ack, chunk)));
        }

        {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if guard.send_idle() {
                guard
                    .congestion
                    .on_transmit_start(std::time::Instant::now());
            }

            if let Err(error) = guard.queue_for_send(packets, remote_addr, prep.reserved_packets) {
                guard.terminate();
                return Poll::Ready(Err(io::Error::other(error.to_string())));
            }
        }

        self.pending_ack = Some(prep.ack_rx);

        if let Some(ref mut ack) = self.pending_ack {
            match Pin::new(ack).poll(cx) {
                Poll::Ready(Ok(result)) => {
                    self.pending_ack = None;
                    if let Err(e) = result {
                        return Poll::Ready(Err(io::Error::other(e.to_string())));
                    }
                    Poll::Ready(Ok(accepted_len))
                }
                Poll::Ready(Err(_)) => {
                    self.pending_ack = None;
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "UDX stream closed",
                    )))
                }
                Poll::Pending => Poll::Ready(Ok(accepted_len)),
            }
        } else {
            Poll::Ready(Ok(accepted_len))
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(ref mut ack_rx) = self.pending_ack {
            match Pin::new(ack_rx).poll(cx) {
                Poll::Ready(Ok(result)) => {
                    self.pending_ack = None;
                    if let Err(e) = result {
                        return Poll::Ready(Err(io::Error::other(e.to_string())));
                    }
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(_)) => {
                    self.pending_ack = None;
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "UDX stream closed",
                    )))
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(ref mut ack_rx) = self.pending_ack {
            match Pin::new(ack_rx).poll(cx) {
                Poll::Ready(Ok(result)) => {
                    self.pending_ack = None;
                    if let Err(e) = result {
                        return Poll::Ready(Err(io::Error::other(e.to_string())));
                    }
                    if self.fin_queued {
                        return Poll::Ready(Ok(()));
                    }
                    // Write ACK resolved — fall through to queue FIN
                }
                Poll::Ready(Err(_)) => {
                    self.pending_ack = None;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        let prep = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if !inner.connected {
                return Poll::Ready(Ok(()));
            }
            inner
                .prepare_end()
                .map_err(|e| io::Error::other(e.to_string()))?
        };
        let header = Header {
            type_flags: FLAG_END,
            data_offset: 0,
            remote_id: prep.remote_id,
            recv_window: DEFAULT_RWND,
            seq: prep.first_seq,
            ack: prep.current_ack,
        };
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(error) = inner.queue_for_send(
            vec![(prep.first_seq, header.encode().to_vec())],
            prep.remote_addr,
            prep.reserved_packets,
        ) {
            inner.terminate();
            return Poll::Ready(Err(io::Error::other(error.to_string())));
        }
        drop(inner);

        self.fin_queued = true;
        self.pending_ack = Some(prep.ack_rx);
        self.as_mut().poll_shutdown(cx)
    }
}

impl Unpin for UdxAsyncStream {}

impl Drop for UdxAsyncStream {
    fn drop(&mut self) {
        if let Some(handle) = self
            .processor
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            // into_async_stream transfers processor ownership here; dropping a
            // JoinHandle would detach the reliability task indefinitely.
            handle.abort();
        }
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref tx) = guard.notify_tx {
            let _ = tx.try_send(super::stream::StreamNotify::Shutdown);
        }
        // The task was just aborted, so a notification alone cannot be relied
        // on to wake pending writers. Resolve them synchronously before the
        // route is released.
        guard.terminate();
        drop(guard);
        if let Some(streams) = self.socket_streams.take() {
            unregister_stream_if_current(&streams, self.local_id, &self.inner);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use tokio::io::AsyncWriteExt;
    use tokio::time::timeout;

    use super::*;
    use crate::UdxRuntime;

    fn loopback() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    #[tokio::test]
    async fn async_write_accepts_exactly_one_bounded_batch_then_drop_unroutes() {
        let runtime = UdxRuntime::new().expect("runtime");
        let left_socket = runtime.create_socket().await.expect("left socket");
        let right_socket = runtime.create_socket().await.expect("right socket");
        left_socket.bind(loopback()).await.expect("bind left");
        right_socket.bind(loopback()).await.expect("bind right");
        let left_addr = left_socket.local_addr().await.expect("left address");
        let right_addr = right_socket.local_addr().await.expect("right address");

        let left = runtime.create_stream(301).await.expect("left stream");
        let right = runtime.create_stream(302).await.expect("right stream");
        left.connect(&left_socket, 302, right_addr)
            .await
            .expect("connect left");
        right
            .connect(&right_socket, 301, left_addr)
            .await
            .expect("connect right");

        let mut async_left = left.into_async_stream();
        let payload = vec![
            0xA5;
            (1200 - super::super::header::HEADER_SIZE)
                * (STREAM_SEND_QUEUE_CAPACITY + 1)
        ];
        let written = timeout(Duration::from_secs(1), async_left.write(&payload))
            .await
            .expect("bounded poll_write returns without waiting for a giant buffer")
            .expect("write succeeds");
        assert_eq!(
            written,
            (1200 - super::super::header::HEADER_SIZE) * STREAM_SEND_QUEUE_CAPACITY,
            "one AsyncWrite call accepts one ACK-gated bounded batch"
        );

        drop(async_left);
        assert!(
            left_socket
                .streams_ref()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&301)
                .is_none()
        );

        right.destroy().await.expect("destroy right");
        left_socket.close().await.expect("close left socket");
        right_socket.close().await.expect("close right socket");
    }
}
