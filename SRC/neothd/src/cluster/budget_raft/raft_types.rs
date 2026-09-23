//! Exact OpenRaft 0.9.25 configuration for the budget authority.

use super::types::{BudgetCommand, BudgetReply};
use std::cmp::min;
use std::io::{self, SeekFrom};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};

/// Upper bound for one complete installed/built budget snapshot. The stream
/// rejects an overflowing write before allocating or extending its vector.
pub const MAX_BUDGET_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;

/// In-memory snapshot stream with a hard byte ceiling. OpenRaft 0.9.25 needs
/// an `AsyncRead + AsyncWrite + AsyncSeek` data type when generic snapshots
/// are disabled; an unconstrained byte cursor has no write-time bound.
#[derive(Clone, Debug, Default)]
pub struct BudgetSnapshotData {
    bytes: Vec<u8>,
    position: usize,
}

impl BudgetSnapshotData {
    pub fn empty() -> Self { Self::default() }

    pub fn from_bytes(bytes: Vec<u8>) -> io::Result<Self> {
        if bytes.len() > MAX_BUDGET_SNAPSHOT_BYTES {
            return Err(snapshot_too_large());
        }
        Ok(Self { bytes, position: 0 })
    }

    pub fn into_bytes(self) -> Vec<u8> { self.bytes }
    pub fn bytes(&self) -> &[u8] { &self.bytes }
}

fn snapshot_too_large() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "budget raft snapshot exceeds configured maximum")
}

impl AsyncRead for BudgetSnapshotData {
    fn poll_read(mut self: Pin<&mut Self>, _: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let available = self.bytes.get(self.position..).unwrap_or(&[]);
        let count = min(available.len(), buffer.remaining());
        buffer.put_slice(&available[..count]);
        self.position += count;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for BudgetSnapshotData {
    fn poll_write(mut self: Pin<&mut Self>, _: &mut Context<'_>, source: &[u8]) -> Poll<io::Result<usize>> {
        let position = self.position;
        let end = match position.checked_add(source.len()) {
            Some(end) if end <= MAX_BUDGET_SNAPSHOT_BYTES => end,
            _ => return Poll::Ready(Err(snapshot_too_large())),
        };
        if position > self.bytes.len() { self.bytes.resize(position, 0); }
        if end > self.bytes.len() { self.bytes.resize(end, 0); }
        self.bytes[position..end].copy_from_slice(source);
        self.position = end;
        Poll::Ready(Ok(source.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
}

impl AsyncSeek for BudgetSnapshotData {
    fn start_seek(mut self: Pin<&mut Self>, seek: SeekFrom) -> io::Result<()> {
        let (base, offset) = match seek {
            SeekFrom::Start(offset) => (0_i128, offset as i128),
            SeekFrom::Current(offset) => (self.position as i128, offset as i128),
            SeekFrom::End(offset) => (self.bytes.len() as i128, offset as i128),
        };
        let position = base.checked_add(offset).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "budget snapshot seek overflow"))?;
        if position < 0 || position > MAX_BUDGET_SNAPSHOT_BYTES as i128 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "budget snapshot seek outside configured maximum"));
        }
        self.position = position as usize;
        Ok(())
    }

    fn poll_complete(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<u64>> { Poll::Ready(Ok(self.position as u64)) }
}

openraft::declare_raft_types!(
    pub BudgetTypeConfig:
        D = BudgetCommand,
        R = BudgetReply,
        NodeId = u64,
        Node = openraft::BasicNode,
        Entry = openraft::Entry<BudgetTypeConfig>,
        SnapshotData = BudgetSnapshotData,
        AsyncRuntime = openraft::TokioRuntime,
);
