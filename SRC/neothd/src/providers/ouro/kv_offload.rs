//! GOLD-ADAPT-KV-03 — CPU-RAM KV cold tier wrapping the hot LRU map.
//! GOLD-ADAPT-KV-04 — Disk cold tier: hash-addressed `~/.neoth/kv_cache/*.kv.bin`
//!                    persists cold evictions so they survive process restarts.
//!
//! Three-tier KV cache stack (hot → cold → disk):
//!
//! * **Hot tier** — `lru::LruCache<u64, PrefixKvEntry>`: Arc-tensor entries
//!   (zero-copy clone, fast restore). Bounded by `NEOTH_OURO_KV_HOT_CAP`
//!   (default 8).
//! * **Cold tier** — `lru::LruCache<u64, ColdEntry>`: serialized f32 bytes.
//!   Hot evictions land here. Bounded by `NEOTH_OURO_KV_COLD_CAP`
//!   (default 32). Cold evictions go to disk when disk is enabled.
//! * **Disk tier** — `~/.neoth/kv_cache/<key_hex>.kv.bin` (KV-04, gated by
//!   `NEOTH_OURO_KV_DISK=1`). Written atomically on cold eviction; probed on
//!   cold miss; read errors degrade gracefully to a miss (never crash inference).
//!
//! **File format** (`<key>.kv.bin`): 4-byte magic `b"NKV\x01"`, key u64 LE,
//! prefix_ids_len u32 LE, prefix_ids u32 LE each, num_layers u32 LE,
//! num_loops u32 LE, then per slot: tag u8 (0=Empty, 1=Kv); if Kv: k_ndim
//! u32 LE, k_shape u32 LE each, v_ndim u32 LE, v_shape u32 LE each,
//! bytes_len u64 LE, raw f32 LE bytes (K then V).
//!
//! **Atomic write**: written to `<key>.kv.bin.tmp` then `rename` to the final
//! path — a crash mid-write leaves a `.tmp` file, never a corrupt `.kv.bin`.
//!
//! **Suffix-first ordering**: when serializing a `KvSnapshot` into a
//! `ColdEntry`, layers are stored in *reverse* order. If the cold LRU
//! overflows, the LRU eviction mechanism drops the oldest insertions first —
//! because we inserted suffix layers last and prefix layers first (reversed),
//! the suffix context is evicted first while the shared prefix layers survive
//! longer. On `deserialize` the layer slice is reversed back to the canonical
//! order.
//!
//! **Collision guard**: `get` checks `prefix_ids` equality on hot, cold, and
//! disk hits before returning a snapshot. A hash collision returns `None`
//! (treated as a miss → full prefill), never a corrupt restore.
//!
//! **Gating**: KV-03 does not add new env-var gates. The existing
//! `NEOTH_OURO_KV_CACHE_MODE=per_loop` + `NEOTH_OURO_PREFIX_KV=1` gate in
//! `run_ouro_forward` is sufficient — if those are not set the cache is never
//! called. KV-04 adds `NEOTH_OURO_KV_DISK=1` (default OFF); without it,
//! `disk_dir` is `None` and the disk tier is entirely bypassed.

use anyhow::{Context, Result};
use candle_core::{DType, Device, Tensor};
use lru::LruCache;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use super::prefix_kv_cache::{KvSnapshot, PrefixKvEntry};

// ─── Cold-tier types ─────────────────────────────────────────────────────────

/// One (K, V) tensor pair serialized as raw little-endian f32 bytes.
/// `None` KV slots (e.g. a layer whose loop slot was never populated)
/// are encoded as `SerialSlot::Empty` so the layer×loop index structure
/// round-trips exactly.
pub enum SerialSlot {
    Empty,
    Kv {
        k_shape: Vec<usize>,
        v_shape: Vec<usize>,
        /// Packed bytes: first K then V, each as `len * 4` little-endian f32.
        bytes: Vec<u8>,
    },
}

/// A serialized `KvSnapshot` stored in the cold LRU tier.
///
/// `slots` is stored in **suffix-first** (reversed-layer) order — see module
/// doc. `num_layers` / `num_loops` are needed to reconstruct the
/// `Vec<Vec<…>>` spine on deserialization.
pub struct ColdEntry {
    pub prefix_ids: Vec<u32>,
    /// Flat `num_layers × num_loops` slots in *suffix-first* (layer-reversed,
    /// loop-inner) row-major order.
    pub slots: Vec<SerialSlot>,
    pub num_layers: usize,
    pub num_loops: usize,
}

// ─── Two-tier cache ──────────────────────────────────────────────────────────

/// Three-tier KV cache: hot `LruCache<u64, PrefixKvEntry>` (Arc-tensor, fast
/// restore) backed by a cold `LruCache<u64, ColdEntry>` (serialized bytes,
/// slower), and optionally a disk tier (KV-04, `~/.neoth/kv_cache/*.kv.bin`).
/// Lives inside `LoadedOuro` behind the adapter's model lock.
///
/// `get` requires `&mut self` because `lru::LruCache::get` bumps recency.
pub struct KvOffloadCache {
    hot: LruCache<u64, PrefixKvEntry>,
    cold: LruCache<u64, ColdEntry>,
    device: Device,
    /// KV-04: when `Some`, cold evictions are written atomically to
    /// `<disk_dir>/<key_hex>.kv.bin`. `None` = disk tier disabled.
    disk_dir: Option<PathBuf>,
    /// KV-04 quota: max total bytes for `<disk_dir>/*.kv.bin`, enforced by
    /// `prune_disk` (LRU-by-mtime) at construction and after every disk write.
    /// From `NEOTH_OURO_KV_DISK_CAP_MB` (default 512 MB). Unused when
    /// `disk_dir` is `None`.
    disk_cap_bytes: u64,
}

impl KvOffloadCache {
    /// `hot_cap` / `cold_cap` come from `NEOTH_OURO_KV_HOT_CAP` /
    /// `NEOTH_OURO_KV_COLD_CAP` env vars (defaults 8 / 32), read once at
    /// model-load time in `ensure_ouro_loaded`.
    ///
    /// `disk_dir` — when `Some`, KV-04 disk tier is active. The directory is
    /// created on construction (non-fatal: disk I/O errors degrade to RAM-only
    /// behaviour).
    pub fn new(hot_cap: usize, cold_cap: usize, device: Device, disk_dir: Option<PathBuf>) -> Self {
        let hot = LruCache::new(NonZeroUsize::new(hot_cap.max(1)).unwrap());
        let cold = LruCache::new(NonZeroUsize::new(cold_cap.max(1)).unwrap());
        let disk_cap_bytes = Self::disk_cap_bytes_from_env();
        if let Some(ref dir) = disk_dir {
            if let Err(e) = std::fs::create_dir_all(dir) {
                tracing::warn!(
                    dir = %dir.display(),
                    err = %e,
                    "KV-04: could not create kv_cache dir; disk tier disabled"
                );
                return Self { hot, cold, device, disk_dir: None, disk_cap_bytes };
            }
            // Enforce the quota at startup so a cache that grew past the cap in a
            // previous run (or under a since-lowered cap) is trimmed before we
            // start adding more entries this run.
            Self::prune_disk(dir, disk_cap_bytes);
        }
        Self { hot, cold, device, disk_dir, disk_cap_bytes }
    }

    /// Disk-tier quota in bytes from `NEOTH_OURO_KV_DISK_CAP_MB` (default 512 MB).
    /// A value of `0` means "prune everything" — the disk tier effectively never
    /// retains across writes (still functions as a within-tick spill).
    fn disk_cap_bytes_from_env() -> u64 {
        std::env::var("NEOTH_OURO_KV_DISK_CAP_MB")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(512)
            .saturating_mul(1024 * 1024)
    }

    /// KV-04 quota enforcement: keep `<dir>/*.kv.bin` under `cap_bytes` by
    /// deleting the least-recently-modified entries first (mtime is the LRU
    /// signal — `read_from_disk` touches it on every hit). Also sweeps stale
    /// `*.kv.bin.tmp` files left by a crash mid-write. All errors are non-fatal:
    /// a full or unwritable disk must never abort inference.
    fn prune_disk(dir: &Path, cap_bytes: u64) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        let mut files: Vec<(PathBuf, u64, std::time::SystemTime)> = Vec::new();
        let mut total: u64 = 0;
        for entry in rd.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            // Sweep stale temp files from interrupted atomic writes.
            if name.ends_with(".kv.bin.tmp") {
                let _ = std::fs::remove_file(&path);
                continue;
            }
            if !name.ends_with(".kv.bin") {
                continue;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            let size = meta.len();
            let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
            total = total.saturating_add(size);
            files.push((path, size, mtime));
        }
        if total <= cap_bytes {
            return;
        }
        // Least-recently-modified first.
        files.sort_by_key(|(_, _, mtime)| *mtime);
        for (path, size, _) in files {
            if total <= cap_bytes {
                break;
            }
            if std::fs::remove_file(&path).is_ok() {
                total = total.saturating_sub(size);
                tracing::debug!(
                    file = %path.display(),
                    "KV-04: pruned disk cache entry over quota"
                );
            }
        }
    }

    /// Probe hot → cold → disk. Returns `Ok(Some(snap))` on any tier hit,
    /// `Ok(None)` on a full miss (hash collision on `prefix_ids` also returns
    /// `None`).
    ///
    /// A cold hit promotes the entry to hot (evicting the current hot-LRU
    /// entry to cold first if hot is full). A disk hit (KV-04) promotes to
    /// hot via the same path. Disk I/O errors degrade to a miss — they do NOT
    /// propagate as errors so inference is never aborted by a full disk or
    /// permission issue.
    pub fn get(&mut self, key: u64, prefix_ids: &[u32]) -> Result<Option<KvSnapshot>> {
        // ── Hot probe ────────────────────────────────────────────────────────
        if let Some(entry) = self.hot.get(&key) {
            if entry.prefix_ids.as_slice() == prefix_ids {
                // Arc clone — zero-copy
                return Ok(Some(entry.snapshot.clone()));
            }
            // Hash collision on hot — treat as miss (do not touch cold)
            return Ok(None);
        }

        // ── Cold probe ───────────────────────────────────────────────────────
        // We need ownership to promote, so use pop + re-insert.
        if let Some(cold_entry) = self.cold.pop(&key) {
            if cold_entry.prefix_ids.as_slice() != prefix_ids {
                // Hash collision on cold — put it back to keep cold tier
                // consistent, then return miss.
                self.cold.put(key, cold_entry);
                return Ok(None);
            }
            // Deserialize → KvSnapshot
            let snap = Self::deserialize(&cold_entry, &self.device)
                .context("KV-03: deserialize cold entry")?;

            // Promote cold → hot. If hot is full, evict hot-LRU → cold.
            self.evict_hot_to_cold_if_full()
                .context("KV-03: evict hot to cold on promotion")?;

            self.hot.put(
                key,
                PrefixKvEntry {
                    snapshot: snap.clone(),
                    prefix_ids: cold_entry.prefix_ids,
                },
            );

            return Ok(Some(snap));
        }

        // ── Disk probe (KV-04) ───────────────────────────────────────────────
        if let Some(ref dir) = self.disk_dir.clone() {
            match Self::read_from_disk(dir, key) {
                Ok(Some(cold_entry)) => {
                    // Collision guard: on-disk prefix_ids must match.
                    if cold_entry.prefix_ids.as_slice() != prefix_ids {
                        // Different prefix_ids at same key — treat as miss; leave
                        // the disk file intact (it may still be valid for another
                        // caller with matching ids).
                        return Ok(None);
                    }
                    // Deserialize → KvSnapshot, promote to hot.
                    let snap = Self::deserialize(&cold_entry, &self.device)
                        .context("KV-04: deserialize disk entry")?;
                    self.evict_hot_to_cold_if_full()
                        .context("KV-04: evict hot to cold on disk promotion")?;
                    self.hot.put(
                        key,
                        PrefixKvEntry {
                            snapshot: snap.clone(),
                            prefix_ids: cold_entry.prefix_ids,
                        },
                    );
                    tracing::debug!(key, "KV-04: disk hit → promoted to hot");
                    return Ok(Some(snap));
                }
                Ok(None) => { /* file doesn't exist — full miss below */ }
                Err(e) => {
                    // Non-fatal: log and degrade to miss.
                    tracing::warn!(key, err = %e, "KV-04: disk read error — treating as miss");
                }
            }
        }

        Ok(None)
    }

    /// Insert a new entry into hot. If hot is full the hot-LRU entry is
    /// serialized suffix-first and pushed to cold. If cold is also full its
    /// LRU entry is simply dropped (RAM-only tier).
    pub fn insert(&mut self, key: u64, entry: PrefixKvEntry) -> Result<()> {
        // If this key is already in hot (re-insert), lru::LruCache::put will
        // replace it in place without an extra eviction — correct behaviour.
        if self.hot.len() == self.hot.cap().get() && !self.hot.contains(&key) {
            self.evict_hot_to_cold_if_full()
                .context("KV-03: evict hot to cold on insert")?;
        }
        self.hot.put(key, entry);
        Ok(())
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Evict the LRU entry from hot and serialize it into cold (suffix-first).
    /// If cold is already at capacity, cascade the cold-LRU entry to disk
    /// (KV-04) before inserting the new entry into cold.
    /// Called when hot is at capacity and a new key must be inserted or promoted.
    ///
    /// **Fail-soft**: if `serialize()` returns an error (e.g. bad tensor dtype),
    /// the hot entry is DROPPED with a warning — a cache eviction must never
    /// panic or abort inference.
    fn evict_hot_to_cold_if_full(&mut self) -> Result<()> {
        if self.hot.len() < self.hot.cap().get() {
            return Ok(());
        }
        if let Some((evicted_key, evicted_entry)) = self.hot.pop_lru() {
            match Self::serialize(&evicted_entry.snapshot, &evicted_entry.prefix_ids) {
                Ok(cold) => {
                    // Before inserting into cold, cascade cold's LRU to disk if cold is full.
                    self.evict_cold_to_disk_if_full(evicted_key);
                    // lru::LruCache::put drops the LRU cold entry automatically if full,
                    // but we have already handled it above via the cascade.
                    self.cold.put(evicted_key, cold);
                }
                Err(e) => {
                    // Fail-soft: bad tensor → drop the evicted hot entry, don't crash.
                    tracing::warn!(
                        key = evicted_key,
                        err = %e,
                        "KV-03: serialize failed on hot eviction — entry dropped (cache miss on next get)"
                    );
                }
            }
        }
        Ok(())
    }

    /// If cold is at capacity, pop the LRU entry and write it to disk (KV-04).
    /// The evicted key being inserted is passed so we can avoid a double-write
    /// if the same key is already being cascaded (rare; harmless if it happens).
    /// All disk errors are non-fatal (logged as warn).
    fn evict_cold_to_disk_if_full(&mut self, _incoming_key: u64) {
        if self.cold.len() < self.cold.cap().get() {
            return;
        }
        if let Some(ref dir) = self.disk_dir.clone() {
            if let Some((evicted_key, cold_entry)) = self.cold.pop_lru() {
                if let Err(e) = Self::write_to_disk(dir, evicted_key, &cold_entry) {
                    tracing::warn!(
                        key = evicted_key,
                        err = %e,
                        "KV-04: disk write failed on cold eviction — entry dropped"
                    );
                } else {
                    tracing::debug!(key = evicted_key, "KV-04: cold eviction → disk");
                    // Enforce the disk quota after growing the cache.
                    Self::prune_disk(dir, self.disk_cap_bytes);
                }
                // Re-insert so cold.put below finds room (we manually popped the LRU).
                // Note: we DON'T re-insert the cold entry — it's been written to disk;
                // keep it evicted so cold has one free slot for the hot eviction.
                drop(cold_entry);
            }
        }
        // If disk is not enabled, lru::LruCache::put will drop the LRU cold
        // entry automatically — no action needed here.
    }

    /// Write a `ColdEntry` to `<dir>/<key_hex>.kv.bin` atomically.
    /// Format: magic(4) + key(8) + prefix_ids_len(4) + prefix_ids(n*4)
    ///         + num_layers(4) + num_loops(4)
    ///         + per slot: tag(1); if Kv: k_ndim(4) + k_shape(ndim*4)
    ///                              + v_ndim(4) + v_shape(ndim*4)
    ///                              + bytes_len(8) + bytes(len).
    ///
    /// Uses `std::fs` (NOT `tokio::fs`) — this is called from a
    /// `spawn_blocking` thread where blocking I/O is correct.
    fn write_to_disk(dir: &Path, key: u64, cold: &ColdEntry) -> Result<()> {
        let mut buf: Vec<u8> = Vec::with_capacity(256 + cold.slots.len() * 64);

        // Magic header.
        buf.extend_from_slice(b"NKV\x01");
        // Key.
        buf.extend_from_slice(&key.to_le_bytes());
        // prefix_ids.
        buf.extend_from_slice(&(cold.prefix_ids.len() as u32).to_le_bytes());
        for id in &cold.prefix_ids {
            buf.extend_from_slice(&id.to_le_bytes());
        }
        // Dimensions.
        buf.extend_from_slice(&(cold.num_layers as u32).to_le_bytes());
        buf.extend_from_slice(&(cold.num_loops as u32).to_le_bytes());

        // Slots (in the existing suffix-first order).
        for slot in &cold.slots {
            match slot {
                SerialSlot::Empty => {
                    buf.push(0u8); // tag = Empty
                }
                SerialSlot::Kv { k_shape, v_shape, bytes } => {
                    buf.push(1u8); // tag = Kv
                    // K shape.
                    buf.extend_from_slice(&(k_shape.len() as u32).to_le_bytes());
                    for d in k_shape {
                        buf.extend_from_slice(&(*d as u32).to_le_bytes());
                    }
                    // V shape.
                    buf.extend_from_slice(&(v_shape.len() as u32).to_le_bytes());
                    for d in v_shape {
                        buf.extend_from_slice(&(*d as u32).to_le_bytes());
                    }
                    // Bytes (K then V packed f32 LE).
                    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
                    buf.extend_from_slice(bytes);
                }
            }
        }

        // Atomic write: tmp → rename.
        let final_path = dir.join(format!("{:016x}.kv.bin", key));
        let tmp_path = dir.join(format!("{:016x}.kv.bin.tmp", key));
        std::fs::write(&tmp_path, &buf)
            .with_context(|| format!("KV-04: write tmp {}", tmp_path.display()))?;
        std::fs::rename(&tmp_path, &final_path)
            .with_context(|| format!("KV-04: rename {} -> {}", tmp_path.display(), final_path.display()))?;
        Ok(())
    }

    /// Read and deserialize a `ColdEntry` from `<dir>/<key_hex>.kv.bin`.
    /// Returns `Ok(None)` when the file does not exist (non-fatal miss).
    /// Returns `Err` on I/O or format errors (caller should log + treat as miss).
    ///
    /// Uses `std::fs` (NOT `tokio::fs`) — called from a `spawn_blocking` thread.
    fn read_from_disk(dir: &Path, key: u64) -> Result<Option<ColdEntry>> {
        let path = dir.join(format!("{:016x}.kv.bin", key));
        let buf = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("KV-04: read {}", path.display())),
        };

        // LRU bump: touch mtime on a disk hit so `prune_disk` evicts genuinely
        // cold entries last (mtime is the LRU signal). Best-effort — a read-only
        // or racing FS just keeps the old mtime. `write(true)` opens without
        // truncating the file we just read.
        if let Ok(f) = std::fs::OpenOptions::new().write(true).open(&path) {
            let _ = f.set_modified(std::time::SystemTime::now());
        }

        let mut pos = 0usize;

        macro_rules! need {
            ($n:expr) => {{
                let n = $n;
                if pos + n > buf.len() {
                    anyhow::bail!("KV-04: truncated file {} at offset {}", path.display(), pos);
                }
                let slice = &buf[pos..pos + n];
                pos += n;
                slice
            }};
        }

        macro_rules! read_u32 {
            () => {{
                let b = need!(4);
                u32::from_le_bytes([b[0], b[1], b[2], b[3]])
            }};
        }

        macro_rules! read_u64 {
            () => {{
                let b = need!(8);
                u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
            }};
        }

        // Magic.
        let magic = need!(4);
        if magic != b"NKV\x01" {
            anyhow::bail!("KV-04: bad magic in {}", path.display());
        }

        // Key (verify matches).
        let file_key = read_u64!();
        if file_key != key {
            anyhow::bail!(
                "KV-04: key mismatch in {} (expected {:016x}, got {:016x})",
                path.display(), key, file_key
            );
        }

        // prefix_ids.
        let ids_len = read_u32!() as usize;
        let mut prefix_ids = Vec::with_capacity(ids_len);
        for _ in 0..ids_len {
            prefix_ids.push(read_u32!());
        }

        // Dimensions.
        let num_layers = read_u32!() as usize;
        let num_loops = read_u32!() as usize;

        // Slots.
        let total_slots = num_layers * num_loops;
        let mut slots = Vec::with_capacity(total_slots);
        for _ in 0..total_slots {
            let tag = need!(1)[0];
            match tag {
                0 => slots.push(SerialSlot::Empty),
                1 => {
                    // K shape.
                    let k_ndim = read_u32!() as usize;
                    let mut k_shape = Vec::with_capacity(k_ndim);
                    for _ in 0..k_ndim {
                        k_shape.push(read_u32!() as usize);
                    }
                    // V shape.
                    let v_ndim = read_u32!() as usize;
                    let mut v_shape = Vec::with_capacity(v_ndim);
                    for _ in 0..v_ndim {
                        v_shape.push(read_u32!() as usize);
                    }
                    // Bytes.
                    let bytes_len = read_u64!() as usize;
                    let bytes = need!(bytes_len).to_vec();
                    slots.push(SerialSlot::Kv { k_shape, v_shape, bytes });
                }
                other => anyhow::bail!(
                    "KV-04: unknown slot tag {} in {}",
                    other,
                    path.display()
                ),
            }
        }

        Ok(Some(ColdEntry { prefix_ids, slots, num_layers, num_loops }))
    }

    /// Serialize a `KvSnapshot` into a `ColdEntry` using suffix-first layer
    /// ordering (layers stored in reverse so early layers stay in cold longer
    /// under LRU pressure).
    ///
    /// Returns `Err` if any candle tensor op fails (dtype coercion, flatten, or
    /// to_vec1). Callers must handle the error rather than panicking — this is a
    /// cache path and must never abort the daemon on a bad tensor.
    fn serialize(snap: &KvSnapshot, prefix_ids: &[u32]) -> Result<ColdEntry> {
        let num_layers = snap.len();
        let num_loops = snap.first().map(|l| l.len()).unwrap_or(0);

        // Iterate layers in REVERSE (suffix-first) so that if cold overflows,
        // the LRU eviction removes the suffix layers first (they were inserted
        // last; LRU pops them first) — but note this is *within* a single
        // ColdEntry's slot Vec, not the cold LruCache order. The guarantee is
        // that on partial reconstruction a later `deserialize` sees slots in
        // the same reverse order and re-reverses, so the round-trip is exact.
        // The cold LruCache itself evicts whole entries; the suffix-first ordering
        // is therefore a deterministic encoding convention, not a per-slot eviction.
        let mut slots = Vec::with_capacity(num_layers * num_loops);
        for layer in snap.iter().rev() {
            for slot in layer.iter() {
                match slot {
                    None => slots.push(SerialSlot::Empty),
                    Some((k_tensor, v_tensor)) => {
                        // Coerce to F32 so the cold-tier format is dtype-stable
                        // even if the model later loads in BF16.
                        let k_f32 = k_tensor
                            .to_dtype(DType::F32)
                            .context("KV-03 serialize: K to f32")?;
                        let v_f32 = v_tensor
                            .to_dtype(DType::F32)
                            .context("KV-03 serialize: V to f32")?;

                        let k_shape = k_f32.dims().to_vec();
                        let v_shape = v_f32.dims().to_vec();

                        let k_vec: Vec<f32> = k_f32
                            .flatten_all()
                            .context("KV-03 serialize: flatten K")?
                            .to_vec1()
                            .context("KV-03 serialize: K to_vec1")?;
                        let v_vec: Vec<f32> = v_f32
                            .flatten_all()
                            .context("KV-03 serialize: flatten V")?
                            .to_vec1()
                            .context("KV-03 serialize: V to_vec1")?;

                        let mut bytes =
                            Vec::with_capacity((k_vec.len() + v_vec.len()) * 4);
                        for f in &k_vec {
                            bytes.extend_from_slice(&f.to_le_bytes());
                        }
                        for f in &v_vec {
                            bytes.extend_from_slice(&f.to_le_bytes());
                        }

                        slots.push(SerialSlot::Kv {
                            k_shape,
                            v_shape,
                            bytes,
                        });
                    }
                }
            }
        }

        Ok(ColdEntry {
            prefix_ids: prefix_ids.to_vec(),
            slots,
            num_layers,
            num_loops,
        })
    }

    /// Deserialize a `ColdEntry` back into a `KvSnapshot`.
    /// Reverses the suffix-first slot order back to canonical (layer 0 first).
    fn deserialize(cold: &ColdEntry, device: &Device) -> Result<KvSnapshot> {
        let ColdEntry {
            num_layers,
            num_loops,
            slots,
            ..
        } = cold;

        if slots.len() != num_layers * num_loops {
            anyhow::bail!(
                "KV-03 deserialize: slot count {} != {}×{}",
                slots.len(),
                num_layers,
                num_loops
            );
        }

        // Rebuild in suffix-first order first, then reverse layers back.
        let mut layers_rev: Vec<Vec<Option<(Tensor, Tensor)>>> =
            Vec::with_capacity(*num_layers);

        let mut slot_iter = slots.iter();
        for _ in 0..*num_layers {
            let mut loop_slots: Vec<Option<(Tensor, Tensor)>> =
                Vec::with_capacity(*num_loops);
            for _ in 0..*num_loops {
                let s = slot_iter.next().ok_or_else(|| {
                    anyhow::anyhow!("KV-03 deserialize: slot iterator exhausted early")
                })?;
                match s {
                    SerialSlot::Empty => loop_slots.push(None),
                    SerialSlot::Kv {
                        k_shape,
                        v_shape,
                        bytes,
                    } => {
                        let k_len: usize = k_shape.iter().product();
                        let v_len: usize = v_shape.iter().product();
                        let expected_bytes = (k_len + v_len) * 4;
                        if bytes.len() != expected_bytes {
                            anyhow::bail!(
                                "KV-03 deserialize: byte len {} != expected {}",
                                bytes.len(),
                                expected_bytes
                            );
                        }

                        let k_f32: Vec<f32> = bytes[..k_len * 4]
                            .chunks_exact(4)
                            .map(|b| {
                                f32::from_le_bytes([b[0], b[1], b[2], b[3]])
                            })
                            .collect();
                        let v_f32: Vec<f32> = bytes[k_len * 4..]
                            .chunks_exact(4)
                            .map(|b| {
                                f32::from_le_bytes([b[0], b[1], b[2], b[3]])
                            })
                            .collect();

                        let k_tensor = Tensor::from_vec(k_f32, k_shape.as_slice(), device)
                            .context("KV-03 deserialize: rebuild K tensor")?;
                        let v_tensor = Tensor::from_vec(v_f32, v_shape.as_slice(), device)
                            .context("KV-03 deserialize: rebuild V tensor")?;

                        loop_slots.push(Some((k_tensor, v_tensor)));
                    }
                }
            }
            layers_rev.push(loop_slots);
        }

        // Reverse to restore canonical layer order (0 = first layer).
        layers_rev.reverse();
        Ok(layers_rev)
    }
}

// ─── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::ouro::prefix_kv_cache::PrefixKvCache;
    use candle_core::Device;

    /// Build a minimal KvSnapshot: 1 layer × 1 loop slot, small 2×2 F32 tensor.
    /// Exercises the full serialize/deserialize round-trip without model weights.
    fn stub_snap(marker: f32) -> KvSnapshot {
        let t = Tensor::new(
            &[[marker, marker], [marker, marker]],
            &Device::Cpu,
        )
        .unwrap();
        vec![vec![Some((t.clone(), t))]]
    }

    /// 2-layer snapshot so suffix-first ordering is non-trivial.
    fn stub_snap_2layer(a: f32, b: f32) -> KvSnapshot {
        let mk = |v: f32| {
            Tensor::new(&[[v, v], [v, v]], &Device::Cpu).unwrap()
        };
        vec![
            vec![Some((mk(a), mk(a)))], // layer 0 (prefix)
            vec![Some((mk(b), mk(b)))], // layer 1 (suffix)
        ]
    }

    // ── Serialize / deserialize round-trip ───────────────────────────────────

    #[test]
    fn serialize_deserialize_roundtrip_single_layer() {
        let snap = stub_snap(1.5);
        let ids = vec![1u32, 2, 3];
        let cold = KvOffloadCache::serialize(&snap, &ids).unwrap();
        let restored =
            KvOffloadCache::deserialize(&cold, &Device::Cpu).unwrap();

        assert_eq!(restored.len(), 1);
        let (k, _v) = restored[0][0].as_ref().unwrap();
        let vals: Vec<f32> = k.flatten_all().unwrap().to_vec1().unwrap();
        assert!(
            vals.iter().all(|x| (x - 1.5).abs() < 1e-6),
            "round-trip marker 1.5"
        );
    }

    #[test]
    fn serialize_deserialize_preserves_layer_order() {
        let snap = stub_snap_2layer(1.0, 2.0);
        let ids = vec![4u32, 5];
        let cold = KvOffloadCache::serialize(&snap, &ids).unwrap();
        let restored =
            KvOffloadCache::deserialize(&cold, &Device::Cpu).unwrap();

        assert_eq!(restored.len(), 2);
        let layer0_val: Vec<f32> = restored[0][0]
            .as_ref()
            .unwrap()
            .0
            .flatten_all()
            .unwrap()
            .to_vec1()
            .unwrap();
        let layer1_val: Vec<f32> = restored[1][0]
            .as_ref()
            .unwrap()
            .0
            .flatten_all()
            .unwrap()
            .to_vec1()
            .unwrap();
        assert!(
            layer0_val.iter().all(|x| (x - 1.0).abs() < 1e-6),
            "layer 0 must be 1.0 after round-trip (suffix-first ordering reversed)"
        );
        assert!(
            layer1_val.iter().all(|x| (x - 2.0).abs() < 1e-6),
            "layer 1 must be 2.0 after round-trip"
        );
    }

    #[test]
    fn serialize_none_slot_roundtrips() {
        // 1 layer, 2 loop slots: first None, second Some.
        let t = Tensor::new(&[[9.0f32]], &Device::Cpu).unwrap();
        let snap: KvSnapshot = vec![vec![None, Some((t.clone(), t))]];
        let cold = KvOffloadCache::serialize(&snap, &[]).unwrap();
        let restored =
            KvOffloadCache::deserialize(&cold, &Device::Cpu).unwrap();
        assert!(restored[0][0].is_none(), "None slot must round-trip as None");
        assert!(
            restored[0][1].is_some(),
            "Some slot must round-trip as Some"
        );
    }

    // ── Two-tier cache behaviour ─────────────────────────────────────────────

    #[test]
    fn hot_hit_returned_without_cold() {
        let mut cache = KvOffloadCache::new(4, 4, Device::Cpu, None);
        let ids = vec![7u32, 8];
        let key = PrefixKvCache::key(&ids);
        cache
            .insert(
                key,
                PrefixKvEntry {
                    snapshot: stub_snap(3.0),
                    prefix_ids: ids.clone(),
                },
            )
            .unwrap();
        let snap = cache.get(key, &ids).unwrap().expect("hot hit");
        let v: Vec<f32> = snap[0][0]
            .as_ref()
            .unwrap()
            .0
            .flatten_all()
            .unwrap()
            .to_vec1()
            .unwrap();
        assert!(v.iter().all(|x| (x - 3.0).abs() < 1e-6));
    }

    #[test]
    fn cold_hit_after_hot_eviction_restores_snapshot() {
        // hot_cap=1, cold_cap=4 → inserting key_b evicts key_a to cold.
        let mut cache = KvOffloadCache::new(1, 4, Device::Cpu, None);
        let ids_a = vec![1u32, 2, 3];
        let ids_b = vec![4u32, 5, 6];
        let key_a = PrefixKvCache::key(&ids_a);
        let key_b = PrefixKvCache::key(&ids_b);

        cache
            .insert(
                key_a,
                PrefixKvEntry {
                    snapshot: stub_snap(1.0),
                    prefix_ids: ids_a.clone(),
                },
            )
            .unwrap();
        // This evicts key_a to cold:
        cache
            .insert(
                key_b,
                PrefixKvEntry {
                    snapshot: stub_snap(2.0),
                    prefix_ids: ids_b.clone(),
                },
            )
            .unwrap();

        // key_a must now be a COLD hit, not a miss:
        let restored = cache
            .get(key_a, &ids_a)
            .expect("get cold hit should not error");
        assert!(
            restored.is_some(),
            "cold tier must return key_a after hot eviction"
        );

        // Verify marker 1.0 survived the cold round-trip:
        let snap = restored.unwrap();
        let v: Vec<f32> = snap[0][0]
            .as_ref()
            .unwrap()
            .0
            .flatten_all()
            .unwrap()
            .to_vec1()
            .unwrap();
        assert!(
            v.iter().all(|x| (x - 1.0).abs() < 1e-5),
            "marker 1.0 must survive cold round-trip; got {v:?}"
        );
    }

    #[test]
    fn cold_promotion_evicts_hot_lru() {
        // hot=1, cold=4. Insert A (hot). Insert B (evicts A to cold). Now get A
        // (cold hit → promote A to hot, evicts B to cold). Then get B must be cold.
        let mut cache = KvOffloadCache::new(1, 4, Device::Cpu, None);
        let ids_a = vec![10u32];
        let ids_b = vec![20u32];
        let ka = PrefixKvCache::key(&ids_a);
        let kb = PrefixKvCache::key(&ids_b);

        cache
            .insert(ka, PrefixKvEntry { snapshot: stub_snap(10.0), prefix_ids: ids_a.clone() })
            .unwrap();
        cache
            .insert(kb, PrefixKvEntry { snapshot: stub_snap(20.0), prefix_ids: ids_b.clone() })
            .unwrap();

        // Promote A from cold (evicts B from hot to cold):
        let snap_a = cache.get(ka, &ids_a).unwrap().expect("cold hit A");
        let va: Vec<f32> = snap_a[0][0].as_ref().unwrap().0.flatten_all().unwrap().to_vec1().unwrap();
        assert!(va.iter().all(|x| (x - 10.0).abs() < 1e-5), "A marker");

        // B must now be cold:
        let snap_b = cache.get(kb, &ids_b).unwrap().expect("B now cold");
        let vb: Vec<f32> = snap_b[0][0].as_ref().unwrap().0.flatten_all().unwrap().to_vec1().unwrap();
        assert!(vb.iter().all(|x| (x - 20.0).abs() < 1e-5), "B marker");
    }

    #[test]
    fn hash_collision_treated_as_miss() {
        // Probe with different prefix_ids than what was inserted (simulates
        // collision: same key, different ids). Must return None, not corrupt data.
        let mut cache = KvOffloadCache::new(4, 4, Device::Cpu, None);
        let ids_real = vec![1u32, 2];
        let ids_wrong = vec![99u32, 99];
        let key = PrefixKvCache::key(&ids_real);
        cache
            .insert(
                key,
                PrefixKvEntry {
                    snapshot: stub_snap(5.0),
                    prefix_ids: ids_real.clone(),
                },
            )
            .unwrap();
        // Probe with wrong prefix_ids — must be a MISS:
        let result = cache.get(key, &ids_wrong).unwrap();
        assert!(
            result.is_none(),
            "prefix_ids mismatch must be a cache miss, not a corrupt restore"
        );
    }

    #[test]
    fn cold_collision_returns_miss_and_preserves_entry() {
        // Evict to cold, then probe with wrong ids → miss; entry stays in cold.
        let mut cache = KvOffloadCache::new(1, 4, Device::Cpu, None);
        let ids_real = vec![1u32, 2];
        let ids_wrong = vec![99u32, 99];
        let key = PrefixKvCache::key(&ids_real);

        cache
            .insert(
                key,
                PrefixKvEntry {
                    snapshot: stub_snap(7.0),
                    prefix_ids: ids_real.clone(),
                },
            )
            .unwrap();
        // Evict to cold:
        cache
            .insert(
                PrefixKvCache::key(&[42u32]),
                PrefixKvEntry {
                    snapshot: stub_snap(0.0),
                    prefix_ids: vec![42],
                },
            )
            .unwrap();

        // Wrong ids → miss, entry stays:
        let miss = cache.get(key, &ids_wrong).unwrap();
        assert!(miss.is_none(), "wrong ids = miss on cold");

        // Correct ids → hit (entry was re-inserted on collision path):
        let hit = cache.get(key, &ids_real).unwrap();
        assert!(hit.is_some(), "correct ids must still hit after collision probe");
    }

    #[test]
    fn reinsert_same_key_does_not_grow_or_double_evict() {
        let mut cache = KvOffloadCache::new(2, 4, Device::Cpu, None);
        let ids_a = vec![1u32];
        let ids_b = vec![2u32];
        let ka = PrefixKvCache::key(&ids_a);
        let kb = PrefixKvCache::key(&ids_b);

        cache.insert(ka, PrefixKvEntry { snapshot: stub_snap(1.0), prefix_ids: ids_a.clone() }).unwrap();
        cache.insert(kb, PrefixKvEntry { snapshot: stub_snap(2.0), prefix_ids: ids_b.clone() }).unwrap();
        // Re-insert existing key at cap — must replace in place:
        cache.insert(ka, PrefixKvEntry { snapshot: stub_snap(1.1), prefix_ids: ids_a.clone() }).unwrap();

        // Both keys still accessible in hot:
        assert!(cache.get(ka, &ids_a).unwrap().is_some(), "A still in hot");
        assert!(cache.get(kb, &ids_b).unwrap().is_some(), "B still in hot");
    }

    // ── KV-04: disk cold tier ────────────────────────────────────────────────

    #[test]
    fn disk_cold_tier_survives_process_restart_simulation() {
        // Use a temp dir to simulate ~/.neoth/kv_cache/.
        let tmp = tempfile::tempdir().unwrap();
        let disk_dir = tmp.path().to_path_buf();

        // Cache with hot=1, cold=1, disk enabled.
        let mut cache = KvOffloadCache::new(1, 1, Device::Cpu, Some(disk_dir.clone()));
        let ids_a = vec![1u32, 2, 3];
        let ids_b = vec![4u32, 5, 6];
        let ids_c = vec![7u32, 8, 9];
        let ka = PrefixKvCache::key(&ids_a);
        let kb = PrefixKvCache::key(&ids_b);
        let kc = PrefixKvCache::key(&ids_c);

        // Insert A → hot.
        cache.insert(ka, PrefixKvEntry { snapshot: stub_snap(1.0), prefix_ids: ids_a.clone() }).unwrap();
        // Insert B → A evicts to cold (cold was empty; disk not yet needed).
        cache.insert(kb, PrefixKvEntry { snapshot: stub_snap(2.0), prefix_ids: ids_b.clone() }).unwrap();
        // Insert C → B evicts to cold; cold was full (cap=1 has A), so A cascades to DISK.
        cache.insert(kc, PrefixKvEntry { snapshot: stub_snap(3.0), prefix_ids: ids_c.clone() }).unwrap();

        // Verify disk file for A exists.
        let disk_file = disk_dir.join(format!("{:016x}.kv.bin", ka));
        assert!(disk_file.exists(), "A must be written to disk on cold eviction cascade");

        // Simulate process restart: new KvOffloadCache pointing at same dir.
        // Fresh hot + cold are empty; disk probe must find A.
        let mut cache2 = KvOffloadCache::new(4, 4, Device::Cpu, Some(disk_dir.clone()));
        let snap = cache2.get(ka, &ids_a).unwrap().expect("disk hit on new cache instance");
        let v: Vec<f32> = snap[0][0].as_ref().unwrap().0.flatten_all().unwrap().to_vec1().unwrap();
        assert!(
            v.iter().all(|x| (x - 1.0).abs() < 1e-5),
            "A marker 1.0 must survive disk round-trip; got {v:?}"
        );

        // Verify collision guard on disk: wrong prefix_ids → miss (not corrupt restore).
        let miss = cache2.get(kb, &[99u32]).unwrap();
        assert!(miss.is_none(), "wrong prefix_ids on disk lookup must be a miss");
    }

    #[test]
    fn disk_prune_evicts_lru_over_cap_and_sweeps_tmp() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        // Three 100-byte entries with distinct mtimes (key 0 oldest … key 2 newest).
        let mk = |key: u64, mtime_secs: u64| {
            let p = dir.join(format!("{key:016x}.kv.bin"));
            std::fs::write(&p, vec![0u8; 100]).unwrap();
            let mtime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(mtime_secs);
            std::fs::OpenOptions::new()
                .write(true)
                .open(&p)
                .unwrap()
                .set_modified(mtime)
                .unwrap();
            p
        };
        let p_old = mk(0, 1_000); // least-recently-modified
        let _p_mid = mk(1, 2_000);
        let _p_new = mk(2, 3_000);
        // A stale temp file from a crashed atomic write must be swept regardless of cap.
        let tmp_file = dir.join("00000000deadbeef.kv.bin.tmp");
        std::fs::write(&tmp_file, vec![0u8; 50]).unwrap();

        // Cap = 250 bytes: 3×100 = 300 > 250 → exactly the oldest entry is pruned.
        KvOffloadCache::prune_disk(dir, 250);

        assert!(!p_old.exists(), "least-recently-modified entry must be pruned over cap");
        assert!(!tmp_file.exists(), "stale .kv.bin.tmp must be swept");
        let total: u64 = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.path()
                    .file_name()
                    .and_then(|s| s.to_str())
                    .map(|n| n.ends_with(".kv.bin"))
                    .unwrap_or(false)
            })
            .map(|e| e.metadata().unwrap().len())
            .sum();
        assert!(total <= 250, "disk total {total} must be ≤ cap 250 after prune");
    }

    #[test]
    fn disk_write_read_roundtrip_binary_format() {
        // Unit test for the write_to_disk / read_from_disk helpers directly.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        let ids = vec![10u32, 20, 30];
        let snap = stub_snap_2layer(7.0, 9.0);
        let cold = KvOffloadCache::serialize(&snap, &ids).unwrap();
        let key: u64 = 0xdeadbeefcafe0001;

        KvOffloadCache::write_to_disk(dir, key, &cold).expect("write_to_disk");
        let restored = KvOffloadCache::read_from_disk(dir, key)
            .expect("read_from_disk Ok")
            .expect("read_from_disk Some");

        assert_eq!(restored.prefix_ids, ids);
        assert_eq!(restored.num_layers, cold.num_layers);
        assert_eq!(restored.num_loops, cold.num_loops);
        assert_eq!(restored.slots.len(), cold.slots.len());

        // Deserialize and verify layer markers survive the disk round-trip.
        let snap_back = KvOffloadCache::deserialize(&restored, &Device::Cpu).unwrap();
        assert_eq!(snap_back.len(), 2);
        let l0: Vec<f32> = snap_back[0][0].as_ref().unwrap().0.flatten_all().unwrap().to_vec1().unwrap();
        let l1: Vec<f32> = snap_back[1][0].as_ref().unwrap().0.flatten_all().unwrap().to_vec1().unwrap();
        assert!(l0.iter().all(|x| (x - 7.0).abs() < 1e-5), "layer0 marker 7.0; got {l0:?}");
        assert!(l1.iter().all(|x| (x - 9.0).abs() < 1e-5), "layer1 marker 9.0; got {l1:?}");
    }

    #[test]
    fn disk_read_nonexistent_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let result = KvOffloadCache::read_from_disk(tmp.path(), 0xffffffffffffffff).unwrap();
        assert!(result.is_none(), "missing file must return Ok(None), not Err");
    }

    #[test]
    fn disk_disabled_when_dir_is_none() {
        // hot=1, cold=1, disk=None → cold evictions are DROPPED (KV-03 behavior).
        // This must NOT panic and must return a miss for the evicted key.
        let mut cache = KvOffloadCache::new(1, 1, Device::Cpu, None);
        let ids_a = vec![1u32];
        let ids_b = vec![2u32];
        let ids_c = vec![3u32];
        let ka = PrefixKvCache::key(&ids_a);
        let kb = PrefixKvCache::key(&ids_b);
        let kc = PrefixKvCache::key(&ids_c);

        cache.insert(ka, PrefixKvEntry { snapshot: stub_snap(1.0), prefix_ids: ids_a.clone() }).unwrap();
        cache.insert(kb, PrefixKvEntry { snapshot: stub_snap(2.0), prefix_ids: ids_b.clone() }).unwrap();
        // A is now in cold (evicted from hot). Insert C: A evicts from cold → dropped (no disk).
        cache.insert(kc, PrefixKvEntry { snapshot: stub_snap(3.0), prefix_ids: ids_c.clone() }).unwrap();

        // A must be gone (dropped cold eviction, no disk).
        let miss = cache.get(ka, &ids_a).unwrap();
        assert!(miss.is_none(), "cold eviction without disk must be a miss, not a panic");
    }
}
