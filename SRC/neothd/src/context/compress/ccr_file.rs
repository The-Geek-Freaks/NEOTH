//! GOLD-HR-10 — persistent, cross-process CCR store + savings metering.
//!
//! The in-memory [`super::ccr::InMemoryCcrStore`] only serves retrieval inside
//! the process that stashed the payload. For `neoth ctx retrieve <key>` to pull
//! a dropped block back from a *separate* CLI process — the headroom CCR
//! promise made real — the store must persist to disk. [`FileCcrStore`] writes
//! each payload to `<dir>/<key>.ccr` (the key is content-addressed
//! `[0-9a-f]{24}`, a safe filename), TTL-expires by mtime, and caps the entry
//! count. The daemon and the CLI point at the same `<home>/.neoth/ccr/` dir.
//!
//! [`record_savings`] / [`read_savings`] give `neoth ctx savings` a cheap,
//! race-free cumulative tally: every compressed block appends one
//! `before after` line to `<dir>/savings.log` (O_APPEND — no read-modify-write
//! race across the daemon + CLI), and the reader sums them.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::context::compress::ccr::{CcrStore, DEFAULT_CAPACITY, DEFAULT_TTL};

/// `<home>/.neoth/ccr/` resolved against HOME / USERPROFILE (matching the
/// convention in `memory::store::default_path`).
pub fn default_ccr_dir() -> PathBuf {
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|_| PathBuf::from("."));
    home.join(".neoth").join("ccr")
}

/// A CCR key is the content-addressed `[0-9a-f]{24}` produced by
/// `ccr::compute_key`. Reject anything else before it touches the filesystem —
/// a CLI-supplied key must never escape the store dir (no `../`, no separators).
fn is_valid_key(key: &str) -> bool {
    key.len() == 24
        && key
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Directory-backed, persistent [`CcrStore`].
pub struct FileCcrStore {
    dir: PathBuf,
    ttl: Duration,
    capacity: usize,
}

impl FileCcrStore {
    pub fn new(dir: PathBuf) -> Self {
        Self::at(dir, DEFAULT_CAPACITY, DEFAULT_TTL)
    }

    pub fn at(dir: PathBuf, capacity: usize, ttl: Duration) -> Self {
        Self {
            dir,
            ttl,
            capacity: capacity.max(1),
        }
    }

    fn path_for(&self, key: &str) -> Option<PathBuf> {
        if !is_valid_key(key) {
            return None;
        }
        Some(self.dir.join(format!("{key}.ccr")))
    }

    /// Evict the oldest entries (by mtime) until under capacity. Best-effort.
    fn evict_if_over_capacity(&self) {
        let mut entries: Vec<(SystemTime, PathBuf)> = match fs::read_dir(&self.dir) {
            Ok(rd) => rd
                .flatten()
                .filter(|e| e.path().extension().is_some_and(|x| x == "ccr"))
                .filter_map(|e| {
                    let m = e.metadata().ok()?.modified().ok()?;
                    Some((m, e.path()))
                })
                .collect(),
            Err(_) => return,
        };
        if entries.len() <= self.capacity {
            return;
        }
        entries.sort_by_key(|(t, _)| *t); // oldest first
        let overflow = entries.len() - self.capacity;
        for (_, p) in entries.into_iter().take(overflow) {
            let _ = fs::remove_file(p);
        }
    }
}

impl CcrStore for FileCcrStore {
    fn put(&self, hash: &str, payload: &str) {
        let Some(path) = self.path_for(hash) else {
            return; // invalid key — never write outside the store dir
        };
        if fs::create_dir_all(&self.dir).is_err() {
            return;
        }
        // Atomic write: tmp + rename so a concurrent reader never sees a torn
        // file. The tmp name is keyed so two puts of distinct keys never clash.
        let tmp = self.dir.join(format!(".{hash}.tmp"));
        if fs::write(&tmp, payload.as_bytes()).is_ok() && fs::rename(&tmp, &path).is_err() {
            let _ = fs::remove_file(&tmp);
        }
        self.evict_if_over_capacity();
    }

    fn get(&self, hash: &str) -> Option<String> {
        let path = self.path_for(hash)?;
        let meta = fs::metadata(&path).ok()?;
        let modified = meta.modified().ok()?;
        if modified.elapsed().map(|e| e > self.ttl).unwrap_or(false) {
            let _ = fs::remove_file(&path); // lazy TTL expiry
            return None;
        }
        fs::read_to_string(&path).ok()
    }

    fn len(&self) -> usize {
        match fs::read_dir(&self.dir) {
            Ok(rd) => rd
                .flatten()
                .filter(|e| e.path().extension().is_some_and(|x| x == "ccr"))
                .count(),
            Err(_) => 0,
        }
    }
}

// ─── Savings metering ──────────────────────────────────────────────────

/// Cumulative compression savings read back from the append-log.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Savings {
    pub blocks: u64,
    pub bytes_before: u64,
    pub bytes_after: u64,
}

impl Savings {
    /// Bytes removed from the wire (before − after).
    pub fn bytes_saved(&self) -> u64 {
        self.bytes_before.saturating_sub(self.bytes_after)
    }
    /// Savings ratio in `0.0..=1.0` (0 when nothing recorded).
    pub fn ratio(&self) -> f64 {
        if self.bytes_before == 0 {
            0.0
        } else {
            self.bytes_saved() as f64 / self.bytes_before as f64
        }
    }
}

/// Append one `before after` record for a compressed block. Best-effort +
/// race-free (single O_APPEND write of a short line).
pub fn record_savings(dir: &Path, before: usize, after: usize) {
    if fs::create_dir_all(dir).is_err() {
        return;
    }
    let line = format!("{before} {after}\n");
    if let Ok(mut f) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("savings.log"))
    {
        let _ = f.write_all(line.as_bytes());
    }
}

/// Sum the savings log. Missing/empty log → all-zero.
pub fn read_savings(dir: &Path) -> Savings {
    let Ok(text) = fs::read_to_string(dir.join("savings.log")) else {
        return Savings::default();
    };
    let mut s = Savings::default();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        if let (Some(b), Some(a)) = (it.next(), it.next()) {
            if let (Ok(b), Ok(a)) = (b.parse::<u64>(), a.parse::<u64>()) {
                s.blocks += 1;
                s.bytes_before += b;
                s.bytes_after += a;
            }
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::compress::ccr::compute_key;

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("neoth_ccr_{}_{}", std::process::id(), tag));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn invalid_keys_rejected() {
        assert!(is_valid_key("0123456789abcdef01234567"));
        assert!(!is_valid_key("../etc/passwd"));
        assert!(!is_valid_key("0123456789ABCDEF01234567")); // uppercase
        assert!(!is_valid_key("short"));
        assert!(!is_valid_key("0123456789abcdef0123456")); // 23 chars
    }

    #[test]
    fn put_get_round_trips_on_disk() {
        let dir = temp_dir("rt");
        let store = FileCcrStore::new(dir.clone());
        let key = compute_key(b"the original payload");
        store.put(&key, "the original payload");
        assert_eq!(store.get(&key).as_deref(), Some("the original payload"));
        // A SECOND store at the same dir (simulating a separate process) sees it.
        let store2 = FileCcrStore::new(dir.clone());
        assert_eq!(store2.get(&key).as_deref(), Some("the original payload"));
        assert_eq!(store2.get("000000000000000000000000"), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn traversal_key_never_writes_outside_dir() {
        let dir = temp_dir("trav");
        let store = FileCcrStore::new(dir.clone());
        store.put("../escape", "evil");
        assert_eq!(store.get("../escape"), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ttl_expires_on_get() {
        let dir = temp_dir("ttl");
        let store = FileCcrStore::at(dir.clone(), 100, Duration::from_millis(10));
        let key = compute_key(b"x");
        store.put(&key, "x");
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(store.get(&key), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn capacity_evicts_oldest() {
        let dir = temp_dir("cap");
        let store = FileCcrStore::at(dir.clone(), 2, DEFAULT_TTL);
        for (i, payload) in ["a", "b", "c"].iter().enumerate() {
            let key = compute_key(payload.as_bytes());
            store.put(&key, payload);
            // Stagger mtimes so eviction order is deterministic.
            std::thread::sleep(Duration::from_millis(10));
            let _ = i;
        }
        assert!(store.len() <= 2);
        // The newest ("c") must survive.
        assert_eq!(store.get(&compute_key(b"c")).as_deref(), Some("c"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn savings_log_accumulates_across_writes() {
        let dir = temp_dir("sav");
        record_savings(&dir, 1000, 200);
        record_savings(&dir, 500, 100);
        let s = read_savings(&dir);
        assert_eq!(s.blocks, 2);
        assert_eq!(s.bytes_before, 1500);
        assert_eq!(s.bytes_after, 300);
        assert_eq!(s.bytes_saved(), 1200);
        assert!((s.ratio() - 0.8).abs() < 1e-9);
        // Missing log → zero.
        assert_eq!(read_savings(&temp_dir("none")), Savings::default());
        let _ = fs::remove_dir_all(&dir);
    }
}
