//! Persisted cluster peer registry — Phase 4 of the auto-discovery
//! SPEC. Operator-confirmed peers live in `~/.neoth/cluster.yaml`;
//! discovery (Phase 2 mDNS / Phase 3 Tailscale) surfaces candidates,
//! `neoth cluster confirm` promotes them into this registry, and
//! `revoke` removes them.
//!
//! Atomic .tmp + rename writes — mid-write crash leaves either the
//! prior good file OR the new good file, never a half-written one.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::discovery::DiscoveryVia;

/// Serialises every read-modify-write of the cluster registry within the
/// process so concurrent refresh tasks (RTT, stability, last-seen, the
/// pairing CLI) can't lose-update the whole-file load→mutate→save cycle
/// (COR-16 / A-43). The on-disk write is already atomic (`.tmp` + rename),
/// which prevents torn READS; this lock closes the read-modify-write race
/// on top of it. Two levels (GR-020):
/// - `REGISTRY_LOCK` (process-local Mutex): serializes the daemon's own
///   background tasks (heartbeat RTT, stability, last-seen, gossip).
/// - [`lock_registry_file`] (blocking OS file lock on `cluster.yaml.lock`):
///   serializes against `neoth cluster confirm`/`revoke` CLI invocations,
///   which are SEPARATE processes — the old "one daemon per host makes a
///   process-wide lock sufficient" claim missed that writer.
/// Read-only accessors (`load`, `is_paired`, `find_by_hostname`)
/// intentionally skip both locks: atomic rename means they always observe
/// a complete file.
static REGISTRY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take the process-wide registry lock, tolerating poisoning (a panic in a
/// prior critical section leaves the file consistent thanks to atomic
/// rename, so the `()` payload is meaningless — recover and proceed).
fn lock_registry() -> std::sync::MutexGuard<'static, ()> {
    REGISTRY_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

/// GR-020 — bounded-blocking exclusive OS lock on
/// `<home>/cluster.yaml.lock`. Dropping the returned handle releases it.
/// Every cross-process write path takes this AFTER the intra-process
/// `REGISTRY_LOCK` (mutex-first): same-process writers then serialise by
/// PARKING on the mutex, so only the single mutex-holder ever contends for
/// this file lock. The old file-first order made concurrent same-process
/// writers all SPIN here and trip the 5s give-up under CPU load (it flaked
/// the concurrent registry tests). A cross-process CLI write still blocks on
/// this lock for the whole load→save, so it can't land mid-cycle (silent
/// lost-update). Built on the same MSRV-1.91-safe primitives as
/// `daemon/pidfile.rs` (`std::fs::File::lock` needs 1.89): non-blocking
/// acquire retried every 50ms, failing loudly after 5s instead of
/// deadlocking on a stuck holder.
fn lock_registry_file(home: &Path) -> Result<std::fs::File> {
    let lock_path = home.join("cluster.yaml.lock");
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create cluster lock dir {}", parent.display()))?;
    }
    const RETRY_EVERY: std::time::Duration = std::time::Duration::from_millis(50);
    const GIVE_UP_AFTER: std::time::Duration = std::time::Duration::from_secs(5);
    let started = std::time::Instant::now();
    loop {
        if let Some(f) = try_lock_registry_file(&lock_path)? {
            return Ok(f);
        }
        if started.elapsed() >= GIVE_UP_AFTER {
            anyhow::bail!(
                "cluster registry lock {} held by another process for >5s — \
                 is a stuck `neoth cluster` invocation or daemon write hanging?",
                lock_path.display()
            );
        }
        std::thread::sleep(RETRY_EVERY);
    }
}

/// One non-blocking exclusive-acquire attempt on the registry lock file.
/// `Ok(Some(file))` = acquired (drop releases); `Ok(None)` = currently
/// held elsewhere; `Err` = real I/O failure. Mirrors `pidfile.rs`:
/// Windows excludes via `share_mode(FILE_SHARE_READ)` at open (a second
/// write-open hits ERROR_SHARING_VIOLATION), Unix via advisory
/// `flock(LOCK_EX | LOCK_NB)`.
fn try_lock_registry_file(lock_path: &Path) -> Result<Option<std::fs::File>> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const ERROR_SHARING_VIOLATION: i32 = 32;
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(FILE_SHARE_READ)
            .open(lock_path)
        {
            Ok(f) => Ok(Some(f)),
            Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => Ok(None),
            Err(e) => {
                Err(e).with_context(|| format!("open cluster lock file {}", lock_path.display()))
            }
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .with_context(|| format!("open cluster lock file {}", lock_path.display()))?;
        // SAFETY: plain flock syscall on a valid owned fd.
        let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            Ok(Some(f))
        } else {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(e).with_context(|| format!("flock {}", lock_path.display()))
            }
        }
    }
}

/// One paired peer — the operator confirmed this device + it's now
/// part of the cluster.
// `Eq` dropped in SL-02b — `stability_score: f64` only satisfies `PartialEq`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PairedPeer {
    /// 64-char lowercase-hex of the peer's ed25519 pub key.
    pub pub_key_hex: String,
    /// Operator-readable label as the peer announced.
    pub instance_label: String,
    /// Network hostname the operator recorded for this peer (SL-01c).
    /// Lets the operator reference a peer by a stable, memorable name
    /// (`neoth cluster confirm <key> --hostname laptop`, then
    /// `neoth cluster revoke laptop`) instead of the 64-char pub_key
    /// hex. Empty when unknown — older `cluster.yaml` files + peers
    /// confirmed without `--hostname`. The struct-level `#[serde(default)]`
    /// keeps pre-SL-01c registries deserialising clean.
    pub hostname: String,
    /// Last-known socket address. Phase 6 gossip updates this on
    /// successful reconnect.
    pub addr: String,
    /// Transport that surfaced the peer initially.
    pub discovered_via: DiscoveryVia,
    /// Unix seconds when the operator confirmed the peer.
    pub paired_at_unix: i64,
    /// Unix seconds when discovery last saw this peer announce.
    /// Phase 2+ refreshes on each successful HMAC-verified announce.
    pub last_seen_unix: i64,
    /// SL-02b: last measured round-trip time to this peer in ms (heartbeat
    /// send→ack). `None` until the first round-trip. `#[serde(default)]`
    /// (struct-level) keeps pre-SL-02b `cluster.yaml` files deserialising clean.
    #[serde(default)]
    pub rtt_ms: Option<u64>,
    /// SL-02b: EWMA heartbeat-success ratio in `[0.0, 1.0]`, seeded NEUTRAL
    /// (0.5) on a fresh peer and nudged by [`compute_stability`] on each
    /// heartbeat hit/miss. Keeps answering → trends 1.0; goes quiet → 0.0.
    #[serde(default = "default_stability")]
    pub stability_score: f64,
}

/// Neutral stability prior — a freshly-confirmed peer (or a pre-SL-02b
/// `cluster.yaml` row missing the field) starts here: no evidence either way.
pub const NEUTRAL_STABILITY: f64 = 0.5;

/// EWMA smoothing factor for [`compute_stability`]. 0.1 = ~10-heartbeat memory.
pub const STABILITY_ALPHA: f64 = 0.1;

fn default_stability() -> f64 {
    NEUTRAL_STABILITY
}

/// Pure EWMA update of a stability score: `prev*(1-α) + hit*α`, clamped to
/// `[0.0, 1.0]`. `success = true` nudges toward 1.0, `false` toward 0.0.
pub fn compute_stability(prev: f64, success: bool) -> f64 {
    let hit = if success { 1.0 } else { 0.0 };
    (prev * (1.0 - STABILITY_ALPHA) + hit * STABILITY_ALPHA).clamp(0.0, 1.0)
}

impl Default for PairedPeer {
    fn default() -> Self {
        Self {
            pub_key_hex: String::new(),
            instance_label: String::new(),
            hostname: String::new(),
            addr: String::new(),
            discovered_via: DiscoveryVia::Manual,
            paired_at_unix: 0,
            last_seen_unix: 0,
            rtt_ms: None,
            stability_score: NEUTRAL_STABILITY,
        }
    }
}

/// Top-level shape of `~/.neoth/cluster.yaml`.
// `Eq` dropped in SL-02b — contains `PairedPeer` which is no longer `Eq`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClusterRegistry {
    /// All confirmed peers, sorted by `pub_key_hex` for stable
    /// on-disk diffs.
    pub peers: Vec<PairedPeer>,
}

/// Default path: `<neoth_home>/cluster.yaml`.
pub fn default_path(home: &Path) -> PathBuf {
    home.join("cluster.yaml")
}

/// Load the registry. Missing file → empty default. Malformed
/// YAML is a hard error — silently disabling every paired peer
/// would mask the corruption.
pub fn load(home: &Path) -> Result<ClusterRegistry> {
    let path = default_path(home);
    if !path.exists() {
        return Ok(ClusterRegistry::default());
    }
    let body = std::fs::read_to_string(&path)
        .with_context(|| format!("read cluster registry at {}", path.display()))?;
    let mut reg: ClusterRegistry = serde_yaml::from_str(&body)
        .with_context(|| format!("parse cluster registry YAML at {}", path.display()))?;
    reg.peers.sort_by(|a, b| a.pub_key_hex.cmp(&b.pub_key_hex));
    Ok(reg)
}

/// Write the registry atomically via `.tmp` + rename.
pub fn save(home: &Path, reg: &ClusterRegistry) -> Result<()> {
    let path = default_path(home);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create cluster registry dir {}", parent.display()))?;
    }
    // Sort before write so on-disk order is stable across runs.
    let mut sorted = reg.clone();
    sorted
        .peers
        .sort_by(|a, b| a.pub_key_hex.cmp(&b.pub_key_hex));
    let tmp = path.with_extension("yaml.tmp");
    let body = serde_yaml::to_string(&sorted).with_context(|| "serialize cluster registry")?;
    std::fs::write(&tmp, body).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} → {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Add or update a peer. If a peer with the same `pub_key_hex`
/// exists, the new entry replaces the old (preserves `paired_at_unix`
/// from the original — re-confirm doesn't reset the timestamp).
pub fn upsert(home: &Path, mut peer: PairedPeer) -> Result<()> {
    let _guard = lock_registry();
    let _file_guard = lock_registry_file(home)?;
    let mut reg = load(home)?;
    if let Some(existing) = reg.peers.iter().find(|p| p.pub_key_hex == peer.pub_key_hex) {
        peer.paired_at_unix = existing.paired_at_unix;
    }
    reg.peers.retain(|p| p.pub_key_hex != peer.pub_key_hex);
    reg.peers.push(peer);
    save(home, &reg)
}

/// Remove a peer by pub_key_hex (or unique prefix). Returns Ok(true)
/// when a peer was removed, Ok(false) when no match found (idempotent
/// `revoke` on a ghost is a no-op).
///
/// Prefix matching: when `key_or_prefix` is shorter than 64 chars,
/// matches any peer whose `pub_key_hex` starts with it. Errors on
/// ambiguous match (multiple peers with that prefix).
pub fn remove(home: &Path, key_or_prefix: &str) -> Result<bool> {
    let _guard = lock_registry();
    let _file_guard = lock_registry_file(home)?;
    let mut reg = load(home)?;
    let matches: Vec<usize> = reg
        .peers
        .iter()
        .enumerate()
        .filter(|(_, p)| p.pub_key_hex.starts_with(key_or_prefix))
        .map(|(i, _)| i)
        .collect();
    match matches.len() {
        0 => Ok(false),
        1 => {
            reg.peers.remove(matches[0]);
            save(home, &reg)?;
            Ok(true)
        }
        n => anyhow::bail!("prefix `{key_or_prefix}` matches {n} peers — use a longer prefix"),
    }
}

/// True when a peer with the given pub_key_hex (or unique prefix)
/// is already paired.
pub fn is_paired(home: &Path, key_or_prefix: &str) -> bool {
    let Ok(reg) = load(home) else {
        return false;
    };
    reg.peers
        .iter()
        .any(|p| p.pub_key_hex.starts_with(key_or_prefix))
}

/// SL-01c: resolve a paired peer by its recorded network hostname
/// (case-insensitive). Returns the first match — `load` sorts by
/// `pub_key_hex`, so the result is deterministic when two peers share
/// a hostname. An empty / whitespace-only `hostname` NEVER matches:
/// peers confirmed without `--hostname` carry an empty field, and a
/// `""` lookup must not silently resolve to one of them (fail-closed,
/// same discipline as `is_paired`). Returns `None` when the registry
/// can't be read (mirrors `is_paired`'s load-failure posture).
pub fn find_by_hostname(home: &Path, hostname: &str) -> Option<PairedPeer> {
    let needle = hostname.trim();
    if needle.is_empty() {
        return None;
    }
    let reg = load(home).ok()?;
    reg.peers
        .into_iter()
        .find(|p| !p.hostname.is_empty() && p.hostname.eq_ignore_ascii_case(needle))
}

/// Update `last_seen_unix` for a paired peer. No-op when the peer
/// isn't paired yet — Phase 2 discovery passes every authenticated
/// announce through this; only the paired ones update.
pub fn refresh_last_seen(home: &Path, pub_key_hex: &str, ts_unix: i64) -> Result<bool> {
    let _guard = lock_registry();
    let _file_guard = lock_registry_file(home)?;
    let mut reg = load(home)?;
    let mut changed = false;
    for p in reg.peers.iter_mut() {
        if p.pub_key_hex == pub_key_hex {
            p.last_seen_unix = ts_unix;
            changed = true;
            break;
        }
    }
    if changed {
        save(home, &reg)?;
    }
    Ok(changed)
}

/// SL-02b: record the last measured RTT (ms) for a paired peer. No-op + `false`
/// when the peer isn't paired. Same load→mutate→save shape as
/// [`refresh_last_seen`].
pub fn refresh_rtt(home: &Path, pub_key_hex: &str, rtt_ms: u64) -> Result<bool> {
    let _guard = lock_registry();
    let _file_guard = lock_registry_file(home)?;
    let mut reg = load(home)?;
    let mut changed = false;
    for p in reg.peers.iter_mut() {
        if p.pub_key_hex == pub_key_hex {
            p.rtt_ms = Some(rtt_ms);
            changed = true;
            break;
        }
    }
    if changed {
        save(home, &reg)?;
    }
    Ok(changed)
}

/// SL-02b: fold a heartbeat hit/miss into a paired peer's EWMA stability score
/// via [`compute_stability`]. No-op + `false` when the peer isn't paired.
pub fn refresh_stability(home: &Path, pub_key_hex: &str, success: bool) -> Result<bool> {
    let _guard = lock_registry();
    let _file_guard = lock_registry_file(home)?;
    let mut reg = load(home)?;
    let mut changed = false;
    for p in reg.peers.iter_mut() {
        if p.pub_key_hex == pub_key_hex {
            p.stability_score = compute_stability(p.stability_score, success);
            changed = true;
            break;
        }
    }
    if changed {
        save(home, &reg)?;
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// GR-020: the registry file lock must exclude a second acquirer —
    /// same semantics an independent `neoth cluster confirm` process
    /// would see (Windows share-mode + Unix flock both act per
    /// open-file-description, so a second in-process probe is an
    /// equivalent stand-in for a foreign process).
    #[test]
    fn registry_file_lock_excludes_second_acquirer_until_released() {
        let dir = tempdir().unwrap();
        let lock_path = dir.path().join("cluster.yaml.lock");
        let held = lock_registry_file(dir.path()).unwrap();
        match try_lock_registry_file(&lock_path) {
            Ok(None) => {}
            other => panic!("expected Ok(None) while lock held, got {other:?}"),
        }
        drop(held);
        let reacquired = try_lock_registry_file(&lock_path)
            .expect("probe must not error")
            .expect("lock must be acquirable after release");
        drop(reacquired);
    }

    fn sample_peer(hex_prefix: &str, label: &str) -> PairedPeer {
        let full = format!("{hex_prefix}{}", "0".repeat(64 - hex_prefix.len()));
        PairedPeer {
            pub_key_hex: full,
            instance_label: label.into(),
            hostname: String::new(),
            addr: "192.0.2.1:4242".into(),
            discovered_via: DiscoveryVia::Mdns,
            paired_at_unix: 1_700_000_000,
            last_seen_unix: 1_700_000_000,
            ..Default::default()
        }
    }

    #[test]
    fn load_missing_file_returns_empty_default() {
        let dir = tempdir().unwrap();
        let reg = load(dir.path()).unwrap();
        assert!(reg.peers.is_empty());
    }

    #[test]
    fn save_then_load_roundtrip() {
        let dir = tempdir().unwrap();
        let mut reg = ClusterRegistry::default();
        reg.peers.push(sample_peer("ab", "laptop"));
        reg.peers.push(sample_peer("cd", "server"));
        save(dir.path(), &reg).unwrap();
        let loaded = load(dir.path()).unwrap();
        assert_eq!(loaded.peers.len(), 2);
        // Sort order pinned: alphabetical by pub_key_hex.
        assert_eq!(loaded.peers[0].instance_label, "laptop");
        assert_eq!(loaded.peers[1].instance_label, "server");
    }

    #[test]
    fn upsert_adds_new_peer() {
        let dir = tempdir().unwrap();
        upsert(dir.path(), sample_peer("ab", "alpha")).unwrap();
        let reg = load(dir.path()).unwrap();
        assert_eq!(reg.peers.len(), 1);
        assert_eq!(reg.peers[0].instance_label, "alpha");
    }

    #[test]
    fn upsert_preserves_original_paired_at_on_reconfirm() {
        let dir = tempdir().unwrap();
        let original = sample_peer("ab", "alpha");
        let orig_ts = original.paired_at_unix;
        upsert(dir.path(), original).unwrap();
        // Re-confirm with a different label + a NEW paired_at — the
        // original ts must survive.
        let mut updated = sample_peer("ab", "alpha-renamed");
        updated.paired_at_unix = 9_999_999_999;
        upsert(dir.path(), updated).unwrap();
        let reg = load(dir.path()).unwrap();
        assert_eq!(reg.peers.len(), 1);
        assert_eq!(reg.peers[0].instance_label, "alpha-renamed");
        assert_eq!(reg.peers[0].paired_at_unix, orig_ts);
    }

    #[test]
    fn remove_full_key_returns_true_on_first_call() {
        let dir = tempdir().unwrap();
        let peer = sample_peer("ab", "alpha");
        let full_key = peer.pub_key_hex.clone();
        upsert(dir.path(), peer).unwrap();
        assert!(remove(dir.path(), &full_key).unwrap());
        // Second call is no-op.
        assert!(!remove(dir.path(), &full_key).unwrap());
    }

    #[test]
    fn remove_short_prefix_works_when_unique() {
        let dir = tempdir().unwrap();
        upsert(dir.path(), sample_peer("ab", "alpha")).unwrap();
        upsert(dir.path(), sample_peer("cd", "charlie")).unwrap();
        // Short prefix "ab" unique → removes alpha.
        assert!(remove(dir.path(), "ab").unwrap());
        let reg = load(dir.path()).unwrap();
        assert_eq!(reg.peers.len(), 1);
        assert_eq!(reg.peers[0].instance_label, "charlie");
    }

    #[test]
    fn remove_ambiguous_prefix_errors() {
        let dir = tempdir().unwrap();
        upsert(dir.path(), sample_peer("ab1", "alpha")).unwrap();
        upsert(dir.path(), sample_peer("ab2", "bravo")).unwrap();
        let err = remove(dir.path(), "ab").unwrap_err();
        assert!(err.to_string().contains("matches 2"));
    }

    #[test]
    fn is_paired_finds_full_and_prefix() {
        let dir = tempdir().unwrap();
        upsert(dir.path(), sample_peer("dead", "alpha")).unwrap();
        assert!(is_paired(dir.path(), "dead"));
        assert!(is_paired(
            dir.path(),
            "dead0000000000000000000000000000000000000000000000000000000000"
        ));
        assert!(!is_paired(dir.path(), "beef"));
    }

    #[test]
    fn refresh_last_seen_updates_paired_only() {
        let dir = tempdir().unwrap();
        let mut peer = sample_peer("ab", "alpha");
        peer.last_seen_unix = 100;
        upsert(dir.path(), peer.clone()).unwrap();
        // Update via full pub_key_hex.
        assert!(refresh_last_seen(dir.path(), &peer.pub_key_hex, 200).unwrap());
        let reg = load(dir.path()).unwrap();
        assert_eq!(reg.peers[0].last_seen_unix, 200);
        // Unknown peer → no-op false.
        let ghost = format!("ff{}", "0".repeat(62));
        assert!(!refresh_last_seen(dir.path(), &ghost, 999).unwrap());
    }

    #[test]
    fn save_atomic_leaves_no_tmp() {
        let dir = tempdir().unwrap();
        upsert(dir.path(), sample_peer("ab", "a")).unwrap();
        let tmp = default_path(dir.path()).with_extension("yaml.tmp");
        assert!(!tmp.exists());
    }

    #[test]
    fn malformed_yaml_is_hard_error() {
        let dir = tempdir().unwrap();
        std::fs::write(default_path(dir.path()), ": : :\n").unwrap();
        assert!(load(dir.path()).is_err());
    }

    #[test]
    fn paired_peer_serde_round_trip_preserves_every_field() {
        let original = PairedPeer {
            pub_key_hex: "ab".repeat(32),
            instance_label: "label".into(),
            hostname: "workstation-01".into(),
            addr: "10.0.0.5:443".into(),
            discovered_via: DiscoveryVia::Tailscale,
            paired_at_unix: 1_234_567_890,
            last_seen_unix: 1_234_567_999,
            ..Default::default()
        };
        let yaml = serde_yaml::to_string(&original).unwrap();
        let back: PairedPeer = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn paired_peer_deserialises_pre_sl01c_yaml_without_hostname() {
        // A cluster.yaml written before SL-01c carries no `hostname`
        // key. The struct-level #[serde(default)] must fill it with an
        // empty string rather than failing the whole registry load —
        // otherwise an upgrade would silently disable every paired peer.
        let legacy = "\
peers:
  - pub_key_hex: "
            .to_string()
            + "ab".repeat(32).as_str()
            + "
    instance_label: laptop
    addr: 10.0.0.5:443
    discovered_via: mdns
    paired_at_unix: 1700000000
    last_seen_unix: 1700000000
";
        let reg: ClusterRegistry = serde_yaml::from_str(&legacy).unwrap();
        assert_eq!(reg.peers.len(), 1);
        assert_eq!(reg.peers[0].hostname, "");
        assert_eq!(reg.peers[0].instance_label, "laptop");
    }

    #[test]
    fn find_by_hostname_matches_case_insensitive() {
        let dir = tempdir().unwrap();
        let mut peer = sample_peer("ab", "laptop");
        peer.hostname = "Workstation-01".into();
        upsert(dir.path(), peer.clone()).unwrap();
        // Exact + case-insensitive both resolve.
        assert_eq!(
            find_by_hostname(dir.path(), "Workstation-01")
                .unwrap()
                .pub_key_hex,
            peer.pub_key_hex
        );
        assert_eq!(
            find_by_hostname(dir.path(), "workstation-01")
                .unwrap()
                .pub_key_hex,
            peer.pub_key_hex
        );
    }

    #[test]
    fn find_by_hostname_none_for_unknown_or_empty() {
        let dir = tempdir().unwrap();
        let mut peer = sample_peer("ab", "laptop");
        peer.hostname = "laptop".into();
        upsert(dir.path(), peer).unwrap();
        // Unknown hostname → None.
        assert!(find_by_hostname(dir.path(), "server").is_none());
        // Empty / whitespace needle never matches (fail-closed) even
        // though a peer with an empty hostname could exist.
        upsert(dir.path(), sample_peer("cd", "no-host")).unwrap(); // hostname == ""
        assert!(find_by_hostname(dir.path(), "").is_none());
        assert!(find_by_hostname(dir.path(), "   ").is_none());
    }

    // ── SL-02b: RTT + stability ──────────────────────────────────────────

    #[test]
    fn compute_stability_seeds_neutral_and_moves() {
        // A fresh peer starts NEUTRAL; a hit nudges up, a miss nudges down.
        let up = compute_stability(NEUTRAL_STABILITY, true);
        let down = compute_stability(NEUTRAL_STABILITY, false);
        assert!(
            up > NEUTRAL_STABILITY && up <= 1.0,
            "hit moves toward 1.0: {up}"
        );
        assert!(
            (0.0..NEUTRAL_STABILITY).contains(&down),
            "miss moves toward 0.0: {down}"
        );
        // Many consecutive hits converge near 1.0; misses near 0.0 (clamped).
        let mut s = NEUTRAL_STABILITY;
        for _ in 0..200 {
            s = compute_stability(s, true);
        }
        assert!(s > 0.99, "sustained hits converge to ~1.0: {s}");
        let mut s = NEUTRAL_STABILITY;
        for _ in 0..200 {
            s = compute_stability(s, false);
        }
        assert!(s < 0.01, "sustained misses converge to ~0.0: {s}");
    }

    #[test]
    fn refresh_rtt_updates_paired_peer_only() {
        let dir = tempdir().unwrap();
        upsert(dir.path(), sample_peer("ab", "laptop")).unwrap();
        let key = format!("ab{}", "0".repeat(62));
        assert!(refresh_rtt(dir.path(), &key, 42).unwrap());
        let reg = load(dir.path()).unwrap();
        assert_eq!(reg.peers[0].rtt_ms, Some(42));
        // Unknown peer → no-op false.
        assert!(!refresh_rtt(dir.path(), "ff", 1).unwrap());
    }

    #[test]
    fn refresh_stability_folds_ewma() {
        let dir = tempdir().unwrap();
        upsert(dir.path(), sample_peer("ab", "laptop")).unwrap();
        let key = format!("ab{}", "0".repeat(62));
        assert_eq!(
            load(dir.path()).unwrap().peers[0].stability_score,
            NEUTRAL_STABILITY
        );
        assert!(refresh_stability(dir.path(), &key, true).unwrap());
        let after_hit = load(dir.path()).unwrap().peers[0].stability_score;
        assert!(after_hit > NEUTRAL_STABILITY);
        assert!(refresh_stability(dir.path(), &key, false).unwrap());
        let after_miss = load(dir.path()).unwrap().peers[0].stability_score;
        assert!(after_miss < after_hit);
        assert!(!refresh_stability(dir.path(), "ff", true).unwrap());
    }

    #[test]
    fn concurrent_distinct_peer_upserts_do_not_lose_updates() {
        // COR-16/A-43: each upsert is a whole-file load→add→save. Without
        // the process-wide registry lock, concurrent upserts of DISTINCT
        // peers each load a snapshot missing the others and save over them
        // → lost peers. The lock serialises the cycle so all survive.
        use std::sync::{Arc, Barrier};
        let dir = tempdir().unwrap();
        let home: Arc<std::path::PathBuf> = Arc::new(dir.path().to_path_buf());
        let n = 8usize;
        let barrier = Arc::new(Barrier::new(n));
        let handles: Vec<_> = (0..n)
            .map(|i| {
                let home = Arc::clone(&home);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let peer = sample_peer(&format!("{i:02x}"), &format!("peer{i}"));
                    barrier.wait();
                    upsert(&home, peer).unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let reg = load(&home).unwrap();
        assert_eq!(
            reg.peers.len(),
            n,
            "every concurrent upsert must survive (no lost update)"
        );
    }

    #[test]
    fn concurrent_rtt_and_stability_refresh_both_persist() {
        // COR-16/A-43: rtt and stability live in the SAME peer record.
        // Without the lock a refresh_rtt racing a refresh_stability both
        // load the same snapshot and the later save drops the earlier
        // field. The lock serialises them so ALL stability folds apply and
        // the rtt lands.
        use std::sync::{Arc, Barrier};
        let dir = tempdir().unwrap();
        upsert(dir.path(), sample_peer("ab", "laptop")).unwrap();
        let home: Arc<std::path::PathBuf> = Arc::new(dir.path().to_path_buf());
        let key = Arc::new(format!("ab{}", "0".repeat(62)));
        let rounds = 25u32;
        let barrier = Arc::new(Barrier::new(2));
        let h_rtt = {
            let (home, key, barrier) = (Arc::clone(&home), Arc::clone(&key), Arc::clone(&barrier));
            std::thread::spawn(move || {
                barrier.wait();
                for r in 0..rounds {
                    refresh_rtt(&home, &key, 10 + r as u64).unwrap();
                }
            })
        };
        let h_stab = {
            let (home, key, barrier) = (Arc::clone(&home), Arc::clone(&key), Arc::clone(&barrier));
            std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..rounds {
                    refresh_stability(&home, &key, true).unwrap();
                }
            })
        };
        h_rtt.join().unwrap();
        h_stab.join().unwrap();

        let reg = load(&home).unwrap();
        let peer = &reg.peers[0];
        assert!(peer.rtt_ms.is_some(), "rtt update must persist");
        // Every one of the `rounds` stability hits must have folded in — a
        // lost update would leave the score below the fully-folded value.
        let mut expected = NEUTRAL_STABILITY;
        for _ in 0..rounds {
            expected = compute_stability(expected, true);
        }
        assert!(
            (peer.stability_score - expected).abs() < 1e-9,
            "all {rounds} stability folds must apply (no lost update): got {} expected {}",
            peer.stability_score,
            expected
        );
    }

    #[test]
    fn pre_sl02b_yaml_without_rtt_stability_loads_defaults() {
        // A cluster.yaml written before SL-02b carries no rtt_ms /
        // stability_score keys — the struct-level #[serde(default)] +
        // default_stability() must fill them rather than failing the load.
        let legacy = "\
peers:
  - pub_key_hex: "
            .to_string()
            + "ab".repeat(32).as_str()
            + "
    instance_label: laptop
    hostname: ''
    addr: 10.0.0.5:443
    discovered_via: mdns
    paired_at_unix: 1700000000
    last_seen_unix: 1700000000
";
        let reg: ClusterRegistry = serde_yaml::from_str(&legacy).unwrap();
        assert_eq!(reg.peers.len(), 1);
        assert_eq!(reg.peers[0].rtt_ms, None);
        assert_eq!(reg.peers[0].stability_score, NEUTRAL_STABILITY);
    }
}
