//! Storage-integrity doctor checks (GOLD-ARCH-06): views.db, WAL
//! segments, HMAC key, quota, disk space.

use std::path::Path;

use rusqlite::Connection;

use super::super::{is_mode_0600, CheckOutcome, CheckStatus};

pub(crate) fn check_views_db(home: &Path) -> CheckOutcome {
    let path = home.join("views.db");
    if !path.exists() {
        return CheckOutcome {
            name: "views.db",
            status: CheckStatus::Warn,
            detail: "absent (will be built on first `neoth serve`)".into(),
        };
    }
    let Ok(conn) = Connection::open(&path) else {
        return CheckOutcome {
            name: "views.db",
            status: CheckStatus::Fail,
            detail: "cannot open SQLite file".into(),
        };
    };
    let integrity: Result<String, _> = conn.query_row("PRAGMA integrity_check", [], |r| r.get(0));
    match integrity {
        Ok(s) if s == "ok" => CheckOutcome {
            name: "views.db",
            status: CheckStatus::Pass,
            detail: "integrity_check ok".into(),
        },
        Ok(other) => CheckOutcome {
            name: "views.db",
            status: CheckStatus::Fail,
            detail: format!("integrity_check returned {other}"),
        },
        Err(e) => CheckOutcome {
            name: "views.db",
            status: CheckStatus::Fail,
            detail: format!("PRAGMA failed: {e}"),
        },
    }
}

pub(crate) fn check_wal_segments(home: &Path) -> CheckOutcome {
    let wal_dir = home.join("wal");
    if !wal_dir.exists() {
        return CheckOutcome {
            name: "wal segments",
            status: CheckStatus::Warn,
            detail: "no wal/ dir (daemon never started)".into(),
        };
    }
    let mut count = 0usize;
    let mut bad = Vec::new();
    let entries = match std::fs::read_dir(&wal_dir) {
        Ok(rd) => rd,
        Err(e) => {
            return CheckOutcome {
                name: "wal segments",
                status: CheckStatus::Fail,
                detail: format!("read wal/ failed: {e}"),
            };
        }
    };
    use crate::wal::segment_header::{SEGMENT_HEADER_LEN, SegmentHeader};
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("wal") {
            continue;
        }
        count += 1;
        let Ok(bytes) = std::fs::read(&path) else {
            bad.push(format!("{}: unreadable", path.display()));
            continue;
        };
        if bytes.len() < SEGMENT_HEADER_LEN {
            bad.push(format!(
                "{}: shorter than SegmentHeader ({} < {})",
                path.display(),
                bytes.len(),
                SEGMENT_HEADER_LEN
            ));
            continue;
        }
        if let Err(e) =
            SegmentHeader::from_le_bytes(bytes[..SEGMENT_HEADER_LEN].try_into().unwrap())
        {
            bad.push(format!("{}: bad header: {e}", path.display()));
        }
    }
    if !bad.is_empty() {
        return CheckOutcome {
            name: "wal segments",
            status: CheckStatus::Fail,
            detail: format!("{} segment(s) bad: {}", bad.len(), bad.join("; ")),
        };
    }
    CheckOutcome {
        name: "wal segments",
        status: CheckStatus::Pass,
        detail: format!("{count} segment(s) ok"),
    }
}

pub(crate) fn check_hmac_key(home: &Path) -> CheckOutcome {
    let path = home.join("wal").join("hmac.key");
    if !path.exists() {
        return CheckOutcome {
            name: "hmac.key",
            status: CheckStatus::Warn,
            detail: "absent (generated on first WAL write)".into(),
        };
    }
    if !is_mode_0600(&path) {
        return CheckOutcome {
            name: "hmac.key",
            status: CheckStatus::Fail,
            detail: format!(
                "mode > 0600 — HMAC compromised; run `chmod 0600 {}`",
                path.display()
            ),
        };
    }
    match std::fs::metadata(&path).map(|m| m.len()) {
        Ok(n) if n >= 16 => CheckOutcome {
            name: "hmac.key",
            status: CheckStatus::Pass,
            detail: format!("{n} bytes, mode 0600"),
        },
        Ok(n) => CheckOutcome {
            name: "hmac.key",
            status: CheckStatus::Fail,
            detail: format!("{n} bytes is too short — regenerate"),
        },
        Err(e) => CheckOutcome {
            name: "hmac.key",
            status: CheckStatus::Fail,
            detail: format!("stat failed: {e}"),
        },
    }
}

pub(crate) fn check_quota(home: &Path) -> CheckOutcome {
    let ceiling = crate::daemon::quota::DEFAULT_CEILING_BYTES;
    let state = crate::daemon::quota::snapshot_quota(home, ceiling);
    if state.is_breached() {
        CheckOutcome {
            name: "disk quota",
            status: CheckStatus::Fail,
            detail: format!(
                "{} ≥ {} ceiling — daemon will reject new writes",
                fmt_bytes(state.used()),
                fmt_bytes(state.ceiling())
            ),
        }
    } else {
        CheckOutcome {
            name: "disk quota",
            status: CheckStatus::Pass,
            detail: format!(
                "{} of {} used",
                fmt_bytes(state.used()),
                fmt_bytes(state.ceiling())
            ),
        }
    }
}

/// Warn when free disk on `~/.neoth/`'s partition is below the full
/// model-cache footprint. Operators who haven't pulled CLIP / whisper /
/// Qwen yet see a heads-up before the download stalls at 70%.
pub(crate) fn check_disk_space(home: &Path) -> CheckOutcome {
    let probe = crate::daemon::hardware::probe(home);
    let avail = probe.disk.home_available_gib();
    let needed = probe.estimated_full_cache_gib;
    if probe.disk.home_total_bytes == 0 {
        return CheckOutcome {
            name: "disk space",
            status: CheckStatus::Pass,
            detail: format!(
                "{} mount not resolvable (containerised?); skipping check",
                probe.disk.home_mount,
            ),
        };
    }
    if avail < needed {
        return CheckOutcome {
            name: "disk space",
            status: CheckStatus::Warn,
            detail: format!(
                "{:.1} GiB free on {} but full model cache is ~{:.1} GiB",
                avail, probe.disk.home_mount, needed,
            ),
        };
    }
    CheckOutcome {
        name: "disk space",
        status: CheckStatus::Pass,
        detail: format!(
            "{:.1} GiB free on {} (need ~{:.1} GiB for full cache)",
            avail, probe.disk.home_mount, needed,
        ),
    }
}

pub(crate) fn fmt_bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if n >= GIB {
        format!("{:.2} GiB", n as f64 / GIB as f64)
    } else if n >= MIB {
        format!("{:.2} MiB", n as f64 / MIB as f64)
    } else if n >= KIB {
        format!("{:.2} KiB", n as f64 / KIB as f64)
    } else {
        format!("{n} B")
    }
}
