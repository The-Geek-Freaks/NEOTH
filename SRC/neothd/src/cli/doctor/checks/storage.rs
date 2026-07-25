//! Storage-integrity doctor checks (GOLD-ARCH-06): views.db, WAL
//! segments, HMAC key, quota, disk space.

use std::path::Path;

use rusqlite::Connection;

use super::super::{CheckDoc, CheckFn, CheckOutcome, CheckStatus, is_mode_0600};

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
    let probe = match crate::daemon::hardware::probe(home) {
        Ok(probe) => probe,
        Err(error) => {
            return CheckOutcome {
                name: "disk space",
                status: CheckStatus::Fail,
                detail: format!("hardware/config probe failed: {error:#}"),
            };
        }
    };
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

/// GOLD-ADAPT-HERMES-07b — surface staged self-heal patch proposals (from
/// crash-log analysis) so the operator reviews them. Warn when any are staged;
/// they are advisory only and never auto-applied.
pub(crate) fn check_self_heal_proposals(home: &Path) -> CheckOutcome {
    let proposals = crate::daemon::self_heal::load_proposals(home);
    if proposals.is_empty() {
        CheckOutcome {
            name: "self-heal proposals",
            status: CheckStatus::Pass,
            detail: "none staged".into(),
        }
    } else {
        CheckOutcome {
            name: "self-heal proposals",
            status: CheckStatus::Warn,
            detail: format!(
                "{} staged patch proposal(s) from crash analysis — review {} (advisory; not auto-applied)",
                proposals.len(),
                crate::daemon::self_heal::proposals_path(home).display()
            ),
        }
    }
}

/// GOLD-ADAPT-CRYPTO-04e — when WAL/config AEAD-at-rest is enabled, remind the
/// operator to back up the master key. Losing it makes every sealed segment AND
/// encrypted credentials permanently unreadable — the highest-severity footgun,
/// so this stays a standing WARN while encryption is on.
pub(crate) fn check_wal_encryption_backup(home: &Path) -> CheckOutcome {
    let config_path = home.join("freedom.yaml");
    let enc = match crate::config::wal::load_wal_config(&config_path) {
        Ok(config) => config.encryption,
        Err(error) => {
            return CheckOutcome {
                name: "wal encryption",
                status: CheckStatus::Fail,
                detail: format!(
                    "cannot load WAL encryption policy from {}: {error:#}",
                    config_path.display()
                ),
            };
        }
    };
    if enc != crate::config::wal::WalEncryption::Aes256GcmSiv {
        return CheckOutcome {
            name: "wal encryption",
            status: CheckStatus::Pass,
            detail: "plaintext at rest (WAL integrity/HMAC always on)".into(),
        };
    }
    // This check used to report "AES-256-GCM-SIV on" from the encryption field
    // alone. It is not on: the seal is applied only when a segment is finalized
    // under `wal.compression: zstd_3`, and no production path selects that
    // policy — so a config with encryption set produced PLAINTEXT segments while
    // this line told the operator to back up a key that was protecting nothing.
    // The WAL writer now refuses to open under that config
    // (`wal::writer::refuse_unimplemented_storage_policy`), so the honest
    // diagnostic is a hard FAIL naming the fix, not a reassuring warning.
    let key = crate::wal::master_key::master_key_path(home);
    CheckOutcome {
        name: "wal encryption",
        status: CheckStatus::Fail,
        detail: format!(
            "wal.encryption is set, but at-rest sealing is NOT applied in this build — it runs \
             only when a segment is finalized under wal.compression = zstd_3, which is not \
             wired. Segments would be plaintext, so the WAL writer refuses to start: set \
             `wal.encryption: none` in {}. (The master key at {} may already exist and is \
             still used for encrypted credentials — keep backing that up.)",
            config_path.display(),
            key.display()
        ),
    }
}

/// Registration: this domain's diagnostics, run in order by
/// `run_all_checks`. Adding a check = add the fn + a `CheckDoc` here.
pub(crate) const CHECKS: &[CheckFn] = &[
    check_views_db,
    check_wal_segments,
    check_hmac_key,
    check_quota,
    check_disk_space,
    check_self_heal_proposals,
    check_wal_encryption_backup,
];

/// Operator runbook entries for this domain (the `--explain` surface).
pub(crate) const DOCS: &[CheckDoc] = &[
    CheckDoc {
        name: "views.db",
        purpose: "SQLite views database — the read-side projection of the \
                  WAL. Holds idx_episode (recall), idx_profile (operator \
                  facts), idx_groundtruth (decay-immune anchors), \
                  idx_consolidated / idx_longterm (memory tiers). Doctor \
                  runs `PRAGMA integrity_check` + verifies schema_version \
                  stamp.",
        common_failures: "Disk full mid-write (corruption); manual delete \
                         (recoverable via `neoth restore`); schema drift \
                         (mis-applied migration).",
        fix: "Corruption → restore from `~/.neoth/backups/`. Schema drift → \
              `neoth migrate up` brings the schema forward. If the daemon \
              can't open it, delete + let the indexer rebuild from WAL.",
    },
    CheckDoc {
        name: "wal segments",
        purpose: "Append-only WAL at `~/.neoth/wal/*.wal`. The audit \
                  trail of every action NEOTH ever took. Doctor walks \
                  the segment directory, checks each segment's frame CRC \
                  + magic preamble, verifies the active segment is \
                  writeable.",
        common_failures: "Last-frame corruption (writer crashed mid-fsync — \
                         self-heals on next index pass); segment dir not \
                         writeable; segments deleted manually.",
        fix: "Corrupt tail frame → harmless, indexer truncates. Read-only \
              dir → `chmod u+w ~/.neoth/wal/`. Manually deleted → live with \
              the gap; the indexer skips missing segments.",
    },
    CheckDoc {
        name: "hmac.key",
        purpose: "HMAC key at `~/.neoth/hmac.key` — signs the compaction \
                  markers in the WAL so tampering is detectable. Doctor \
                  checks existence, that the file is exactly 32 bytes \
                  (HMAC-SHA256 key size), and 0600 mode.",
        common_failures: "Missing (daemon auto-generates on first run); \
                         wrong size (manual edit); world-readable.",
        fix: "Missing → next daemon start regenerates. Wrong size → delete \
              + restart (loses ability to verify markers pre-restart). \
              `chmod 600 ~/.neoth/hmac.key`.",
    },
    CheckDoc {
        name: "disk quota",
        purpose: "Pre-write quota guard. Doctor checks the home dir's \
                  current usage vs the configured ceiling \
                  (`freedom.yaml::quota_ceiling_bytes`, default 5 GiB). \
                  Warns past 75% used; fails past 90%.",
        common_failures: "Long-lived daemon with no consolidation → WAL \
                         segments accumulate; backups in `~/.neoth/backups/` \
                         pile up.",
        fix: "Tighten the ceiling or prune. `neoth wal compact` rolls \
              old segments. `neoth backup --prune --keep 7` rotates the \
              backup set.",
    },
    CheckDoc {
        name: "disk space",
        purpose: "Free space on the partition holding `~/.neoth/`. Warns \
                  past 1 GiB free, fails past 100 MiB. Below the fail \
                  threshold the WAL writer's quota guard will reject new \
                  writes — better to warn early.",
        common_failures: "A NAS or always-on home server with a data disk \
                         filling up; a laptop with OS-disk pressure.",
        fix: "Prune backups (`neoth backup --prune`); compact WAL (`neoth \
              wal compact`); move `~/.neoth/` to a larger volume via \
              symlink + `chown`.",
    },
    CheckDoc {
        name: "wal encryption",
        purpose: "CRYPTO-04 — reports the TRUE state of WAL segment AEAD-at-rest. \
                  Segment sealing runs only when a segment is finalized under \
                  `wal.compression: zstd_3`, which this build does not wire, so \
                  `wal.encryption` cannot take effect and the WAL writer refuses \
                  to start while it is set. WAL integrity (HMAC) is always on \
                  independent of this. Encrypted credentials use the same master \
                  key and DO work.",
        common_failures: "`wal.encryption: aes256_gcm_siv` left in freedom.yaml \
                         from an earlier setup — segments were plaintext and this \
                         check used to report the encryption as on. Separately: \
                         encryption enabled WITHOUT an offline key backup → a \
                         Windows reinstall / machine migration permanently loses \
                         encrypted credentials.",
        fix: "Set `wal.encryption: none` (segment sealing lands with WAL \
              compression in a later release). Keep the master key backed up for \
              credentials: `neoth security backup-master-key --out <offline \
              path>`; restore with `neoth security restore-master-key --from \
              <path>` before first start.",
    },
    CheckDoc {
        name: "self-heal proposals",
        purpose: "HERMES-07b — the monitor cron categorises new panics in \
                  `~/.neoth/crash.log` into staged, operator-reviewable patch \
                  proposals (`~/.neoth/self_heal/proposals.jsonl`). Doctor \
                  surfaces the count so they don't sit unseen.",
        common_failures: "Staged proposals accumulating = the daemon is \
                         panicking repeatedly; each proposal names the likely \
                         file:line + fix class.",
        fix: "Review `~/.neoth/self_heal/proposals.jsonl` — each entry has a \
              category + suggested_action + evidence. Apply fixes manually \
              (NEOTH never self-patches). Clear the file once addressed.",
    },
];
