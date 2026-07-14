//! GOLD-ADAPT-HASH-01 — opthash backend microbench (opt-in, never runs by default).
//!
//! # Purpose
//!
//! Council verdict: NO production default.  The only goal is to determine whether
//! `ElasticHashMap` / `FunnelHashMap` offer a meaningful throughput advantage over
//! `std::collections::HashMap` on a realistic NEOTH key shape (String sender-ids)
//! under high-churn workloads (insert, delete, re-insert, lookup).
//!
//! # Running
//!
//! ```text
//! cargo test --features hash-bench -- bench_hash_backends --ignored --nocapture
//! ```
//!
//! Requires rustc >= 1.88 (opthash 0.10.x MSRV).  On a 1.86 toolchain cargo
//! will report an MSRV conflict for the `opthash` dep — upgrade the toolchain or
//! accept the verdict: SKIP, keep std.
//!
//! # Default build
//!
//! Everything below the `#[cfg(feature = "hash-bench")]` gate is excluded from
//! compilation when the feature is absent.  The single sentinel test at the bottom
//! of the file confirms that the file itself compiles in the default configuration.

// ── helper module, compiled only when the feature is active ─────────────────
#[cfg(feature = "hash-bench")]
mod bench_impl {
    use opthash::{ElasticHashMap, FunnelHashMap};
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    // ---- key generator -------------------------------------------------------

    /// Produce `n` sender-id strings in the two shapes NEOTH sees most:
    ///   - even index → `"tg:<telegram_id>"`          (Telegram numeric user-id)
    ///   - odd index  → `"wa:+1<digits>@s.whatsapp.net"` (WhatsApp JID)
    ///
    /// Both shapes are 18–40 bytes — long enough to exercise heap allocation
    /// and string-compare paths in the hasher.
    pub(super) fn make_sender_ids(n: usize) -> Vec<String> {
        (0..n)
            .map(|i| {
                if i % 2 == 0 {
                    format!("tg:{}", 100_000_000u64 + i as u64)
                } else {
                    format!("wa:+1{}@s.whatsapp.net", 2_000_000_000u64 + i as u64)
                }
            })
            .collect()
    }

    // ---- workload description ------------------------------------------------
    //
    // Phase 1 — BULK INSERT: insert all N (key, message_count) pairs.
    // Phase 2 — CHURN:
    //   * remove every key where i % 3 == 0
    //   * update value in-place for i % 3 == 1  (value *= 2)
    //   * leave i % 3 == 2 untouched
    // Phase 3 — CHURN RE-INSERT: re-insert the removed keys with value + 1.
    // Phase 4 — LOOKUP: retrieve every original key; accumulate a wrapping checksum.
    //
    // The final checksum is deterministic:
    //   i % 3 == 0  →  key present, value = i + 1
    //   i % 3 == 1  →  key present, value = i * 2
    //   i % 3 == 2  →  key present, value = i
    // All three maps must agree on the checksum.

    pub(super) struct Timings {
        pub insert: Duration,
        pub churn: Duration,
        pub reinsert: Duration,
        pub lookup: Duration,
    }

    // ---- per-map bench helpers -----------------------------------------------

    pub(super) fn run_std(keys: &[String], n: usize) -> (u64, Timings) {
        let mut map: HashMap<&str, u64> = HashMap::with_capacity(n);

        let t0 = Instant::now();
        for (i, k) in keys.iter().enumerate() {
            map.insert(k.as_str(), i as u64);
        }
        let insert = t0.elapsed();

        let t1 = Instant::now();
        for (i, k) in keys.iter().enumerate() {
            match i % 3 {
                0 => {
                    map.remove(k.as_str());
                }
                1 => {
                    if let Some(v) = map.get_mut(k.as_str()) {
                        *v *= 2;
                    }
                }
                _ => {}
            }
        }
        let churn = t1.elapsed();

        let t2 = Instant::now();
        for (i, k) in keys.iter().enumerate() {
            if i % 3 == 0 {
                map.insert(k.as_str(), i as u64 + 1);
            }
        }
        let reinsert = t2.elapsed();

        let t3 = Instant::now();
        let mut sum: u64 = 0;
        for k in keys.iter() {
            if let Some(&v) = map.get(k.as_str()) {
                sum = sum.wrapping_add(v);
            }
        }
        let lookup = t3.elapsed();

        (
            sum,
            Timings {
                insert,
                churn,
                reinsert,
                lookup,
            },
        )
    }

    pub(super) fn run_elastic(keys: &[String], n: usize) -> (u64, Timings) {
        let mut map: ElasticHashMap<&str, u64> = ElasticHashMap::with_capacity(n);

        let t0 = Instant::now();
        for (i, k) in keys.iter().enumerate() {
            map.insert(k.as_str(), i as u64);
        }
        let insert = t0.elapsed();

        let t1 = Instant::now();
        for (i, k) in keys.iter().enumerate() {
            match i % 3 {
                0 => {
                    map.remove(k.as_str());
                }
                1 => {
                    if let Some(v) = map.get_mut(k.as_str()) {
                        *v *= 2;
                    }
                }
                _ => {}
            }
        }
        let churn = t1.elapsed();

        let t2 = Instant::now();
        for (i, k) in keys.iter().enumerate() {
            if i % 3 == 0 {
                map.insert(k.as_str(), i as u64 + 1);
            }
        }
        let reinsert = t2.elapsed();

        let t3 = Instant::now();
        let mut sum: u64 = 0;
        for k in keys.iter() {
            if let Some(&v) = map.get(k.as_str()) {
                sum = sum.wrapping_add(v);
            }
        }
        let lookup = t3.elapsed();

        (
            sum,
            Timings {
                insert,
                churn,
                reinsert,
                lookup,
            },
        )
    }

    pub(super) fn run_funnel(keys: &[String], n: usize) -> (u64, Timings) {
        let mut map: FunnelHashMap<&str, u64> = FunnelHashMap::with_capacity(n);

        let t0 = Instant::now();
        for (i, k) in keys.iter().enumerate() {
            map.insert(k.as_str(), i as u64);
        }
        let insert = t0.elapsed();

        let t1 = Instant::now();
        for (i, k) in keys.iter().enumerate() {
            match i % 3 {
                0 => {
                    map.remove(k.as_str());
                }
                1 => {
                    if let Some(v) = map.get_mut(k.as_str()) {
                        *v *= 2;
                    }
                }
                _ => {}
            }
        }
        let churn = t1.elapsed();

        let t2 = Instant::now();
        for (i, k) in keys.iter().enumerate() {
            if i % 3 == 0 {
                map.insert(k.as_str(), i as u64 + 1);
            }
        }
        let reinsert = t2.elapsed();

        let t3 = Instant::now();
        let mut sum: u64 = 0;
        for k in keys.iter() {
            if let Some(&v) = map.get(k.as_str()) {
                sum = sum.wrapping_add(v);
            }
        }
        let lookup = t3.elapsed();

        (
            sum,
            Timings {
                insert,
                churn,
                reinsert,
                lookup,
            },
        )
    }

    fn print_row(label: &str, t: &Timings) {
        println!(
            "{:<20} insert={:>10?}  churn={:>10?}  reinsert={:>10?}  lookup={:>10?}  total={:>10?}",
            label,
            t.insert,
            t.churn,
            t.reinsert,
            t.lookup,
            t.insert + t.churn + t.reinsert + t.lookup,
        );
    }

    // ── the actual test ──────────────────────────────────────────────────────

    #[test]
    #[ignore = "GOLD-ADAPT-HASH-01: cargo test --features hash-bench -- bench_hash_backends --ignored --nocapture"]
    pub(super) fn bench_hash_backends() {
        const N: usize = 50_000;
        let keys = make_sender_ids(N);

        // ---- warm-up run (populate instruction/data caches) ------------------
        let _ = run_std(&keys, N);
        let _ = run_elastic(&keys, N);
        let _ = run_funnel(&keys, N);

        // ---- measured runs ---------------------------------------------------
        let (std_sum, std_t) = run_std(&keys, N);
        let (el_sum, el_t) = run_elastic(&keys, N);
        let (fn_sum, fn_t) = run_funnel(&keys, N);

        // ---- correctness assert: all three maps agree on the aggregate -------
        assert_eq!(
            std_sum, el_sum,
            "ElasticHashMap correctness fail: aggregate differs from std::HashMap \
             (std={std_sum}, elastic={el_sum})"
        );
        assert_eq!(
            std_sum, fn_sum,
            "FunnelHashMap correctness fail: aggregate differs from std::HashMap \
             (std={std_sum}, funnel={fn_sum})"
        );

        // ---- results ---------------------------------------------------------
        println!("\n=== GOLD-ADAPT-HASH-01  N={N} sender-id String keys ===");
        println!(
            "{:<20} {:>12} {:>12} {:>12} {:>12} {:>12}",
            "impl", "insert", "churn", "reinsert", "lookup", "total"
        );
        print_row("std::HashMap", &std_t);
        print_row("ElasticHashMap", &el_t);
        print_row("FunnelHashMap", &fn_t);
        println!("checksum (all agree): {std_sum}");
        println!(
            "\nNote: opthash uses foldhash by default (faster than SipHash); \
             std::HashMap uses SipHash (DoS-resistant by design). \
             Compare total-of-work, not just raw numbers."
        );
    }
}

// ── sentinel: always compiled, always passes ────────────────────────────────
/// This test confirms the file compiles cleanly on the default build (no
/// `hash-bench` feature).  The real bench above is excluded by the `cfg` gate.
#[test]
fn hash_bench_gate_off_compiles() {
    // Feature hash-bench is OFF in the default build.
    // Enable with: cargo test --features hash-bench -- bench_hash_backends --ignored --nocapture
}

// ── re-export the bench fn so cargo's test harness can discover it ───────────
#[cfg(feature = "hash-bench")]
use bench_impl::bench_hash_backends;
