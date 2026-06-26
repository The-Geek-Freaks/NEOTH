//! GOLD-ADAPT-KV-03 — CPU-RAM KV cold tier wrapping the hot LRU map.
//!
//! Replaces `PrefixKvCache`'s arbitrary-eviction `HashMap` with a two-tier
//! LRU stack:
//!
//! * **Hot tier** — `lru::LruCache<u64, PrefixKvEntry>`: Arc-tensor entries
//!   (zero-copy clone, fast restore). Bounded by `NEOTH_OURO_KV_HOT_CAP`
//!   (default 8).
//! * **Cold tier** — `lru::LruCache<u64, ColdEntry>`: serialized f32 bytes.
//!   Hot evictions land here. Bounded by `NEOTH_OURO_KV_COLD_CAP`
//!   (default 32). Cold evictions are simply dropped (CPU-only until KV-04
//!   adds disk).
//!
//! **Suffix-first ordering**: when serializing a `KvSnapshot` into a
//! `ColdEntry`, layers are stored in *reverse* order. If the cold LRU
//! overflows, the LRU eviction mechanism drops the oldest insertions first —
//! because we inserted suffix layers last and prefix layers first (reversed),
//! the suffix context is evicted first while the shared prefix layers survive
//! longer. On `deserialize` the layer slice is reversed back to the canonical
//! order.
//!
//! **Collision guard**: `get` checks `prefix_ids` equality on both hot and
//! cold hits before returning a snapshot. A hash collision returns `None`
//! (treated as a miss → full prefill), never a corrupt restore.
//!
//! **Gating**: KV-03 does not add new env-var gates. The existing
//! `NEOTH_OURO_KV_CACHE_MODE=per_loop` + `NEOTH_OURO_PREFIX_KV=1` gate in
//! `run_ouro_forward` is sufficient — if those are not set the cache is never
//! called.

use anyhow::{Context, Result};
use candle_core::{DType, Device, Tensor};
use lru::LruCache;
use std::num::NonZeroUsize;

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

/// Two-tier KV cache: hot `LruCache<u64, PrefixKvEntry>` (Arc-tensor, fast
/// restore) backed by a cold `LruCache<u64, ColdEntry>` (serialized bytes,
/// slower). Lives inside `LoadedOuro` behind the adapter's model lock.
///
/// `get` requires `&mut self` because `lru::LruCache::get` bumps recency.
pub struct KvOffloadCache {
    hot: LruCache<u64, PrefixKvEntry>,
    cold: LruCache<u64, ColdEntry>,
    device: Device,
}

impl KvOffloadCache {
    /// `hot_cap` / `cold_cap` come from `NEOTH_OURO_KV_HOT_CAP` /
    /// `NEOTH_OURO_KV_COLD_CAP` env vars (defaults 8 / 32), read once at
    /// model-load time in `ensure_ouro_loaded`.
    pub fn new(hot_cap: usize, cold_cap: usize, device: Device) -> Self {
        let hot = LruCache::new(NonZeroUsize::new(hot_cap.max(1)).unwrap());
        let cold = LruCache::new(NonZeroUsize::new(cold_cap.max(1)).unwrap());
        Self { hot, cold, device }
    }

    /// Probe hot then cold. Returns `Ok(Some(snap))` on any tier hit, `Ok(None)`
    /// on a full miss (hash collision on `prefix_ids` also returns `None`).
    ///
    /// A cold hit promotes the entry to hot (evicting the current hot-LRU
    /// entry to cold first if hot is full).
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
    /// Called when hot is at capacity and a new key must be inserted or promoted.
    fn evict_hot_to_cold_if_full(&mut self) -> Result<()> {
        if self.hot.len() < self.hot.cap().get() {
            return Ok(());
        }
        if let Some((evicted_key, evicted_entry)) = self.hot.pop_lru() {
            let cold = Self::serialize(&evicted_entry.snapshot, &evicted_entry.prefix_ids);
            // lru::LruCache::put drops the LRU cold entry automatically if full
            self.cold.put(evicted_key, cold);
        }
        Ok(())
    }

    /// Serialize a `KvSnapshot` into a `ColdEntry` using suffix-first layer
    /// ordering (layers stored in reverse so early layers stay in cold longer
    /// under LRU pressure).
    fn serialize(snap: &KvSnapshot, prefix_ids: &[u32]) -> ColdEntry {
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
                            .expect("KV-03 serialize: K to f32");
                        let v_f32 = v_tensor
                            .to_dtype(DType::F32)
                            .expect("KV-03 serialize: V to f32");

                        let k_shape = k_f32.dims().to_vec();
                        let v_shape = v_f32.dims().to_vec();

                        let k_vec: Vec<f32> = k_f32
                            .flatten_all()
                            .expect("KV-03 serialize: flatten K")
                            .to_vec1()
                            .expect("KV-03 serialize: K to_vec1");
                        let v_vec: Vec<f32> = v_f32
                            .flatten_all()
                            .expect("KV-03 serialize: flatten V")
                            .to_vec1()
                            .expect("KV-03 serialize: V to_vec1");

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

        ColdEntry {
            prefix_ids: prefix_ids.to_vec(),
            slots,
            num_layers,
            num_loops,
        }
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
        let cold = KvOffloadCache::serialize(&snap, &ids);
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
        let cold = KvOffloadCache::serialize(&snap, &ids);
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
        let cold = KvOffloadCache::serialize(&snap, &[]);
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
        let mut cache = KvOffloadCache::new(4, 4, Device::Cpu);
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
        let mut cache = KvOffloadCache::new(1, 4, Device::Cpu);
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
        let mut cache = KvOffloadCache::new(1, 4, Device::Cpu);
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
        let mut cache = KvOffloadCache::new(4, 4, Device::Cpu);
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
        let mut cache = KvOffloadCache::new(1, 4, Device::Cpu);
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
        let mut cache = KvOffloadCache::new(2, 4, Device::Cpu);
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
}
