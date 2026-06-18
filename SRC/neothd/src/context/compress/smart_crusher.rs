//! GOLD-HR-06 — structured (JSON) compression.
//!
//! Two JsonArray transforms:
//!
//! - [`JsonMinifier`] — a faithful port of headroom's reformat: parse with
//!   `serde_json`, re-emit compact, keep whichever is shorter. Lossless, no
//!   CCR. Strips pretty-print whitespace from a JSON dump.
//! - [`SmartCrusher`] — the structured offload. A tool that returns a
//!   500-row JSON array of objects buries the signal in repetition; the model
//!   needs the *shape* + a *representative sample*, not all 500 rows. This
//!   keeps a head + strided-middle + tail sample plus a schema line, drops the
//!   rest, and stashes the byte-exact original via CCR.
//!
//! NEOTH ships a lean row-sampler rather than headroom's 20-module
//! `smart_crusher/` (statistical outlier detection, field classification,
//! saturation-curve `compute_optimal_k`). Those are quality refinements over
//! head/tail/stride sampling, not correctness — and most are primitives with
//! no consumer in NEOTH yet. The CCR marker makes any dropped row one
//! retrieval away regardless.

use std::collections::BTreeSet;
use std::fmt::Write;

use serde_json::Value;

use crate::context::compress::ccr::{CcrStore, compute_key, marker_for};
use crate::context::compress::content_detector::ContentType;
use crate::context::compress::transform::{
    CompressionContext, OffloadOutput, OffloadTransform, ReformatOutput, ReformatTransform,
    TransformError,
};

// ─── JsonMinifier (reformat) ───────────────────────────────────────────

const MINIFIER_NAME: &str = "json_minifier";

/// Whitespace-stripping JSON minifier (arrays + objects). Lossless.
#[derive(Debug, Default, Clone, Copy)]
pub struct JsonMinifier;

impl ReformatTransform for JsonMinifier {
    fn name(&self) -> &'static str {
        MINIFIER_NAME
    }

    fn applies_to(&self) -> &[ContentType] {
        &[ContentType::JsonArray]
    }

    fn apply(&self, content: &str) -> Result<ReformatOutput, TransformError> {
        let trimmed = content.trim();
        if trimmed.is_empty() {
            return Err(TransformError::skipped(MINIFIER_NAME, "empty input"));
        }
        let value: Value = serde_json::from_str(trimmed)
            .map_err(|e| TransformError::invalid_input(MINIFIER_NAME, e.to_string()))?;
        let minified = serde_json::to_string(&value)
            .map_err(|e| TransformError::internal(MINIFIER_NAME, e.to_string()))?;
        // Never inflate.
        if minified.len() >= content.len() {
            return Ok(ReformatOutput::from_lengths(
                content.len(),
                content.to_string(),
            ));
        }
        Ok(ReformatOutput::from_lengths(content.len(), minified))
    }
}

// ─── SmartCrusher (offload) ────────────────────────────────────────────

const CRUSHER_NAME: &str = "smart_crusher";
const CONFIDENCE: f32 = 0.8;

/// Tunables for [`SmartCrusher`]. Code-level defaults; not freedom.yaml.
#[derive(Debug, Clone, Copy)]
pub struct SmartCrusherConfig {
    /// Arrays shorter than this are passed through.
    pub min_rows: usize,
    /// Verbatim head rows kept.
    pub head_rows: usize,
    /// Verbatim tail rows kept.
    pub tail_rows: usize,
    /// Total rows kept (head + strided middle + tail). Beyond this, rows go
    /// to CCR only.
    pub max_keep: usize,
}

impl Default for SmartCrusherConfig {
    fn default() -> Self {
        Self {
            min_rows: 10,
            head_rows: 5,
            tail_rows: 2,
            max_keep: 20,
        }
    }
}

pub struct SmartCrusher {
    config: SmartCrusherConfig,
}

impl SmartCrusher {
    pub fn new(config: SmartCrusherConfig) -> Self {
        Self { config }
    }
}

impl Default for SmartCrusher {
    fn default() -> Self {
        Self::new(SmartCrusherConfig::default())
    }
}

impl OffloadTransform for SmartCrusher {
    fn name(&self) -> &'static str {
        CRUSHER_NAME
    }

    fn applies_to(&self) -> &[ContentType] {
        &[ContentType::JsonArray]
    }

    fn estimate_bloat(&self, content: &str) -> f32 {
        let trimmed = content.trim();
        if !trimmed.starts_with('[') {
            return 0.0;
        }
        let Ok(Value::Array(arr)) = serde_json::from_str::<Value>(trimmed) else {
            return 0.0;
        };
        let n = arr.len();
        if n < self.config.min_rows {
            return 0.0;
        }
        let keep = self.select_indices(n).len();
        ((n.saturating_sub(keep)) as f32 / n as f32).clamp(0.0, 1.0)
    }

    fn apply(
        &self,
        content: &str,
        _ctx: &CompressionContext,
        store: &dyn CcrStore,
    ) -> Result<OffloadOutput, TransformError> {
        let trimmed = content.trim();
        let value: Value = serde_json::from_str(trimmed)
            .map_err(|e| TransformError::invalid_input(CRUSHER_NAME, e.to_string()))?;
        let Value::Array(arr) = value else {
            return Err(TransformError::skipped(CRUSHER_NAME, "not a JSON array"));
        };
        let n = arr.len();
        if n < self.config.min_rows {
            return Err(TransformError::skipped(CRUSHER_NAME, "below min_rows"));
        }
        // GOLD-ADAPT-HR-04 — size the sample to the array's diversity (a uniform
        // array keeps the floor; a diverse one keeps up to max_keep).
        let cap = optimal_k(
            &arr,
            self.config.head_rows + self.config.tail_rows,
            self.config.max_keep,
        );
        let mut keep_set: BTreeSet<usize> =
            self.select_indices_capped(n, cap).into_iter().collect();
        // GOLD-ADAPT-HR-05 — pin structural outliers (a rare field or a rare
        // categorical value) outside the drop budget so a lone error row is never
        // sampled away.
        keep_set.extend(detect_outliers(&arr));
        let keep_idx: Vec<usize> = keep_set.into_iter().collect();
        if keep_idx.len() >= n {
            return Err(TransformError::skipped(CRUSHER_NAME, "nothing to drop"));
        }

        let key = compute_key(content.as_bytes());
        let marker = marker_for(&key);

        // Schema: keys of the first object row (tabular hint for the model).
        let schema = arr
            .iter()
            .find_map(|v| v.as_object())
            .map(|o| o.keys().cloned().collect::<Vec<_>>().join(","));

        let mut out = String::with_capacity(content.len() / 4);
        match &schema {
            Some(s) => {
                let _ = writeln!(
                    out,
                    "[smart_crusher: kept {} of {n} rows; schema: {s}; full array at {marker}]",
                    keep_idx.len()
                );
            }
            None => {
                let _ = writeln!(
                    out,
                    "[smart_crusher: kept {} of {n} rows; full array at {marker}]",
                    keep_idx.len()
                );
            }
        }
        // Emit the kept rows as one compact JSON sample array. The header
        // line already states it's a K-of-N sample, so no per-gap notes are
        // needed (those would dwarf the savings on arrays of small scalars).
        let sample: Vec<String> = keep_idx
            .iter()
            .map(|&idx| serde_json::to_string(&arr[idx]))
            .collect::<Result<_, _>>()
            .map_err(|e| TransformError::internal(CRUSHER_NAME, e.to_string()))?;
        out.push('[');
        out.push_str(&sample.join(","));
        out.push(']');

        if out.len() >= content.len() {
            return Err(TransformError::skipped(CRUSHER_NAME, "no byte savings"));
        }
        store.put(&key, content);
        Ok(OffloadOutput::from_lengths(content.len(), out, key))
    }

    fn confidence(&self) -> f32 {
        CONFIDENCE
    }
}

impl SmartCrusher {
    /// Sorted, de-duplicated indices to keep: head + strided middle + tail,
    /// capped at `max_keep`. Used by `estimate_bloat` (the fixed-cap estimate).
    fn select_indices(&self, n: usize) -> Vec<usize> {
        self.select_indices_capped(n, self.config.max_keep)
    }

    /// As [`select_indices`] but with an explicit keep cap, so `apply` can pass
    /// the GOLD-ADAPT-HR-04 adaptive count instead of the fixed `max_keep`.
    fn select_indices_capped(&self, n: usize, cap: usize) -> Vec<usize> {
        let cap = cap.max(1);
        let mut set: BTreeSet<usize> = BTreeSet::new();
        let head = self.config.head_rows.min(n);
        for i in 0..head {
            set.insert(i);
        }
        for i in n.saturating_sub(self.config.tail_rows)..n {
            set.insert(i);
        }
        // Fill the middle with an even stride up to the cap.
        let mid_lo = self.config.head_rows.min(n);
        let mid_hi = n.saturating_sub(self.config.tail_rows);
        if mid_hi > mid_lo && set.len() < cap {
            let remaining = cap - set.len();
            let span = mid_hi - mid_lo;
            let step = (span / (remaining + 1)).max(1);
            let mut i = mid_lo;
            while i < mid_hi && set.len() < cap {
                set.insert(i);
                i += step;
            }
        }
        set.into_iter().collect()
    }
}

/// GOLD-ADAPT-HR-04 — adaptive keep-count. A near-uniform array (rows differing
/// only in ids/numbers) needs far fewer kept rows than a diverse one. Key each
/// row with its digit runs collapsed to `#` (so `{"id":5,…}` and `{"id":7,…}`
/// share a template) and size the sample by the distinct-template count, clamped
/// to `[min_k, max_k]`.
//
// neoth: distinct-template count is the simple proxy for headroom's Kneedle
// saturation-curve compute_optimal_k (bigram-coverage knee + zlib-ratio
// validation, ~150 LOC). It captures the dominant case — id-varying homogeneous
// rows collapse to one template → keep the floor. Upgrade path: the bigram-Kneedle
// if a profile shows partially-redundant arrays leaving savings on the table.
fn optimal_k(rows: &[Value], min_k: usize, max_k: usize) -> usize {
    let mut templates: BTreeSet<String> = BTreeSet::new();
    for v in rows {
        templates.insert(digit_template(
            &serde_json::to_string(v).unwrap_or_default(),
        ));
        if templates.len() >= max_k {
            break; // already at the cap — counting further can't raise k
        }
    }
    templates.len().clamp(min_k, max_k)
}

/// A string with each run of ASCII digits collapsed to a single `#`.
fn digit_template(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_digits = false;
    for c in s.chars() {
        if c.is_ascii_digit() {
            if !in_digits {
                out.push('#');
            }
            in_digits = true;
        } else {
            out.push(c);
            in_digits = false;
        }
    }
    out
}

/// GOLD-ADAPT-HR-05 — indices of rows that must survive the drop regardless of
/// position. The strided sampler would discard the one `status:error` row at
/// index 37 of a 100-row array; this pins two classes of structural outlier:
///   1. rows carrying a RARE field (present in < 20 % of object rows), and
///   2. rows whose value of a low-cardinality field falls OUTSIDE that field's
///      Pareto 80 % cover (a rare categorical value).
fn detect_outliers(items: &[Value]) -> BTreeSet<usize> {
    use std::collections::HashMap;
    let mut must_keep: BTreeSet<usize> = BTreeSet::new();
    let objs: Vec<(usize, &serde_json::Map<String, Value>)> = items
        .iter()
        .enumerate()
        .filter_map(|(i, v)| v.as_object().map(|o| (i, o)))
        .collect();
    let n = objs.len();
    if n == 0 {
        return must_keep;
    }
    let rare_field_floor = (n as f64 * 0.20).ceil() as usize;

    // Field frequency across object rows.
    let mut field_count: HashMap<&str, usize> = HashMap::new();
    for (_, obj) in &objs {
        for k in obj.keys() {
            *field_count.entry(k.as_str()).or_insert(0) += 1;
        }
    }

    // Pass 1: a row with any rare field is a structural outlier.
    for (idx, obj) in &objs {
        if obj
            .keys()
            .any(|k| field_count.get(k.as_str()).copied().unwrap_or(0) < rare_field_floor)
        {
            must_keep.insert(*idx);
        }
    }

    // Pass 2: rare categorical values (Pareto 80 % cover) of low-cardinality fields.
    for (field, &present) in &field_count {
        if present == 0 {
            continue;
        }
        let mut val_counts: HashMap<String, usize> = HashMap::new();
        for (_, obj) in &objs {
            if let Some(v) = obj.get(*field) {
                *val_counts.entry(v.to_string()).or_insert(0) += 1;
            }
        }
        // Only genuinely categorical fields get the Pareto treatment: skip a
        // field with too many distinct values OR one where values barely repeat
        // (e.g. an `id` field where every value is unique is NOT categorical, so
        // its rare "tail" must not be mistaken for outliers).
        if val_counts.len() > 50 || val_counts.len() * 2 > present {
            continue;
        }
        let mut sorted: Vec<(&String, usize)> = val_counts.iter().map(|(k, &c)| (k, c)).collect();
        sorted.sort_by_key(|&(_, c)| std::cmp::Reverse(c));
        let target = (present as f64 * 0.80).ceil() as usize;
        let mut covered = 0usize;
        let mut top: BTreeSet<&String> = BTreeSet::new();
        for (val, cnt) in &sorted {
            top.insert(val);
            covered += cnt;
            if covered >= target {
                break;
            }
        }
        for (idx, obj) in &objs {
            if let Some(v) = obj.get(*field) {
                if !top.contains(&v.to_string()) {
                    must_keep.insert(*idx);
                }
            }
        }
    }
    must_keep
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::compress::ccr::{InMemoryCcrStore, extract_keys};

    // ── JsonMinifier ──────────────────────────────────────────────────

    #[test]
    fn minifier_strips_whitespace_losslessly() {
        let pretty = "[\n  1,\n  2,\n  3\n]";
        let r = JsonMinifier.apply(pretty).expect("parses");
        assert_eq!(r.output, "[1,2,3]");
        assert!(r.bytes_saved > 0);
    }

    #[test]
    fn minifier_invalid_and_empty() {
        assert!(matches!(
            JsonMinifier.apply("{not: valid"),
            Err(TransformError::InvalidInput { .. })
        ));
        assert!(matches!(
            JsonMinifier.apply(""),
            Err(TransformError::Skipped { .. })
        ));
    }

    #[test]
    fn minifier_never_grows() {
        for input in [r#"{}"#, r#"[]"#, r#"42"#, r#"{"k":"v"}"#] {
            let r = JsonMinifier.apply(input).expect("valid");
            assert!(r.output.len() <= input.len());
        }
    }

    // ── SmartCrusher ──────────────────────────────────────────────────

    fn crusher() -> SmartCrusher {
        SmartCrusher::default()
    }

    fn tabular_array(rows: usize) -> String {
        let items: Vec<String> = (0..rows)
            .map(|i| format!(r#"{{"id":{i},"name":"event-{i}","value":{}}}"#, i * 10))
            .collect();
        format!("[{}]", items.join(","))
    }

    #[test]
    fn name_and_applies_to() {
        assert_eq!(crusher().name(), "smart_crusher");
        assert_eq!(crusher().applies_to(), &[ContentType::JsonArray]);
    }

    #[test]
    fn small_array_and_non_array_score_zero() {
        assert_eq!(crusher().estimate_bloat(&tabular_array(5)), 0.0);
        assert_eq!(crusher().estimate_bloat(r#"{"a":1}"#), 0.0);
        assert_eq!(crusher().estimate_bloat("not json"), 0.0);
    }

    #[test]
    fn large_array_scores_high() {
        // 500 rows, keep 20 → ~0.96 droppable.
        assert!(crusher().estimate_bloat(&tabular_array(500)) > 0.9);
    }

    #[test]
    fn crush_keeps_sample_schema_and_round_trips_via_ccr() {
        let input = tabular_array(500);
        let store = InMemoryCcrStore::new();
        let r = crusher()
            .apply(&input, &CompressionContext::default(), &store)
            .expect("crushes large array");
        assert!(r.bytes_saved > 0);
        assert!(r.output.len() < input.len() / 4, "strong savings expected");
        // Schema + sample present; header states the K-of-N sample.
        assert!(r.output.contains("schema: id,name,value"));
        assert!(r.output.contains("of 500 rows"));
        assert!(r.output.contains(r#""id":0"#)); // head kept
        assert!(r.output.contains(r#""id":499"#)); // tail kept
        // CCR round-trip.
        assert_eq!(store.get(&r.cache_key).as_deref(), Some(input.as_str()));
        assert_eq!(extract_keys(&r.output)[0], r.cache_key);
    }

    #[test]
    fn crush_skips_small_array() {
        let input = tabular_array(5);
        let store = InMemoryCcrStore::new();
        assert!(matches!(
            crusher().apply(&input, &CompressionContext::default(), &store),
            Err(TransformError::Skipped { .. })
        ));
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn crush_scalar_array_without_schema() {
        let input = format!(
            "[{}]",
            (0..100)
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        let store = InMemoryCcrStore::new();
        let r = crusher()
            .apply(&input, &CompressionContext::default(), &store)
            .expect("crushes scalar array");
        assert!(!r.output.contains("schema:"));
        assert!(r.bytes_saved > 0);
        assert_eq!(store.get(&r.cache_key).as_deref(), Some(input.as_str()));
    }

    #[test]
    fn select_indices_includes_head_and_tail() {
        let c = crusher();
        let idx = c.select_indices(500);
        assert!(idx.len() <= c.config.max_keep);
        assert!(idx.contains(&0)); // head
        assert!(idx.contains(&499)); // tail
        // Sorted + unique.
        let mut sorted = idx.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(idx, sorted);
    }

    #[test]
    fn optimal_k_uniform_array_keeps_the_floor() {
        // 100 rows differing only in numbers → one template → keep the floor.
        let rows: Vec<Value> = (0..100)
            .map(|i| serde_json::json!({"id": i, "status": "ok"}))
            .collect();
        assert_eq!(optimal_k(&rows, 7, 20), 7);
    }

    #[test]
    fn optimal_k_distinct_content_keeps_more_than_floor() {
        let colors = [
            "red", "green", "blue", "cyan", "magenta", "yellow", "black", "white", "gray", "pink",
            "orange", "purple",
        ];
        let rows: Vec<Value> = colors
            .iter()
            .map(|c| serde_json::json!({"color": c}))
            .collect();
        // 12 distinct templates → clamp(12, [3,20]) = 12 (above the floor).
        assert_eq!(optimal_k(&rows, 3, 20), 12);
    }

    #[test]
    fn detect_outliers_pins_rare_categorical_value() {
        // 99 status=ok, 1 status=error → the error row is a must-keep outlier;
        // the `id` field (every value unique) must NOT be treated as categorical.
        let mut rows: Vec<Value> = (0..100)
            .map(|i| serde_json::json!({"id": i, "status": "ok"}))
            .collect();
        rows[37] = serde_json::json!({"id": 37, "status": "error"});
        let outliers = detect_outliers(&rows);
        assert!(outliers.contains(&37), "rare status=error row pinned");
        assert_eq!(
            outliers.len(),
            1,
            "the unique-id field must not over-flag the tail"
        );
    }

    #[test]
    fn detect_outliers_pins_rare_field() {
        let mut rows: Vec<Value> = (0..10).map(|i| serde_json::json!({"id": i})).collect();
        rows.push(serde_json::json!({"id": 10, "trace": "boom"}));
        assert!(detect_outliers(&rows).contains(&10));
    }

    #[test]
    fn crush_keeps_the_rare_error_row_end_to_end() {
        // The strided sampler alone would drop index 37; HR-05 pins it.
        let mut items: Vec<String> = (0..100)
            .map(|i| format!(r#"{{"id":{i},"status":"ok"}}"#))
            .collect();
        items[37] = r#"{"id":37,"status":"error"}"#.to_string();
        let input = format!("[{}]", items.join(","));
        let store = InMemoryCcrStore::new();
        let r = crusher()
            .apply(&input, &CompressionContext::default(), &store)
            .expect("crushes");
        assert!(
            r.output.contains(r#""status":"error""#),
            "the rare error row must survive: {}",
            r.output
        );
    }
}
