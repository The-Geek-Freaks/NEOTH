//! Typed row structs returned by recall queries.

/// One row from `idx_episode` (hot tier), `idx_consolidated` (warm) or
/// `idx_longterm` (cold). Returned to the recall CLI for display.
///
/// `tier` defaults to `"hot"` for backwards compat — pre-tier callers
/// still produce the same JSON shape because the field carries the
/// historical interpretation when omitted on deserialise.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EpisodeHit {
    pub event_id: i64,
    pub event_type: u8,
    pub ts_ns: i64,
    pub text: String,
    pub text_hash: String,
    pub channel: Option<String>,
    pub sender_id: Option<String>,
    pub operator_id: Option<String>,
    /// Which tier this row came from — `"hot"`, `"warm"`, or `"cold"`.
    /// Defaults to `"hot"` so old serialised payloads round-trip.
    #[serde(default = "default_hot_tier")]
    pub tier: String,
    /// Importance score at recall time. Optional because the cold tier
    /// has it, but pre-tier hot-tier hits did not record it.
    #[serde(default)]
    pub importance: Option<f64>,
    /// JV-MEM-05: recall `access_count` for hot-tier rows. The ranker stretches
    /// a frequently-accessed memory's recency half-life so it decays slower.
    /// 0 for warm/cold/groundtruth rows (no per-row count) and old payloads.
    #[serde(default)]
    pub access_count: u32,
}

fn default_hot_tier() -> String {
    "hot".to_string()
}
