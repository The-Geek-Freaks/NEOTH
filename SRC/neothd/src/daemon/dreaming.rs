//! R-02 Dreaming pipeline — scaffold.
//!
//! Vision: periodically (default: nightly) the daemon surveys the
//! day's events, identifies thematic clusters, and writes a "dream"
//! entry that compresses the day into a few semantic anchors. Future
//! recall reads dreams BEFORE digging through individual events —
//! same shape as a human brain reaching for "what happened
//! yesterday?" before "what was the third sentence at 14:32?".
//!
//! This module ships the storage + types + composer shape so future
//! work (LLM-driven clustering, theme detection, embedding-based
//! recall hook) snaps in without rewriting the surface. The
//! ACTUAL clustering pass is multi-week — for now `compose_dream`
//! produces a deterministic snapshot of the input events that
//! operators can read + a Dream Day record that the pipeline can
//! later refine.
//!
//! Storage: `~/.neoth/dreams/<YYYY-MM-DD>.jsonl`. One dream per
//! line. Append-only — historical dreams stay readable as the
//! schema evolves (any added field is `serde(default)`).
//!
//! ## Pipeline shape (future Phase 2)
//!
//! 1. `gather_day_events(home, date)` — load every event from the
//!    WAL + idx_episode for the target day
//! 2. `cluster_themes(events)` — embedding-based + topic-modelling
//!    grouping (Phase 2 — needs Day-14b local inference)
//! 3. For each theme:
//!    a. `summarise_theme(theme_events) -> String` (Phase 2 — LLM)
//!    b. `compose_dream(theme_summary, events, motifs) -> Dream`
//!    c. `append_dream(home, &dream)` — JSONL persist
//! 4. `recall::seed_with_dreams(home, n)` — surface the N latest
//!    dreams BEFORE episode rows (Phase 2 wiring into existing
//!    recall composite score)

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::providers::{Provider, Request};

/// One persisted dream entry. The deterministic v0.1 composer
/// fills `theme_label` with a stable string derived from input
/// event ids; Phase 2 replaces this with LLM-summarised themes
/// while keeping the wire shape stable.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct Dream {
    /// Unix seconds at composition time.
    pub composed_ts_unix: i64,
    /// Date this dream summarises (`YYYY-MM-DD` UTC).
    pub day: String,
    /// Operator-readable theme label. v0.1 deterministic; Phase 2
    /// becomes an LLM-summarised motif.
    pub theme_label: String,
    /// Compressed narrative of the theme. v0.1 prints the source
    /// event count + first/last timestamps; Phase 2 becomes a
    /// 2-3 sentence LLM summary.
    pub summary: String,
    /// Source-event anchors so the recall layer can drill from a
    /// dream BACK to the underlying events.
    pub event_ids: Vec<i64>,
    /// Tags for fast filtering. v0.1 empty; Phase 2 fills with
    /// motif keywords.
    pub tags: Vec<String>,
}

/// Input to `compose_dream` — minimal event shape that doesn't
/// pull in WAL types so the composer stays unit-testable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRef {
    pub id: i64,
    pub ts_unix: i64,
    /// Truncated preview the composer surfaces in the summary.
    pub preview: String,
}

impl Dream {
    /// OB-01a (Session 24) — render this dream as an Obsidian-
    /// flavoured markdown document. Returns a string ready to
    /// drop into `~/Obsidian/NEOTH/Dreams/YYYY-MM-DD.md` (one
    /// dream per file when called from OB-01's nightly cron, or
    /// concatenated when N-06's weekly digest workflow runs).
    ///
    /// ## Layout
    ///
    /// 1. **YAML frontmatter** — Obsidian's metadata convention.
    ///    Carries `day` / `theme` / `composed_unix` / `event_count`
    ///    / `tags` so Dataview queries can filter dreams without
    ///    parsing the body.
    /// 2. **H1 heading** with the day + theme label.
    /// 3. **Summary block** with the deterministic narrative.
    /// 4. **Source events list** — bulleted `event_id` references
    ///    so the operator can jump back to the WAL frame via
    ///    `neoth wal show --event-id <id>`.
    ///
    /// ## Why YAML frontmatter + not just plain markdown
    ///
    /// Obsidian's Dataview plugin (the most common operator
    /// workflow) indexes frontmatter fields automatically. A
    /// dream file without frontmatter loses the date-filter +
    /// theme-filter that operators rely on. The serializer
    /// emits it unconditionally — empty `tags: []` is preferred
    /// over a missing field for the same reason.
    ///
    /// ## Drift guard
    ///
    /// Pinned by the tests:
    /// - Frontmatter `---` delimiters
    /// - Field order: day → theme → composed_unix → event_count → tags
    /// - H1 heading shape `# Dream YYYY-MM-DD — <theme>`
    /// - Empty event list renders an explicit "(no source events)"
    ///   line rather than an empty bullet section (Dataview prefers
    ///   non-empty sections)
    pub fn to_obsidian_md(&self) -> String {
        let yaml_tags = if self.tags.is_empty() {
            "[]".to_string()
        } else {
            // YAML inline-list form with quoted tags so an operator-
            // typed `#tag` literal can't accidentally start a YAML
            // anchor or comment.
            let quoted: Vec<String> = self
                .tags
                .iter()
                .map(|t| format!("\"{}\"", t.replace('"', "\\\"")))
                .collect();
            format!("[{}]", quoted.join(", "))
        };
        let body_events = if self.event_ids.is_empty() {
            "(no source events)".to_string()
        } else {
            self.event_ids
                .iter()
                .map(|id| format!("- event_id: `{id}`"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        format!(
            "---\n\
             day: \"{day}\"\n\
             theme: \"{theme}\"\n\
             composed_unix: {composed}\n\
             event_count: {count}\n\
             tags: {tags}\n\
             ---\n\
             \n\
             # Dream {day} — {theme}\n\
             \n\
             ## Summary\n\
             \n\
             {summary}\n\
             \n\
             ## Source events\n\
             \n\
             {events}\n",
            day = self.day,
            theme = escape_yaml_string(&self.theme_label),
            composed = self.composed_ts_unix,
            count = self.event_ids.len(),
            tags = yaml_tags,
            summary = self.summary,
            events = body_events,
        )
    }
}

/// Escape a string for safe embedding inside a YAML double-quoted
/// scalar. Operator-supplied theme labels can contain `"` or `\`
/// which would otherwise break the frontmatter parser. Conservative:
/// every `\` and `"` gets backslash-escaped; everything else passes
/// through verbatim (newlines in theme labels are not expected; if
/// they appear, they survive as literal `\n` which Dataview tolerates).
fn escape_yaml_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Directory under `home` that holds the daily JSONL files.
pub fn dreams_dir(home: &Path) -> PathBuf {
    home.join("dreams")
}

/// File for a given `YYYY-MM-DD`.
pub fn jsonl_file_for_day(home: &Path, day: &str) -> PathBuf {
    dreams_dir(home).join(format!("{day}.jsonl"))
}

/// Compose one dream entry from a slice of events + a deterministic
/// theme label. v0.1 produces a stable snapshot the operator can
/// read; Phase 2 replaces this with LLM-driven clustering +
/// summarisation while keeping the return shape stable.
pub fn compose_dream(day: &str, theme_label: &str, events: &[EventRef]) -> Dream {
    let composed_ts_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let summary = if events.is_empty() {
        format!("Theme `{theme_label}`: no events in window.")
    } else {
        let first_ts = events.iter().map(|e| e.ts_unix).min().unwrap_or(0);
        let last_ts = events.iter().map(|e| e.ts_unix).max().unwrap_or(0);
        // Surface the first 2 + last event previews to give the
        // operator a quick "what was this about" anchor. Truncate
        // each preview at 120 chars char-boundary-safe.
        let mut anchors: Vec<String> = events
            .iter()
            .take(2)
            .map(|e| truncate_safe(&e.preview, 120))
            .collect();
        if events.len() > 2 {
            let last = events.last().unwrap();
            anchors.push(format!("… {}", truncate_safe(&last.preview, 120)));
        }
        format!(
            "Theme `{theme_label}`: {} events between ts={} and ts={}. Anchors: {}",
            events.len(),
            first_ts,
            last_ts,
            anchors.join(" | "),
        )
    };
    Dream {
        composed_ts_unix,
        day: day.to_string(),
        theme_label: theme_label.to_string(),
        summary,
        event_ids: events.iter().map(|e| e.id).collect(),
        tags: Vec::new(),
    }
}

/// Append one dream to its date-keyed JSONL. Creates the dreams
/// dir on demand. Best-effort I/O; the caller decides whether to
/// warn-and-continue or surface the error.
pub fn append_dream(home: &Path, dream: &Dream) -> std::io::Result<()> {
    fs::create_dir_all(dreams_dir(home))?;
    let path = jsonl_file_for_day(home, &dream.day);
    let mut line = serde_json::to_vec(dream).map_err(std::io::Error::other)?;
    line.push(b'\n');
    let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
    f.write_all(&line)?;
    f.flush()?;
    Ok(())
}

/// Load every dream for `day` (`YYYY-MM-DD`). Missing file → empty.
/// Malformed lines are skipped — corrupted disk states don't kill
/// the read path.
pub fn load_dreams_for_day(home: &Path, day: &str) -> Vec<Dream> {
    let path = jsonl_file_for_day(home, day);
    let Ok(body) = fs::read_to_string(&path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in body.lines() {
        if let Ok(d) = serde_json::from_str::<Dream>(line) {
            out.push(d);
        }
    }
    out
}

/// R-02 Phase 2: load every dream from the last `lookback_days`
/// days, filter to those whose theme_label OR summary OR tags
/// contain `query` (case-insensitive substring), and return up to
/// `max_hits`. Sorted by `composed_ts_unix` descending so the
/// newest dreams surface first — the recall layer prepends these
/// rows BEFORE episode hits so an operator's "what happened
/// yesterday" question reaches yesterday's dreams first.
pub fn seed_with_dreams(
    home: &Path,
    query: &str,
    lookback_days: u32,
    max_hits: usize,
) -> Vec<Dream> {
    let q = query.to_lowercase();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut all = Vec::new();
    for back in 0..lookback_days as i64 {
        let ts = now - back * 86_400;
        let day = format_date_utc(ts);
        for dream in load_dreams_for_day(home, &day) {
            let hay = format!(
                "{} {} {}",
                dream.theme_label.to_lowercase(),
                dream.summary.to_lowercase(),
                dream.tags.join(" ").to_lowercase(),
            );
            if q.is_empty() || hay.contains(&q) {
                all.push(dream);
            }
        }
    }
    all.sort_by_key(|d| std::cmp::Reverse(d.composed_ts_unix));
    all.truncate(max_hits);
    all
}

/// Outcome of [`sync_dreams_to_obsidian`]. Caller uses `written` to
/// decide whether to emit a success line or skip the audit row when
/// the day had no dreams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamSyncOutcome {
    pub day: String,
    /// `true` when at least one dream existed and the file was
    /// written. `false` for empty days — no file is created in that
    /// case so the operator's vault stays clean.
    pub written: bool,
    /// Final on-disk path. For empty days this still reflects where
    /// the file would have been written — useful for dry-run UIs.
    pub target_path: PathBuf,
    pub dream_count: usize,
    /// Total bytes written. 0 for empty days.
    pub bytes_written: usize,
}

/// OB-01 — collect every dream for `day` from the NEOTH home dir
/// and write a single Obsidian-formatted markdown file to
/// `<vault>/<subdir>/Dreams/<day>.md`. Multiple dreams for the
/// same day concatenate with a thematic-break `\n---\n\n` so the
/// rendered note reads as one daily compilation; the YAML
/// frontmatter on dream #1 is kept and the rest stack under it.
///
/// Atomic write: the body lands in `<file>.tmp` first, then a
/// rename swaps it into place — operators editing the vault while
/// NEOTH writes never see a half-flushed file.
///
/// Empty-day behaviour: when no dreams exist for `day`, no file is
/// created. The vault's Dreams folder stays unpolluted by quiet
/// days. The caller can show a "no dreams on YYYY-MM-DD" line if
/// needed via the `written: false` return.
pub fn sync_dreams_to_obsidian(
    neoth_home: &Path,
    vault_root: &Path,
    subdir: &str,
    day: &str,
) -> std::io::Result<DreamSyncOutcome> {
    let dreams = load_dreams_for_day(neoth_home, day);
    let dreams_dir = vault_root.join(subdir).join("Dreams");
    let target_path = dreams_dir.join(format!("{day}.md"));

    if dreams.is_empty() {
        return Ok(DreamSyncOutcome {
            day: day.to_string(),
            written: false,
            target_path,
            dream_count: 0,
            bytes_written: 0,
        });
    }

    let body: String = dreams
        .iter()
        .map(Dream::to_obsidian_md)
        .collect::<Vec<_>>()
        .join("\n---\n\n");

    fs::create_dir_all(&dreams_dir)?;
    let tmp_path = dreams_dir.join(format!("{day}.md.tmp"));
    // Atomic-rename pattern: write to .tmp, fsync, rename. On Windows
    // `rename` over an existing file fails — remove the target first.
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)?;
        f.write_all(body.as_bytes())?;
        f.flush()?;
    }
    if target_path.exists() {
        fs::remove_file(&target_path)?;
    }
    fs::rename(&tmp_path, &target_path)?;

    Ok(DreamSyncOutcome {
        day: day.to_string(),
        written: true,
        target_path,
        dream_count: dreams.len(),
        bytes_written: body.len(),
    })
}

fn format_date_utc(ts_unix: i64) -> String {
    // Same Howard Hinnant civil-from-days algorithm as usage_log.
    let days = ts_unix.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let yy = if m <= 2 { y + 1 } else { y };
    format!("{yy:04}-{m:02}-{d:02}")
}

/// Char-boundary-safe truncation. Same shape as the helpers in
/// usage_log + skills::router so a future audit finds them
/// together.
fn truncate_safe(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max_chars).collect();
        out.push('…');
        out
    }
}

// ── Day-14b Phase 4: R-02 dreaming episodic clustering ───────────────

/// Embed a slice of events via the operator's `EmbedProvider`.
/// Returns one L2-normalised vector per event (in input order).
/// Individual failures bubble up as `Err` — the caller short-
/// circuits the dreaming pass + falls back to deterministic theme
/// labels (today's `compose_dream` shape) per the L-07 safe-default.
pub async fn embed_events(
    events: &[EventRef],
    provider: &dyn crate::providers::embed::EmbedProvider,
) -> anyhow::Result<Vec<Vec<f32>>> {
    use crate::providers::embed::EmbedRequest;
    let mut out = Vec::with_capacity(events.len());
    for ev in events {
        let resp = provider
            .embed(EmbedRequest::new(ev.preview.clone()))
            .await?;
        out.push(resp.vector);
    }
    Ok(out)
}

/// Cosine threshold above which two event embeddings are considered
/// to belong to the same theme cluster. 0.55 is a deliberate compromise:
///   - Lower than the skill router's 0.72 (event previews are
///     short + noisy; tighter threshold over-fragments themes)
///   - Higher than 0.5 (the "random pair" baseline for natural-language
///     embeddings on Qwen2.5 — anything below this is noise)
/// Operators tune via `freedom.yaml::dreaming.cluster_threshold` once
/// the wizard step ships (Phase 4b).
pub const DREAMING_CLUSTER_THRESHOLD: f32 = 0.55;

/// SPEC-12 cross-theme merge: cosine threshold above which two ALREADY-distinct
/// per-cluster centroids collapse into one meta-theme. Stricter than
/// [`DREAMING_CLUSTER_THRESHOLD`] (0.55) — two clusters the intra-event pass kept
/// apart should only re-merge when their centroids are genuinely co-located, not
/// merely loosely related. Off by default (`freedom.yaml::dreaming.merge_cross_themes`).
pub const DREAMING_CROSS_THEME_THRESHOLD: f32 = 0.75;

// ── SPEC-12 Phase 4b: LLM theme summarisation ───────────────────────────

/// Max characters of one event preview fed into the theme-summary prompt.
/// Bounds the prompt even when a cluster holds long events.
const THEME_SUMMARY_PREVIEW_CHARS: usize = 200;
/// Max previews included in the prompt. A cluster can be large; the first
/// N give the model enough signal without an unbounded prompt.
const THEME_SUMMARY_MAX_PREVIEWS: usize = 12;
/// Max characters of the sanitised theme label (the rest is a `…` clamp).
const THEME_LABEL_MAX_CHARS: usize = 60;

/// Build the theme-summarisation prompt from a cluster's event previews.
/// Pure + deterministic (no wall-clock, no RNG) so the prompt is replay-
/// stable for a given cluster. Each preview is trimmed + truncated and the
/// count is capped to keep the prompt bounded.
///
/// **Privacy gate (SPEC-12):** the chat provider that labels the cluster may be
/// a metered cloud model (the operator opted into `summarize_themes`), so every
/// preview is run through [`crate::security::redact::redact_text`] FIRST —
/// secrets/keys/tokens/PII never leave the device inside a summarisation
/// prompt, even though the operator opted into LLM labels. Redact-then-truncate
/// so a clipped preview can't leak a partial secret.
pub fn build_theme_summary_prompt(previews: &[String]) -> String {
    let mut body = String::new();
    for p in previews.iter().take(THEME_SUMMARY_MAX_PREVIEWS) {
        let redacted = crate::security::redact::redact_text(p.trim());
        let trimmed = truncate_safe(redacted.trim(), THEME_SUMMARY_PREVIEW_CHARS);
        if trimmed.is_empty() {
            continue;
        }
        body.push_str("- ");
        body.push_str(&trimmed);
        body.push('\n');
    }
    format!(
        "You are labelling a cluster of related memory snippets for a personal \
         AI's nightly dream journal. Read the snippets and reply with ONLY a short \
         theme label of 3 to 6 words — no punctuation, no quotes, no preamble, no \
         explanation.\n\n\
         Snippets:\n{body}\nTheme label:"
    )
}

/// Sanitise a raw LLM theme label into a safe, bounded, single-line string.
/// Replaces control chars with spaces, collapses whitespace runs, strips
/// wrapping quotes/backticks, and clamps the length. An empty result (model
/// returned nothing usable) falls back to `fallback` — the deterministic
/// `cluster-N-seed-id` label — so a useless reply never blanks the theme.
pub fn sanitize_theme_label(raw: &str, fallback: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let collapsed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    let unquoted = collapsed
        .trim_matches(|c| c == '"' || c == '\'' || c == '`')
        .trim();
    if unquoted.is_empty() {
        return fallback.to_string();
    }
    truncate_safe(unquoted, THEME_LABEL_MAX_CHARS)
}

/// Summarise one cluster's theme via the chat `provider`, or return the
/// deterministic `fallback` label. Best-effort: `chat = None`, a provider
/// error, or an empty/garbage reply all yield `fallback` — theme
/// summarisation NEVER fails the dreaming pass (the dreams are the product;
/// the label is a nicety).
async fn summarise_or_fallback(
    chat: Option<&dyn Provider>,
    cluster_events: &[EventRef],
    fallback: &str,
) -> String {
    let Some(provider) = chat else {
        return fallback.to_string();
    };
    let previews: Vec<String> = cluster_events.iter().map(|e| e.preview.clone()).collect();
    let prompt = build_theme_summary_prompt(&previews);
    let req = Request {
        prompt,
        ..Default::default()
    };
    match provider.complete(req).await {
        Ok(c) => sanitize_theme_label(&c.text, fallback),
        Err(e) => {
            tracing::warn!(
                error = %e,
                cluster = %fallback,
                "dreaming: theme summarisation failed; using deterministic label",
            );
            fallback.to_string()
        }
    }
}

/// Single-linkage agglomerative clustering on event embeddings.
///
/// Input: parallel slices — `events[i]` ↔ `embeddings[i]`. Output:
/// groups of event indices, where each group represents one theme
/// cluster. The first event in each group is the cluster seed; every
/// subsequent event in the group has cosine ≥ threshold to at least
/// one already-included event (single-linkage).
///
/// Empty input → empty output. Mismatched slice lengths → empty output
/// (defensive — caller bug, but the dreaming pass shouldn't panic on
/// a stale snapshot).
///
/// Pure function — no I/O. The actual cosine math lives in
/// `providers::embed::cosine`. Single-pass `O(N²)` — fine for the
/// 50-500 events/day workload R-02 expects; if dreaming ever runs
/// on >5k events we'd swap to HNSW or an LSH approximation.
pub fn cluster_events_by_cosine(
    events: &[EventRef],
    embeddings: &[Vec<f32>],
    threshold: f32,
) -> Vec<Vec<usize>> {
    if events.is_empty() || events.len() != embeddings.len() {
        return Vec::new();
    }
    let n = events.len();
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for i in 0..n {
        let mut placed = false;
        for group in groups.iter_mut() {
            // Single-linkage: i joins the group if it crosses
            // threshold to ANY existing member.
            let hits_any = group.iter().any(|&j| {
                crate::providers::embed::cosine(&embeddings[i], &embeddings[j]) >= threshold
            });
            if hits_any {
                group.push(i);
                placed = true;
                break;
            }
        }
        if !placed {
            groups.push(vec![i]);
        }
    }
    groups
}

/// Orchestrator: embed every event, cluster by cosine, compose one
/// Dream per cluster. When `chat` is `Some`, each cluster's theme label
/// is summarised by the chat provider (SPEC-12 Phase 4b — turns
/// `cluster-3-seed-918` into a real motif); when `None` (or a per-cluster
/// summary call fails) it falls back to the deterministic
/// `cluster-N-seed-id` label so the shape never breaks.
///
/// Returns `Err` when any embed call fails — the dreaming task in
/// `daemon/dreaming_task.rs` (Phase 4c) catches this + falls back to
/// the deterministic `compose_dream` path so the operator still
/// gets a dream entry per day even when local inference is down. A chat
/// (theme-summary) failure is NON-fatal — it degrades that one label,
/// never the pass.
/// SPEC-12 cross-theme dependency merging (clustering-of-clusters). Merge Dreams
/// whose per-cluster centroid embeddings have cosine ≥ `threshold` into one
/// meta-theme. PURE — no I/O, no async, no RNG; `O(K²)` over K clusters (a day's
/// clusters number in the low tens).
///
/// - `cluster_groups[i]` are the event-index members of `dreams[i]`.
/// - `embeddings` is the full per-event slice (same indexing as the original
///   `events`). The centroid of cluster `i` is the **L2-normalised** mean of its
///   members' embeddings — normalisation is load-bearing: the mean of unit
///   vectors is NOT unit-length, so an un-normalised centroid would deflate every
///   cross-cluster cosine and the threshold would never fire.
///
/// Single-linkage agglomeration over centroids (same shape as
/// [`cluster_events_by_cosine`]). The first cluster of a merged group is the seed
/// (gives `day` / `composed_ts_unix` / the leading label); members' `event_ids`
/// (de-duplicated, input order) + `tags` (de-duplicated, sorted) are unioned; the
/// merged label is `"<a> + <b>"` (sanitised + clamped) and the summary is
/// prefixed `"Merged N themes: …"`. Clusters not merged pass through unchanged.
/// Defensive: returns the input clone when `dreams.len() < 2`, on a
/// `cluster_groups` length mismatch, or when embeddings have zero dimension.
pub fn merge_overlapping_dreams(
    dreams: &[Dream],
    cluster_groups: &[Vec<usize>],
    embeddings: &[Vec<f32>],
    threshold: f32,
) -> Vec<Dream> {
    if dreams.len() < 2 || cluster_groups.len() != dreams.len() {
        return dreams.to_vec();
    }
    let dim = embeddings.iter().map(|e| e.len()).max().unwrap_or(0);
    if dim == 0 {
        return dreams.to_vec();
    }
    // L2-normalised centroid per cluster (mean of member embeddings, normalised).
    let centroids: Vec<Vec<f32>> = cluster_groups
        .iter()
        .map(|members| {
            let mut c = vec![0.0f32; dim];
            let mut n = 0usize;
            for &j in members {
                if let Some(e) = embeddings.get(j) {
                    for (slot, v) in e.iter().enumerate().take(dim) {
                        c[slot] += *v;
                    }
                    n += 1;
                }
            }
            if n > 0 {
                let inv = 1.0 / n as f32;
                for x in c.iter_mut() {
                    *x *= inv;
                }
            }
            let norm = c.iter().map(|x| x * x).sum::<f32>().sqrt();
            if norm > f32::EPSILON {
                for x in c.iter_mut() {
                    *x /= norm;
                }
            }
            c
        })
        .collect();
    // Single-linkage agglomeration over centroids → meta-groups of dream indices.
    let mut meta: Vec<Vec<usize>> = Vec::new();
    for i in 0..dreams.len() {
        let mut placed = false;
        for g in meta.iter_mut() {
            let hits = g
                .iter()
                .any(|&j| crate::providers::embed::cosine(&centroids[i], &centroids[j]) >= threshold);
            if hits {
                g.push(i);
                placed = true;
                break;
            }
        }
        if !placed {
            meta.push(vec![i]);
        }
    }
    meta.into_iter()
        .map(|g| {
            if g.len() == 1 {
                return dreams[g[0]].clone();
            }
            let seed = &dreams[g[0]];
            let merged_labels = g
                .iter()
                .map(|&i| dreams[i].theme_label.as_str())
                .collect::<Vec<_>>()
                .join(" + ");
            let theme_label = sanitize_theme_label(&merged_labels, &seed.theme_label);
            let mut event_ids: Vec<i64> = Vec::new();
            for &i in &g {
                for id in &dreams[i].event_ids {
                    if !event_ids.contains(id) {
                        event_ids.push(*id);
                    }
                }
            }
            let mut tags: Vec<String> = g.iter().flat_map(|&i| dreams[i].tags.clone()).collect();
            tags.sort();
            tags.dedup();
            Dream {
                composed_ts_unix: seed.composed_ts_unix,
                day: seed.day.clone(),
                theme_label,
                summary: format!("Merged {} themes: {}", g.len(), seed.summary),
                event_ids,
                tags,
            }
        })
        .collect()
}

pub async fn compose_dreams_with_embeddings(
    day: &str,
    events: &[EventRef],
    provider: &dyn crate::providers::embed::EmbedProvider,
    chat: Option<&dyn Provider>,
    threshold: f32,
    merge_cross_themes: bool,
) -> anyhow::Result<Vec<Dream>> {
    if events.is_empty() {
        return Ok(Vec::new());
    }
    let embeddings = embed_events(events, provider).await?;
    let groups = cluster_events_by_cosine(events, &embeddings, threshold);
    let mut dreams = Vec::with_capacity(groups.len());
    for (idx, group) in groups.iter().enumerate() {
        let cluster_events: Vec<EventRef> = group.iter().map(|&i| events[i].clone()).collect();
        let seed_id = cluster_events.first().map(|e| e.id).unwrap_or(0);
        let fallback = format!("cluster-{idx}-seed-{seed_id}");
        let theme_label = summarise_or_fallback(chat, &cluster_events, &fallback).await;
        dreams.push(compose_dream(day, &theme_label, &cluster_events));
    }
    // SPEC-12 cross-theme merge — opt-in, after per-cluster Dreams exist.
    if merge_cross_themes && dreams.len() > 1 {
        return Ok(merge_overlapping_dreams(
            &dreams,
            &groups,
            &embeddings,
            DREAMING_CROSS_THEME_THRESHOLD,
        ));
    }
    Ok(dreams)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn ev(id: i64, ts: i64, preview: &str) -> EventRef {
        EventRef {
            id,
            ts_unix: ts,
            preview: preview.into(),
        }
    }

    #[test]
    fn compose_dream_with_no_events_says_no_events() {
        let d = compose_dream("2026-05-22", "morning", &[]);
        assert_eq!(d.day, "2026-05-22");
        assert_eq!(d.theme_label, "morning");
        assert!(d.summary.contains("no events"));
        assert!(d.event_ids.is_empty());
        assert!(d.tags.is_empty());
    }

    #[test]
    fn compose_dream_surfaces_first_two_and_last_anchor() {
        let events = vec![
            ev(1, 100, "first"),
            ev(2, 200, "second"),
            ev(3, 300, "middle"),
            ev(4, 400, "last"),
        ];
        let d = compose_dream("2026-05-22", "work", &events);
        assert_eq!(d.event_ids, vec![1, 2, 3, 4]);
        assert!(d.summary.contains("4 events"));
        assert!(d.summary.contains("ts=100"));
        assert!(d.summary.contains("ts=400"));
        assert!(d.summary.contains("first"));
        assert!(d.summary.contains("second"));
        assert!(d.summary.contains("last"));
    }

    #[test]
    fn append_and_load_roundtrip() {
        let dir = tempdir().unwrap();
        let d = compose_dream("2026-05-22", "test", &[ev(1, 100, "hi")]);
        append_dream(dir.path(), &d).unwrap();
        let loaded = load_dreams_for_day(dir.path(), "2026-05-22");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].theme_label, "test");
        assert_eq!(loaded[0].event_ids, vec![1]);
    }

    #[test]
    fn append_multiple_dreams_to_same_day() {
        let dir = tempdir().unwrap();
        for label in ["morning", "afternoon", "evening"] {
            let d = compose_dream("2026-05-22", label, &[]);
            append_dream(dir.path(), &d).unwrap();
        }
        let loaded = load_dreams_for_day(dir.path(), "2026-05-22");
        assert_eq!(loaded.len(), 3);
    }

    #[test]
    fn load_dreams_missing_file_returns_empty() {
        let dir = tempdir().unwrap();
        assert!(load_dreams_for_day(dir.path(), "2026-05-22").is_empty());
    }

    #[test]
    fn load_dreams_skips_malformed_lines() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dreams_dir(dir.path())).unwrap();
        let file = jsonl_file_for_day(dir.path(), "2026-05-22");
        std::fs::write(
            &file,
            "{not json\n\
             {\"composed_ts_unix\":1,\"day\":\"2026-05-22\",\"theme_label\":\"x\",\
             \"summary\":\"y\",\"event_ids\":[],\"tags\":[]}\n\
             garbage\n",
        )
        .unwrap();
        let loaded = load_dreams_for_day(dir.path(), "2026-05-22");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].theme_label, "x");
    }

    #[test]
    fn compose_dream_truncates_long_previews() {
        let long: String = "a".repeat(500);
        let events = vec![ev(1, 100, &long)];
        let d = compose_dream("2026-05-22", "long", &events);
        // The summary line bound includes the truncation char.
        assert!(d.summary.contains("…"));
        // Stored event_ids stay full fidelity.
        assert_eq!(d.event_ids, vec![1]);
    }

    #[test]
    fn seed_with_dreams_empty_when_no_files() {
        let dir = tempdir().unwrap();
        let hits = seed_with_dreams(dir.path(), "anything", 7, 10);
        assert!(hits.is_empty());
    }

    #[test]
    fn seed_with_dreams_empty_query_returns_all_recent() {
        let dir = tempdir().unwrap();
        // Write a few dreams for today.
        let day = format_date_utc(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        );
        for (i, label) in ["alpha", "beta", "gamma"].iter().enumerate() {
            let mut d = compose_dream(&day, label, &[]);
            d.composed_ts_unix = (i as i64) * 10;
            append_dream(dir.path(), &d).unwrap();
        }
        let hits = seed_with_dreams(dir.path(), "", 7, 10);
        assert_eq!(hits.len(), 3);
        // Newest first.
        assert_eq!(hits[0].theme_label, "gamma");
        assert_eq!(hits[2].theme_label, "alpha");
    }

    #[test]
    fn seed_with_dreams_filters_by_substring_in_theme_or_summary() {
        let dir = tempdir().unwrap();
        let day = format_date_utc(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        );
        let mut a = compose_dream(&day, "auth_bug", &[]);
        a.tags.push("debug".into());
        append_dream(dir.path(), &a).unwrap();
        let b = compose_dream(&day, "vacation_plan", &[]);
        append_dream(dir.path(), &b).unwrap();
        let auth = seed_with_dreams(dir.path(), "auth", 7, 10);
        assert_eq!(auth.len(), 1);
        assert_eq!(auth[0].theme_label, "auth_bug");
        let debug = seed_with_dreams(dir.path(), "debug", 7, 10);
        assert_eq!(debug.len(), 1, "tag substring also matches");
    }

    #[test]
    fn seed_with_dreams_respects_max_hits() {
        let dir = tempdir().unwrap();
        let day = format_date_utc(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        );
        for i in 0..10 {
            let d = compose_dream(&day, &format!("entry_{i}"), &[]);
            append_dream(dir.path(), &d).unwrap();
        }
        let hits = seed_with_dreams(dir.path(), "entry", 7, 3);
        assert_eq!(hits.len(), 3);
    }

    #[test]
    fn dream_serde_roundtrip_preserves_every_field() {
        let d = Dream {
            composed_ts_unix: 1234,
            day: "2026-05-22".into(),
            theme_label: "label".into(),
            summary: "narrative".into(),
            event_ids: vec![1, 2, 3],
            tags: vec!["alpha".into(), "beta".into()],
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: Dream = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    // ── Phase 4 — episodic clustering ────────────────────────────────

    fn cluster_ev(id: i64, preview: &str) -> EventRef {
        EventRef {
            id,
            ts_unix: id, // doesn't matter for cluster math
            preview: preview.to_string(),
        }
    }

    /// Toy embed provider: first-word keyword → unit vector at slot.
    /// "weather" → 0, "news" → 1, "code" → 2, else → 3.
    struct DreamSlotMock;

    #[async_trait::async_trait]
    impl crate::providers::embed::EmbedProvider for DreamSlotMock {
        fn name(&self) -> &'static str {
            "dream_slot_mock"
        }
        fn default_dim(&self) -> usize {
            4
        }
        async fn embed(
            &self,
            req: crate::providers::embed::EmbedRequest,
        ) -> anyhow::Result<crate::providers::embed::EmbedResponse> {
            let slot = match req.text.split_whitespace().next().unwrap_or("") {
                "weather" => 0,
                "news" => 1,
                "code" => 2,
                _ => 3,
            };
            let mut v = vec![0.0f32; 4];
            v[slot] = 1.0;
            Ok(crate::providers::embed::EmbedResponse {
                vector: v,
                model: "dream_slot_mock".into(),
                latency: std::time::Duration::from_micros(1),
            })
        }
    }

    #[test]
    fn cluster_events_empty_input_returns_empty() {
        let groups = cluster_events_by_cosine(&[], &[], 0.5);
        assert!(groups.is_empty());
    }

    #[test]
    fn cluster_events_mismatched_lengths_returns_empty() {
        // Defensive — caller bug shouldn't panic the dreaming task.
        let events = vec![cluster_ev(1, "x")];
        let embeddings: Vec<Vec<f32>> = vec![];
        assert!(cluster_events_by_cosine(&events, &embeddings, 0.5).is_empty());
    }

    #[test]
    fn cluster_events_groups_identical_embeddings() {
        let events = vec![cluster_ev(1, "a"), cluster_ev(2, "b"), cluster_ev(3, "c")];
        // All three at slot 0 → one cluster of size 3.
        let mut e0 = vec![0.0f32; 4];
        e0[0] = 1.0;
        let embeddings = vec![e0.clone(), e0.clone(), e0];
        let groups = cluster_events_by_cosine(&events, &embeddings, 0.5);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0], vec![0, 1, 2]);
    }

    #[test]
    fn cluster_events_splits_orthogonal_embeddings() {
        let events = vec![cluster_ev(1, "a"), cluster_ev(2, "b"), cluster_ev(3, "c")];
        // Three orthogonal unit vectors → three clusters of size 1.
        let embeddings = vec![
            vec![1.0, 0.0, 0.0, 0.0],
            vec![0.0, 1.0, 0.0, 0.0],
            vec![0.0, 0.0, 1.0, 0.0],
        ];
        let groups = cluster_events_by_cosine(&events, &embeddings, 0.5);
        assert_eq!(groups.len(), 3);
        for g in &groups {
            assert_eq!(g.len(), 1);
        }
    }

    // ── SPEC-12 cross-theme merge ────────────────────────────────────────

    fn dream_with(label: &str, ids: Vec<i64>, tags: &[&str]) -> Dream {
        Dream {
            composed_ts_unix: 1700,
            day: "2026-06-05".into(),
            theme_label: label.into(),
            summary: format!("summary-{label}"),
            event_ids: ids,
            tags: tags.iter().map(|t| (*t).to_string()).collect(),
        }
    }

    fn slot_vec(slot: usize) -> Vec<f32> {
        let mut v = vec![0.0f32; 4];
        v[slot] = 1.0;
        v
    }

    #[test]
    fn merge_no_overlap_keeps_clusters_separate() {
        // Orthogonal slot-0/1/2 centroids → no cross-merge.
        let dreams = vec![
            dream_with("weather", vec![1], &["w"]),
            dream_with("news", vec![2], &["n"]),
            dream_with("code", vec![3], &["c"]),
        ];
        let groups = vec![vec![0], vec![1], vec![2]];
        let embeddings = vec![slot_vec(0), slot_vec(1), slot_vec(2)];
        let out = merge_overlapping_dreams(&dreams, &groups, &embeddings, 0.75);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].event_ids, vec![1]);
        assert_eq!(out[2].event_ids, vec![3]);
    }

    #[test]
    fn merge_high_overlap_collapses_into_one() {
        // Both centroids at slot-0 (cosine = 1.0) → merge.
        let dreams = vec![
            dream_with("auth", vec![1, 2], &["a", "shared"]),
            dream_with("login", vec![2, 3], &["b", "shared"]),
        ];
        let groups = vec![vec![0], vec![1]];
        let embeddings = vec![slot_vec(0), slot_vec(0)];
        let out = merge_overlapping_dreams(&dreams, &groups, &embeddings, 0.75);
        assert_eq!(out.len(), 1);
        // event_ids unioned in input order, de-duplicated (the shared `2` once).
        assert_eq!(out[0].event_ids, vec![1, 2, 3]);
        assert!(out[0].theme_label.contains("auth") && out[0].theme_label.contains("login"));
        assert!(out[0].summary.starts_with("Merged 2 themes:"));
        // tags unioned, sorted, de-duplicated.
        assert_eq!(
            out[0].tags,
            vec!["a".to_string(), "b".to_string(), "shared".to_string()]
        );
    }

    #[test]
    fn merge_threshold_boundary_flips_behaviour() {
        // centroid_B has cosine 0.78 with centroid_A = [1,0,0,0].
        let cos = 0.78f32;
        let b = vec![cos, (1.0 - cos * cos).sqrt(), 0.0, 0.0];
        let dreams = vec![dream_with("a", vec![1], &[]), dream_with("b", vec![2], &[])];
        let groups = vec![vec![0], vec![1]];
        let embeddings = vec![slot_vec(0), b];
        // threshold below the pair's cosine → merge.
        assert_eq!(merge_overlapping_dreams(&dreams, &groups, &embeddings, 0.75).len(), 1);
        // threshold above the pair's cosine → stay separate.
        assert_eq!(merge_overlapping_dreams(&dreams, &groups, &embeddings, 0.80).len(), 2);
    }

    #[test]
    fn merge_defensive_passthrough() {
        // single dream → unchanged.
        let one = vec![dream_with("solo", vec![1], &[])];
        assert_eq!(merge_overlapping_dreams(&one, &[vec![0]], &[slot_vec(0)], 0.75).len(), 1);
        // cluster_groups length mismatch → input clone (no merge attempted).
        let two = vec![dream_with("a", vec![1], &[]), dream_with("b", vec![2], &[])];
        assert_eq!(merge_overlapping_dreams(&two, &[vec![0]], &[slot_vec(0)], 0.75).len(), 2);
        // empty → empty.
        assert!(merge_overlapping_dreams(&[], &[], &[], 0.75).is_empty());
    }

    #[tokio::test]
    async fn compose_with_merge_flag_does_not_over_merge_orthogonal_clusters() {
        // weather + news form 2 orthogonal clusters; merge_cross_themes=true must
        // NOT collapse them (centroid cosine 0.0 < 0.75) — proves the flag is
        // wired end-to-end AND that the merge is conservative.
        let events = vec![
            cluster_ev(1, "weather sunny"),
            cluster_ev(2, "weather rainy"),
            cluster_ev(3, "news election"),
            cluster_ev(4, "news economy"),
        ];
        let dreams =
            compose_dreams_with_embeddings("2026-06-05", &events, &DreamSlotMock, None, 0.5, true)
                .await
                .unwrap();
        assert_eq!(dreams.len(), 2, "orthogonal weather/news clusters must not cross-merge");
    }

    #[test]
    fn cluster_events_single_linkage_chains_through_existing() {
        // A at slot 0, B at slot 0 (joins A), C orthogonal to A and B
        // (new cluster). Single-linkage: B joins because it crosses
        // threshold to A; C does NOT join even though it shares the
        // group lookup with B because cos(C, A) = cos(C, B) = 0.
        let events = vec![cluster_ev(1, "a"), cluster_ev(2, "b"), cluster_ev(3, "c")];
        let embeddings = vec![
            vec![1.0, 0.0, 0.0, 0.0],
            vec![1.0, 0.0, 0.0, 0.0],
            vec![0.0, 1.0, 0.0, 0.0],
        ];
        let groups = cluster_events_by_cosine(&events, &embeddings, 0.5);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0], vec![0, 1]);
        assert_eq!(groups[1], vec![2]);
    }

    #[test]
    fn cluster_threshold_constant_pinned() {
        assert_eq!(DREAMING_CLUSTER_THRESHOLD, 0.55);
    }

    #[tokio::test]
    async fn embed_events_roundtrips_via_provider() {
        let events = vec![
            cluster_ev(1, "weather today"),
            cluster_ev(2, "news headlines"),
        ];
        let vectors = embed_events(&events, &DreamSlotMock).await.unwrap();
        assert_eq!(vectors.len(), 2);
        assert_eq!(vectors[0][0], 1.0); // weather slot
        assert_eq!(vectors[1][1], 1.0); // news slot
    }

    #[tokio::test]
    async fn embed_events_propagates_provider_errors() {
        struct FailingEmbed;
        #[async_trait::async_trait]
        impl crate::providers::embed::EmbedProvider for FailingEmbed {
            fn name(&self) -> &'static str {
                "failing"
            }
            fn default_dim(&self) -> usize {
                4
            }
            async fn embed(
                &self,
                _req: crate::providers::embed::EmbedRequest,
            ) -> anyhow::Result<crate::providers::embed::EmbedResponse> {
                anyhow::bail!("provider unavailable")
            }
        }
        let events = vec![cluster_ev(1, "x")];
        assert!(embed_events(&events, &FailingEmbed).await.is_err());
    }

    #[tokio::test]
    async fn compose_dreams_with_embeddings_one_per_cluster() {
        let day = "2026-05-23";
        // 2 weather events + 1 news event → 2 clusters → 2 dreams.
        let events = vec![
            cluster_ev(1, "weather forecast for monday"),
            cluster_ev(2, "weather pattern shifting"),
            cluster_ev(3, "news from berlin"),
        ];
        let dreams = compose_dreams_with_embeddings(day, &events, &DreamSlotMock, None, 0.5, false)
            .await
            .unwrap();
        assert_eq!(dreams.len(), 2);
        // First cluster carries 2 events (the two weather ones).
        let weather_dream = dreams.iter().find(|d| d.event_ids.contains(&1)).unwrap();
        assert!(weather_dream.event_ids.contains(&2));
        assert!(!weather_dream.event_ids.contains(&3));
        // Second cluster carries the lone news event.
        let news_dream = dreams.iter().find(|d| d.event_ids.contains(&3)).unwrap();
        assert_eq!(news_dream.event_ids, vec![3]);
        // Theme labels are stable + reference the cluster seed.
        assert!(weather_dream.theme_label.contains("seed-1"));
        assert!(news_dream.theme_label.contains("seed-3"));
    }

    #[tokio::test]
    async fn compose_dreams_empty_input_returns_empty() {
        let dreams = compose_dreams_with_embeddings("2026-05-23", &[], &DreamSlotMock, None, 0.5, false)
            .await
            .unwrap();
        assert!(dreams.is_empty());
    }

    // ── SPEC-12 Phase 4b — LLM theme summarisation ───────────────────────────

    /// Chat provider that returns a fixed reply — exercises the summarised
    /// theme-label path.
    struct FixedLabelChat {
        reply: &'static str,
    }
    #[async_trait::async_trait]
    impl Provider for FixedLabelChat {
        fn name(&self) -> &'static str {
            "fixed_label_chat"
        }
        async fn complete(&self, _req: Request) -> anyhow::Result<crate::providers::Completion> {
            Ok(crate::providers::Completion {
                text: self.reply.into(),
                model: "fixed_label_chat".into(),
                latency: std::time::Duration::from_micros(1),
                input_tokens: None,
                output_tokens: None,
            })
        }
    }

    /// Chat provider that always errors — exercises the deterministic fallback.
    struct FailingChat;
    #[async_trait::async_trait]
    impl Provider for FailingChat {
        fn name(&self) -> &'static str {
            "failing_chat"
        }
        async fn complete(&self, _req: Request) -> anyhow::Result<crate::providers::Completion> {
            anyhow::bail!("chat provider down")
        }
    }

    #[test]
    fn build_theme_summary_prompt_lists_previews_and_instruction() {
        let previews = vec!["weather forecast".to_string(), "rain on monday".to_string()];
        let prompt = build_theme_summary_prompt(&previews);
        assert!(prompt.contains("- weather forecast"));
        assert!(prompt.contains("- rain on monday"));
        assert!(prompt.contains("Theme label:"));
        assert!(prompt.contains("3 to 6 words"));
    }

    #[test]
    fn build_theme_summary_prompt_caps_preview_count() {
        let previews: Vec<String> = (0..30).map(|i| format!("snippet number {i}")).collect();
        let prompt = build_theme_summary_prompt(&previews);
        // Only the first THEME_SUMMARY_MAX_PREVIEWS bullets appear.
        let bullets = prompt.matches("- snippet number").count();
        assert_eq!(
            bullets, THEME_SUMMARY_MAX_PREVIEWS,
            "prompt must cap previews at {THEME_SUMMARY_MAX_PREVIEWS}",
        );
        assert!(prompt.contains("snippet number 0"));
        assert!(!prompt.contains("snippet number 29"));
    }

    #[test]
    fn build_theme_summary_prompt_redacts_secrets_before_the_cloud_call() {
        // SPEC-12 privacy gate: a preview carrying a secret must NOT reach the
        // (possibly cloud) summary prompt verbatim.
        let previews = vec![
            "deployed with key AKIAIOSFODNN7EXAMPLE to prod".to_string(),
            "talked about the weekend trip".to_string(),
        ];
        let prompt = build_theme_summary_prompt(&previews);
        assert!(
            !prompt.contains("AKIAIOSFODNN7EXAMPLE"),
            "raw secret leaked into the summary prompt: {prompt}"
        );
        assert!(prompt.contains("[REDACTED:"), "expected a redaction marker");
        // Non-secret content still flows through.
        assert!(prompt.contains("weekend trip"));
    }

    #[test]
    fn sanitize_theme_label_collapses_and_strips() {
        assert_eq!(
            sanitize_theme_label("  auth   refactor\n", "fb"),
            "auth refactor"
        );
        assert_eq!(sanitize_theme_label("\"deploy pipeline\"", "fb"), "deploy pipeline");
        assert_eq!(sanitize_theme_label("`code review`", "fb"), "code review");
    }

    #[test]
    fn sanitize_theme_label_empty_falls_back() {
        assert_eq!(sanitize_theme_label("", "cluster-0-seed-1"), "cluster-0-seed-1");
        assert_eq!(sanitize_theme_label("   \n\t  ", "fb"), "fb");
        assert_eq!(sanitize_theme_label("\"\"", "fb"), "fb");
    }

    #[test]
    fn sanitize_theme_label_clamps_long_output() {
        let long = "a".repeat(200);
        let out = sanitize_theme_label(&long, "fb");
        assert!(out.chars().count() <= THEME_LABEL_MAX_CHARS + 1, "got {} chars", out.chars().count());
        assert!(out.ends_with('…'));
    }

    #[tokio::test]
    async fn compose_dreams_uses_llm_label_when_chat_present() {
        let day = "2026-06-03";
        let events = vec![
            cluster_ev(1, "weather forecast for monday"),
            cluster_ev(2, "weather pattern shifting"),
        ];
        let chat = FixedLabelChat {
            reply: "  monday weather outlook  ",
        };
        let dreams = compose_dreams_with_embeddings(day, &events, &DreamSlotMock, Some(&chat), 0.5, false)
            .await
            .unwrap();
        assert_eq!(dreams.len(), 1);
        // The LLM label replaced the deterministic cluster-N-seed-id.
        assert_eq!(dreams[0].theme_label, "monday weather outlook");
        assert!(!dreams[0].theme_label.contains("cluster-"));
    }

    #[tokio::test]
    async fn compose_dreams_falls_back_to_deterministic_on_chat_error() {
        let day = "2026-06-03";
        let events = vec![cluster_ev(1, "weather forecast for monday")];
        let dreams =
            compose_dreams_with_embeddings(day, &events, &DreamSlotMock, Some(&FailingChat), 0.5, false)
                .await
                .unwrap();
        assert_eq!(dreams.len(), 1);
        // Chat error must degrade the label, never fail the pass.
        assert!(
            dreams[0].theme_label.starts_with("cluster-"),
            "expected deterministic fallback, got {}",
            dreams[0].theme_label,
        );
    }

    // ── OB-01a (Session 24) to_obsidian_md serializer ─────────────────

    fn fixture_dream() -> Dream {
        Dream {
            composed_ts_unix: 1_700_000_000,
            day: "2026-05-25".into(),
            theme_label: "memory-tier consolidation".into(),
            summary: "Theme `memory-tier consolidation`: 4 events between ts=1700 and ts=1900."
                .into(),
            event_ids: vec![1, 2, 3, 4],
            tags: vec!["memory".into(), "consolidation".into()],
        }
    }

    #[test]
    fn ob_01a_renders_yaml_frontmatter_with_required_fields() {
        let md = fixture_dream().to_obsidian_md();
        // Frontmatter delimiters on the first + a later line.
        assert!(
            md.starts_with("---\n"),
            "frontmatter must start at line 1: {md}"
        );
        assert!(
            md.contains("\n---\n\n"),
            "frontmatter must close before body: {md}"
        );
        // All 5 required fields present, in documented order.
        let frontmatter_end = md.find("\n---\n").expect("closing ---");
        let frontmatter = &md[..frontmatter_end];
        let day_pos = frontmatter.find("day:").expect("day field");
        let theme_pos = frontmatter.find("theme:").expect("theme field");
        let composed_pos = frontmatter
            .find("composed_unix:")
            .expect("composed_unix field");
        let count_pos = frontmatter.find("event_count:").expect("event_count field");
        let tags_pos = frontmatter.find("tags:").expect("tags field");
        assert!(day_pos < theme_pos, "day must precede theme");
        assert!(theme_pos < composed_pos, "theme must precede composed_unix");
        assert!(
            composed_pos < count_pos,
            "composed_unix must precede event_count"
        );
        assert!(count_pos < tags_pos, "event_count must precede tags");
    }

    #[test]
    fn ob_01a_renders_h1_heading_with_day_and_theme() {
        let md = fixture_dream().to_obsidian_md();
        assert!(
            md.contains("# Dream 2026-05-25 — memory-tier consolidation"),
            "H1 must include day + em-dash + theme: {md}",
        );
    }

    #[test]
    fn ob_01a_summary_block_carries_the_dream_narrative() {
        let md = fixture_dream().to_obsidian_md();
        assert!(md.contains("## Summary"));
        assert!(md.contains("memory-tier consolidation"));
        assert!(md.contains("4 events"));
    }

    #[test]
    fn ob_01a_source_events_lists_every_event_id() {
        let md = fixture_dream().to_obsidian_md();
        assert!(md.contains("## Source events"));
        for id in 1..=4 {
            assert!(
                md.contains(&format!("event_id: `{id}`")),
                "event_id {id} missing from: {md}",
            );
        }
    }

    #[test]
    fn ob_01a_empty_event_list_renders_explicit_placeholder() {
        // Dataview prefers a non-empty section. Empty bullet list
        // would render as a stray heading; the placeholder line
        // gives the operator + the parser something to anchor on.
        let mut d = fixture_dream();
        d.event_ids.clear();
        let md = d.to_obsidian_md();
        assert!(md.contains("(no source events)"));
        assert!(md.contains("event_count: 0"));
    }

    #[test]
    fn ob_01a_empty_tags_render_as_empty_inline_yaml_list() {
        // Pinned: empty tags MUST render as `tags: []` (Dataview-
        // queryable), NOT omitted. A missing field would break
        // operators' Dataview `WHERE contains(tags, ...)` queries.
        let mut d = fixture_dream();
        d.tags.clear();
        let md = d.to_obsidian_md();
        assert!(md.contains("tags: []"), "got: {md}");
    }

    #[test]
    fn ob_01a_tags_render_as_quoted_inline_yaml_list() {
        let md = fixture_dream().to_obsidian_md();
        // Drift guard: tags must be quoted to survive Obsidian's
        // YAML parser when an operator hand-tags with `#` literal
        // (which YAML treats as a comment).
        assert!(md.contains("tags: [\"memory\", \"consolidation\"]"));
    }

    #[test]
    fn ob_01a_escapes_double_quote_in_theme_label() {
        // Operator-supplied theme labels can contain `"` — must
        // be escaped or the YAML frontmatter parser dies.
        let mut d = fixture_dream();
        d.theme_label = "she said \"hi\"".into();
        let md = d.to_obsidian_md();
        assert!(md.contains("theme: \"she said \\\"hi\\\"\""), "got: {md}",);
    }

    #[test]
    fn ob_01a_escapes_backslash_in_theme_label() {
        let mut d = fixture_dream();
        d.theme_label = r"path\to\thing".into();
        let md = d.to_obsidian_md();
        assert!(md.contains(r#"theme: "path\\to\\thing""#), "got: {md}",);
    }

    #[test]
    fn ob_01a_output_ends_with_newline() {
        // Hard convention for Obsidian files — POSIX-style trailing
        // newline so concatenation into a daily digest doesn't merge
        // adjacent dreams onto the same line.
        let md = fixture_dream().to_obsidian_md();
        assert!(md.ends_with('\n'), "md must end with newline");
    }

    #[test]
    fn ob_01a_event_count_field_matches_event_ids_len() {
        // Drift guard: `event_count` in YAML frontmatter MUST equal
        // the bulleted source-events list length. A future refactor
        // that derives count from a different source would silently
        // diverge.
        let d = fixture_dream();
        let md = d.to_obsidian_md();
        assert!(md.contains(&format!("event_count: {}", d.event_ids.len())));
    }

    // ── OB-01 sync_dreams_to_obsidian ─────────────────────────────────────

    fn make_dream(day: &str, theme: &str, summary: &str, ev_ids: &[i64]) -> Dream {
        Dream {
            composed_ts_unix: 1_700_000_000,
            day: day.to_string(),
            theme_label: theme.to_string(),
            summary: summary.to_string(),
            event_ids: ev_ids.to_vec(),
            tags: vec![],
        }
    }

    #[test]
    fn ob01_sync_no_dreams_skips_write() {
        let home = tempdir().unwrap();
        let vault = tempdir().unwrap();
        let outcome = sync_dreams_to_obsidian(home.path(), vault.path(), "NEOTH", "2026-05-26")
            .expect("sync ok");
        assert!(!outcome.written, "empty day must not produce a vault file");
        assert_eq!(outcome.dream_count, 0);
        assert!(!outcome.target_path.exists());
    }

    #[test]
    fn ob01_sync_single_dream_writes_file() {
        let home = tempdir().unwrap();
        let vault = tempdir().unwrap();
        let d = make_dream("2026-05-26", "morning", "morning routine", &[1, 2]);
        append_dream(home.path(), &d).unwrap();

        let outcome = sync_dreams_to_obsidian(home.path(), vault.path(), "NEOTH", "2026-05-26")
            .expect("sync ok");
        assert!(outcome.written);
        assert_eq!(outcome.dream_count, 1);
        assert!(outcome.bytes_written > 0);
        assert!(outcome.target_path.exists());

        let body = std::fs::read_to_string(&outcome.target_path).unwrap();
        assert!(body.starts_with("---\n")); // YAML frontmatter delimiter
        assert!(body.contains("theme: \"morning\""));
        assert!(body.contains("event_id: `1`"));
    }

    #[test]
    fn ob01_sync_multiple_dreams_joined_with_hr() {
        let home = tempdir().unwrap();
        let vault = tempdir().unwrap();
        append_dream(
            home.path(),
            &make_dream("2026-05-26", "morning", "morning theme", &[1]),
        )
        .unwrap();
        append_dream(
            home.path(),
            &make_dream("2026-05-26", "afternoon", "afternoon theme", &[2]),
        )
        .unwrap();

        let outcome = sync_dreams_to_obsidian(home.path(), vault.path(), "NEOTH", "2026-05-26")
            .expect("sync ok");
        assert_eq!(outcome.dream_count, 2);

        let body = std::fs::read_to_string(&outcome.target_path).unwrap();
        // Both themes appear.
        assert!(
            body.contains("theme: \"morning\""),
            "missing morning: {body}"
        );
        assert!(
            body.contains("theme: \"afternoon\""),
            "missing afternoon: {body}",
        );
        // The thematic-break separator joins them.
        assert!(
            body.contains("\n---\n\n"),
            "missing dream-separator HR: {body}",
        );
    }

    #[test]
    fn ob01_sync_writes_atomic_no_dotfile_lingers() {
        let home = tempdir().unwrap();
        let vault = tempdir().unwrap();
        append_dream(home.path(), &make_dream("2026-05-26", "x", "y", &[1])).unwrap();

        let outcome = sync_dreams_to_obsidian(home.path(), vault.path(), "NEOTH", "2026-05-26")
            .expect("sync ok");
        let dreams_dir = outcome.target_path.parent().unwrap();
        let leftover_tmp = dreams_dir.join("2026-05-26.md.tmp");
        assert!(!leftover_tmp.exists(), "tmp file must be renamed away");
    }

    #[test]
    fn ob01_sync_overwrites_stale_existing_file() {
        let home = tempdir().unwrap();
        let vault = tempdir().unwrap();
        let dreams_dir = vault.path().join("NEOTH").join("Dreams");
        std::fs::create_dir_all(&dreams_dir).unwrap();
        let target = dreams_dir.join("2026-05-26.md");
        std::fs::write(&target, "STALE CONTENT").unwrap();

        append_dream(
            home.path(),
            &make_dream("2026-05-26", "fresh", "today", &[42]),
        )
        .unwrap();
        let outcome = sync_dreams_to_obsidian(home.path(), vault.path(), "NEOTH", "2026-05-26")
            .expect("sync ok");
        assert!(outcome.written);

        let body = std::fs::read_to_string(&outcome.target_path).unwrap();
        assert!(!body.contains("STALE CONTENT"), "stale content survived");
        assert!(body.contains("theme: \"fresh\""));
    }

    #[test]
    fn ob01_sync_target_path_lives_under_vault_subdir_dreams() {
        let home = tempdir().unwrap();
        let vault = tempdir().unwrap();
        append_dream(home.path(), &make_dream("2026-05-26", "x", "y", &[1])).unwrap();

        let outcome =
            sync_dreams_to_obsidian(home.path(), vault.path(), "CUSTOM-SUBDIR", "2026-05-26")
                .unwrap();
        let expected = vault
            .path()
            .join("CUSTOM-SUBDIR")
            .join("Dreams")
            .join("2026-05-26.md");
        assert_eq!(outcome.target_path, expected);
    }

    #[test]
    fn ob01_sync_byte_count_matches_file_size() {
        let home = tempdir().unwrap();
        let vault = tempdir().unwrap();
        append_dream(home.path(), &make_dream("2026-05-26", "x", "y", &[1])).unwrap();

        let outcome =
            sync_dreams_to_obsidian(home.path(), vault.path(), "NEOTH", "2026-05-26").unwrap();
        let actual = std::fs::metadata(&outcome.target_path).unwrap().len() as usize;
        assert_eq!(actual, outcome.bytes_written);
    }
}
