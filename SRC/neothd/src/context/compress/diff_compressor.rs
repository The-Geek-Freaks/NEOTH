//! GOLD-HR-05 — `DiffCompressor`: trim context, cap files, drop diff noise.
//!
//! A `git diff` is dominated by bytes the LLM rarely needs:
//!
//! - **Lockfile churn** — `npm install` reshuffles thousands of
//!   `package-lock.json` lines while changing one `package.json` line. The
//!   manifest carries the signal; the lockfile is noise.
//! - **Whitespace-only hunks** — reformat / lint commits churn bytes without
//!   changing semantics.
//! - **Context lines** — a 200-line hunk that changes 3 lines is mostly
//!   unchanged context the model doesn't need verbatim.
//! - **File floods** — a 60-file refactor diff blows the budget; the model
//!   usually needs the first handful in detail and a list of the rest.
//!
//! This single offload folds headroom's `DiffNoise` (lockfile + whitespace
//! drop) together with context-trimming and a file cap. Dropped/trimmed bytes
//! leave the wire but the byte-exact original is stashed via CCR
//! ([`super::ccr`]) — lossy on the wire, lossless on retrieval; 40–90 % on
//! real diffs. NEOTH uses its SHA-256 CCR key (no `md5` dep, unlike upstream)
//! and a lean line-walker (no 1600-line unified-diff parser).

use std::fmt::Write;

use crate::context::compress::ccr::{compute_key, marker_for, CcrStore};
use crate::context::compress::content_detector::ContentType;
use crate::context::compress::transform::{
    CompressionContext, OffloadOutput, OffloadTransform, TransformError,
};

const NAME: &str = "diff_compressor";
const CONFIDENCE: f32 = 0.85;

/// Tunables for [`DiffCompressor`]. Code-level defaults; not freedom.yaml.
#[derive(Debug, Clone)]
pub struct DiffCompressorConfig {
    /// Diffs shorter than this are passed through.
    pub min_lines: usize,
    /// Path suffixes treated as lockfiles (whole hunk body dropped).
    pub lockfile_suffixes: Vec<String>,
    /// Drop whole hunks that are whitespace-only changes.
    pub drop_whitespace_only_hunks: bool,
    /// Context lines kept on each side of a change inside a non-dropped hunk.
    pub context_lines: usize,
    /// After this many changed files, the rest are summarised as a count.
    pub max_files: usize,
}

impl Default for DiffCompressorConfig {
    fn default() -> Self {
        Self {
            min_lines: 50,
            lockfile_suffixes: vec![
                "Cargo.lock".into(),
                "package-lock.json".into(),
                "yarn.lock".into(),
                "pnpm-lock.yaml".into(),
                "poetry.lock".into(),
                "go.sum".into(),
                "Gemfile.lock".into(),
                "composer.lock".into(),
            ],
            drop_whitespace_only_hunks: true,
            context_lines: 3,
            max_files: 20,
        }
    }
}

pub struct DiffCompressor {
    config: DiffCompressorConfig,
}

impl DiffCompressor {
    pub fn new(config: DiffCompressorConfig) -> Self {
        Self { config }
    }
}

impl Default for DiffCompressor {
    fn default() -> Self {
        Self::new(DiffCompressorConfig::default())
    }
}

impl OffloadTransform for DiffCompressor {
    fn name(&self) -> &'static str {
        NAME
    }

    fn applies_to(&self) -> &[ContentType] {
        &[ContentType::GitDiff]
    }

    fn estimate_bloat(&self, content: &str) -> f32 {
        if content.is_empty() || content.lines().count() < self.config.min_lines {
            return 0.0;
        }
        let segments = parse_segments(content);
        if segments.is_empty() {
            return 0.0;
        }
        let mut droppable = 0usize;
        let mut total = 0usize;
        for (idx, seg) in segments.iter().enumerate() {
            let body_bytes: usize = seg.body_lines.iter().map(|l| l.len() + 1).sum();
            total += body_bytes;
            let drop_whole = self.is_lockfile(&seg.new_path)
                || (self.config.drop_whitespace_only_hunks && seg.body_is_whitespace_only());
            if drop_whole || idx >= self.config.max_files {
                droppable += body_bytes;
            } else {
                // Trimmable context = body lines neither changed nor within the
                // context window of a change.
                droppable += seg.trimmable_context_bytes(self.config.context_lines);
            }
        }
        if total == 0 {
            return 0.0;
        }
        (droppable as f32 / total as f32).clamp(0.0, 1.0)
    }

    fn apply(
        &self,
        content: &str,
        _ctx: &CompressionContext,
        store: &dyn CcrStore,
    ) -> Result<OffloadOutput, TransformError> {
        let segments = parse_segments(content);
        if segments.is_empty() {
            return Err(TransformError::skipped(NAME, "no diff sections"));
        }

        // Key first; only write to the store once savings are confirmed.
        let key = compute_key(content.as_bytes());
        let marker = marker_for(&key);

        let mut out = String::with_capacity(content.len());
        out.push_str(&leading_pre_diff_lines(content));

        let seg_count = segments.len();
        let mut changed = false;
        for (idx, seg) in segments.iter().enumerate() {
            if idx >= self.config.max_files {
                let remaining = seg_count - idx;
                let _ = writeln!(
                    out,
                    "[… {remaining} more changed files trimmed — retrieve {marker} …]"
                );
                changed = true;
                break;
            }
            for h in &seg.header_lines {
                out.push_str(h);
                out.push('\n');
            }
            let drop_lockfile = self.is_lockfile(&seg.new_path);
            let drop_ws = self.config.drop_whitespace_only_hunks && seg.body_is_whitespace_only();
            if drop_lockfile || drop_ws {
                let reason = if drop_lockfile { "lockfile" } else { "whitespace-only" };
                let _ = writeln!(
                    out,
                    "[diff_compressor: {reason} hunk dropped ({} lines) — retrieve {marker}]",
                    seg.body_lines.len()
                );
                changed = true;
            } else {
                let trimmed = trim_context(&seg.body_lines, self.config.context_lines, &marker);
                changed |= trimmed.trimmed_any;
                out.push_str(&trimmed.body);
            }
        }

        if !content.ends_with('\n') && out.ends_with('\n') {
            out.pop();
        }
        if !changed || out.len() >= content.len() {
            return Err(TransformError::skipped(NAME, "nothing droppable"));
        }
        store.put(&key, content);
        Ok(OffloadOutput::from_lengths(content.len(), out, key))
    }

    fn confidence(&self) -> f32 {
        CONFIDENCE
    }
}

impl DiffCompressor {
    fn is_lockfile(&self, path: &str) -> bool {
        if path.is_empty() {
            return false;
        }
        for suffix in &self.config.lockfile_suffixes {
            if path.ends_with(suffix.as_str()) {
                let prefix_len = path.len() - suffix.len();
                if prefix_len == 0 {
                    return true;
                }
                let prev = path.as_bytes()[prefix_len - 1];
                if prev == b'/' || prev == b'\\' {
                    return true;
                }
            }
        }
        false
    }
}

// ─── Diff parsing (lean line-walker, no regex) ─────────────────────────

/// One file's segment: pre-body header lines (`diff --git`, `index`,
/// `+++/---`) + the body (from the first `@@` to the next `diff --git`).
struct Segment<'a> {
    new_path: String,
    header_lines: Vec<&'a str>,
    body_lines: Vec<&'a str>,
}

impl Segment<'_> {
    /// True if every `+`/`-` line, whitespace-stripped and paired in order,
    /// leaves equal token sequences (a reformat that changed no semantics).
    fn body_is_whitespace_only(&self) -> bool {
        let mut adds: Vec<String> = Vec::new();
        let mut subs: Vec<String> = Vec::new();
        let mut saw_change = false;
        for line in &self.body_lines {
            match line.as_bytes().first() {
                Some(b'+') if !line.starts_with("+++") => {
                    saw_change = true;
                    adds.push(strip_ws(&line[1..]));
                }
                Some(b'-') if !line.starts_with("---") => {
                    saw_change = true;
                    subs.push(strip_ws(&line[1..]));
                }
                _ => {}
            }
        }
        saw_change && adds == subs
    }

    /// Bytes of context lines that would be trimmed (neither a change nor
    /// within `context` lines of one, and not a hunk header).
    fn trimmable_context_bytes(&self, context: usize) -> usize {
        let keep = keep_mask(&self.body_lines, context);
        self.body_lines
            .iter()
            .zip(keep.iter())
            .filter(|&(_, &k)| !k)
            .map(|(l, _)| l.len() + 1)
            .sum()
    }
}

fn strip_ws(s: &str) -> String {
    s.chars().filter(|c| !c.is_ascii_whitespace()).collect()
}

fn is_change_line(line: &str) -> bool {
    match line.as_bytes().first() {
        Some(b'+') => !line.starts_with("+++"),
        Some(b'-') => !line.starts_with("---"),
        _ => false,
    }
}

/// Mark which body lines survive context-trimming: hunk headers (`@@`),
/// change lines, and the `context` lines on each side of every change.
fn keep_mask(body: &[&str], context: usize) -> Vec<bool> {
    let n = body.len();
    let mut keep = vec![false; n];
    for (i, line) in body.iter().enumerate() {
        if line.starts_with("@@") || is_change_line(line) {
            keep[i] = true;
        }
    }
    // Expand the window around each change line.
    let changes: Vec<usize> = (0..n).filter(|&i| is_change_line(body[i])).collect();
    for c in changes {
        let lo = c.saturating_sub(context);
        let hi = (c + context).min(n - 1);
        for k in keep.iter_mut().take(hi + 1).skip(lo) {
            *k = true;
        }
    }
    keep
}

struct TrimmedBody {
    body: String,
    trimmed_any: bool,
}

/// Rebuild a hunk body keeping changes + context window, collapsing dropped
/// context runs into a single retrieval placeholder.
fn trim_context(body: &[&str], context: usize, marker: &str) -> TrimmedBody {
    let keep = keep_mask(body, context);
    let n = body.len();
    let mut out = String::with_capacity(body.iter().map(|l| l.len() + 1).sum());
    let mut trimmed_any = false;
    let mut i = 0;
    while i < n {
        if keep[i] {
            out.push_str(body[i]);
            out.push('\n');
            i += 1;
        } else {
            let start = i;
            while i < n && !keep[i] {
                i += 1;
            }
            let dropped = i - start;
            let _ = writeln!(out, "[… {dropped} context lines trimmed — retrieve {marker} …]");
            trimmed_any = true;
        }
    }
    TrimmedBody { body: out, trimmed_any }
}

/// One [`Segment`] per `diff --git` header. Lines before the first header are
/// excluded (the caller picks them up via [`leading_pre_diff_lines`]).
fn parse_segments(content: &str) -> Vec<Segment<'_>> {
    let mut segments: Vec<Segment<'_>> = Vec::new();
    let mut current: Option<Segment<'_>> = None;
    let mut in_body = false;

    for line in content.lines() {
        if line.starts_with("diff --git") {
            if let Some(s) = current.take() {
                segments.push(s);
            }
            current = Some(Segment {
                new_path: parse_new_path(line),
                header_lines: vec![line],
                body_lines: Vec::new(),
            });
            in_body = false;
            continue;
        }
        let Some(seg) = current.as_mut() else {
            continue;
        };
        if !in_body {
            if line.starts_with("@@") {
                in_body = true;
                seg.body_lines.push(line);
                continue;
            }
            seg.header_lines.push(line);
        } else {
            seg.body_lines.push(line);
        }
    }
    if let Some(s) = current.take() {
        segments.push(s);
    }
    segments
}

/// Lines from the start up to (not including) the first `diff --git`.
fn leading_pre_diff_lines(content: &str) -> String {
    let mut out = String::new();
    for line in content.lines() {
        if line.starts_with("diff --git") {
            break;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// New-file path from `diff --git a/X b/Y` → `Y` (after the last ` b/`).
fn parse_new_path(header: &str) -> String {
    header.rfind(" b/").map(|idx| header[idx + 3..].to_string()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::compress::ccr::{extract_keys, InMemoryCcrStore};

    fn offload() -> DiffCompressor {
        DiffCompressor::default()
    }

    fn build_diff(files: &[(&str, &[&str])]) -> String {
        let mut s = String::new();
        for (path, body) in files {
            s.push_str(&format!("diff --git a/{path} b/{path}\n"));
            s.push_str(&format!("--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n"));
            for b in *body {
                s.push_str(b);
                s.push('\n');
            }
        }
        s
    }

    #[test]
    fn name_and_applies_to() {
        assert_eq!(offload().name(), "diff_compressor");
        assert_eq!(offload().applies_to(), &[ContentType::GitDiff]);
    }

    #[test]
    fn below_min_lines_and_empty_score_zero() {
        assert_eq!(offload().estimate_bloat(""), 0.0);
        let diff = build_diff(&[("Cargo.lock", &["-old", "+new"])]);
        assert_eq!(offload().estimate_bloat(&diff), 0.0);
    }

    #[test]
    fn lockfile_dominated_scores_high_and_drops() {
        let lock: Vec<String> = (0..200)
            .flat_map(|i| vec![format!("-old{i}"), format!("+new{i}")])
            .collect();
        let lock_refs: Vec<&str> = lock.iter().map(|s| s.as_str()).collect();
        let diff = build_diff(&[
            ("Cargo.lock", &lock_refs),
            ("Cargo.toml", &["-foo = \"1\"", "+foo = \"2\""]),
        ]);
        assert!(offload().estimate_bloat(&diff) > 0.9);

        let store = InMemoryCcrStore::new();
        let r = offload()
            .apply(&diff, &CompressionContext::default(), &store)
            .expect("compresses");
        assert!(r.bytes_saved > 0);
        assert!(r.output.contains("lockfile hunk dropped"));
        assert!(r.output.contains("foo = \"2\""), "real manifest change survives");
        assert_eq!(store.get(&r.cache_key).as_deref(), Some(diff.as_str()));
        assert_eq!(extract_keys(&r.output)[0], r.cache_key);
    }

    #[test]
    fn whitespace_only_hunk_dropped() {
        let body: Vec<String> = (0..40)
            .flat_map(|i| vec![format!("-line {i}   "), format!("+line {i}")])
            .collect();
        let refs: Vec<&str> = body.iter().map(|s| s.as_str()).collect();
        let diff = build_diff(&[("src/main.rs", &refs)]);
        assert!(offload().estimate_bloat(&diff) > 0.5);
        let store = InMemoryCcrStore::new();
        let r = offload()
            .apply(&diff, &CompressionContext::default(), &store)
            .expect("compresses");
        assert!(r.output.contains("whitespace-only hunk dropped"));
    }

    #[test]
    fn context_heavy_hunk_is_trimmed_changes_survive() {
        // 100 context lines, 1 change in the middle.
        let mut body: Vec<String> = Vec::new();
        for i in 0..50 {
            body.push(format!(" context {i}"));
        }
        body.push("-old value".into());
        body.push("+new value".into());
        for i in 0..50 {
            body.push(format!(" context {}", 50 + i));
        }
        let refs: Vec<&str> = body.iter().map(|s| s.as_str()).collect();
        let diff = build_diff(&[("src/big.rs", &refs)]);
        let store = InMemoryCcrStore::new();
        let r = offload()
            .apply(&diff, &CompressionContext::default(), &store)
            .expect("trims context");
        assert!(r.bytes_saved > 0);
        assert!(r.output.contains("-old value") && r.output.contains("+new value"));
        assert!(r.output.contains("context lines trimmed"));
        // Context within the window survives; far context is gone.
        assert!(r.output.contains("context 49")); // adjacent to change
        assert!(!r.output.contains("context 5\n")); // far from change
        assert_eq!(store.get(&r.cache_key).as_deref(), Some(diff.as_str()));
    }

    #[test]
    fn file_cap_summarises_the_tail() {
        // 25 small changed files, cap = 20 → 5 summarised.
        let files: Vec<(String, Vec<String>)> = (0..25)
            .map(|i| (format!("src/f{i}.rs"), vec![format!("-a{i}"), format!("+b{i}")]))
            .collect();
        let mut diff = String::new();
        for (path, body) in &files {
            diff.push_str(&format!("diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n"));
            for b in body {
                diff.push_str(b);
                diff.push('\n');
            }
        }
        let store = InMemoryCcrStore::new();
        let r = offload()
            .apply(&diff, &CompressionContext::default(), &store)
            .expect("caps files");
        assert!(r.output.contains("5 more changed files trimmed"));
        assert!(r.output.contains("src/f0.rs")); // first kept
        assert!(!r.output.contains("src/f24.rs")); // tail trimmed
    }

    #[test]
    fn real_code_diff_not_flagged() {
        let body: Vec<String> = (0..40)
            .flat_map(|i| vec![format!("-old line {i}"), format!("+new line {i}")])
            .collect();
        let refs: Vec<&str> = body.iter().map(|s| s.as_str()).collect();
        let diff = build_diff(&[("src/main.rs", &refs)]);
        // All changes, no context, no lockfile → nothing droppable → score 0.
        assert_eq!(offload().estimate_bloat(&diff), 0.0);
        let store = InMemoryCcrStore::new();
        assert!(matches!(
            offload().apply(&diff, &CompressionContext::default(), &store),
            Err(TransformError::Skipped { .. })
        ));
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn lockfile_path_match_is_segment_aware() {
        let o = offload();
        assert!(o.is_lockfile("Cargo.lock"));
        assert!(o.is_lockfile("crates/foo/Cargo.lock"));
        assert!(!o.is_lockfile("MyCargo.lock"));
        assert!(!o.is_lockfile("FakeCargo.lockfile"));
    }

    #[test]
    fn leading_commit_message_survives() {
        let mut diff = String::from("From abc Mon Sep 17\nSubject: bump deps\n\n");
        let lock: Vec<String> = (0..40)
            .flat_map(|i| vec![format!("-old{i}"), format!("+new{i}")])
            .collect();
        let refs: Vec<&str> = lock.iter().map(|s| s.as_str()).collect();
        diff.push_str(&build_diff(&[("yarn.lock", &refs)]));
        let store = InMemoryCcrStore::new();
        let r = offload()
            .apply(&diff, &CompressionContext::default(), &store)
            .expect("compresses");
        assert!(r.output.contains("Subject: bump deps"));
        assert!(r.output.contains("lockfile hunk dropped"));
    }
}
