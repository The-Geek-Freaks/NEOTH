//! GOLD-HR-07 — `SearchOffload`: thin clustered grep/ripgrep output.
//!
//! A repo-wide `grep` can return hundreds of `file:line:content` hits, most of
//! them clustered into a few files. The model rarely needs all 50 matches in
//! `utils.py` — it needs a few representative hits per file plus a count of the
//! rest. This offload keeps the top matches per file (preferring lines that hit
//! the user's query — the folded-in "anchor" selection), summarises the
//! remainder, caps the file count, and stashes the byte-exact original via CCR.
//!
//! Anchor selection is folded in here rather than as headroom's separate
//! 1200-line `anchor_selector` (a full relevance ranker): a match whose content
//! contains a query token ranks ahead of one that doesn't. Lines that aren't
//! `file:line:` hits (ripgrep summaries, blank separators) pass through
//! verbatim.

use std::collections::BTreeMap;
use std::fmt::Write;

use crate::context::compress::ccr::{compute_key, marker_for, CcrStore};
use crate::context::compress::content_detector::ContentType;
use crate::context::compress::transform::{
    CompressionContext, OffloadOutput, OffloadTransform, TransformError,
};

const NAME: &str = "search_offload";
const CONFIDENCE: f32 = 0.8;

/// Parse a `path:line:` (grep -n style) hit, returning the path slice — the same
/// grammar the content detector uses to recognise search output. **Windows-aware
/// (GOLD-ADAPT-HR-01):** a leading drive prefix (`C:\…` / `C:/…`) is not mistaken
/// for the `:line:` delimiter. The old `^([^\s:]+):\d+:` regex matched only `C`
/// then failed on the backslash, so on NEOTH's own Windows build platform every
/// drive-rooted grep hit fell through unrecognised and search output was never
/// thinned. Returns `None` for non-hit lines (ripgrep summaries, blank
/// separators, timestamped log lines) so they pass through verbatim.
fn parse_line_path(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    // Skip a Windows drive prefix so its colon isn't read as the line marker.
    let scan_from = if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
    {
        3
    } else {
        0
    };
    // The path runs to the FIRST colon at/after scan_from; that colon must open a
    // `:<digits>:` line-number marker (matching the original grammar).
    let colon = scan_from + bytes[scan_from..].iter().position(|&b| b == b':')?;
    let num_start = colon + 1;
    let num_end = num_start
        + bytes[num_start..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
    if num_end == num_start || bytes.get(num_end) != Some(&b':') {
        return None;
    }
    let path = &line[..colon];
    if path.is_empty() || path.bytes().any(|b| b.is_ascii_whitespace()) {
        return None;
    }
    Some(path)
}

/// Tunables for [`SearchOffload`]. Code-level defaults; not freedom.yaml.
#[derive(Debug, Clone, Copy)]
pub struct SearchOffloadConfig {
    /// Fewer total matches than this → passthrough.
    pub min_matches: usize,
    /// Matches kept per file before the rest are summarised.
    pub per_file_keep: usize,
    /// Files kept before the rest are summarised as a count.
    pub max_files: usize,
}

impl Default for SearchOffloadConfig {
    fn default() -> Self {
        Self {
            min_matches: 10,
            per_file_keep: 3,
            max_files: 30,
        }
    }
}

pub struct SearchOffload {
    config: SearchOffloadConfig,
}

impl SearchOffload {
    pub fn new(config: SearchOffloadConfig) -> Self {
        Self { config }
    }
}

impl Default for SearchOffload {
    fn default() -> Self {
        Self::new(SearchOffloadConfig::default())
    }
}

/// A parsed search line: its file (for grouping) + the full original text.
struct Match<'a> {
    file: &'a str,
    line: &'a str,
}

fn parse_matches(content: &str) -> Vec<Match<'_>> {
    content
        .lines()
        .filter_map(|line| parse_line_path(line).map(|file| Match { file, line }))
        .collect()
}

impl OffloadTransform for SearchOffload {
    fn name(&self) -> &'static str {
        NAME
    }

    fn applies_to(&self) -> &[ContentType] {
        &[ContentType::SearchResults]
    }

    fn estimate_bloat(&self, content: &str) -> f32 {
        if content.is_empty() {
            return 0.0;
        }
        let matches = parse_matches(content);
        if matches.len() < self.config.min_matches {
            return 0.0;
        }
        // Droppable = matches beyond per_file_keep in each file.
        let mut per_file: BTreeMap<&str, usize> = BTreeMap::new();
        for m in &matches {
            *per_file.entry(m.file).or_default() += 1;
        }
        let droppable: usize = per_file
            .values()
            .map(|&c| c.saturating_sub(self.config.per_file_keep))
            .sum();
        (droppable as f32 / matches.len() as f32).clamp(0.0, 1.0)
    }

    fn apply(
        &self,
        content: &str,
        ctx: &CompressionContext,
        store: &dyn CcrStore,
    ) -> Result<OffloadOutput, TransformError> {
        let matches = parse_matches(content);
        if matches.len() < self.config.min_matches {
            return Err(TransformError::skipped(NAME, "below min_matches"));
        }

        // Group matches by file, preserving first-seen file order.
        let mut order: Vec<&str> = Vec::new();
        let mut by_file: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for m in &matches {
            if !by_file.contains_key(m.file) {
                order.push(m.file);
            }
            by_file.entry(m.file).or_default().push(m.line);
        }

        let query_terms: Vec<String> = ctx
            .query
            .split_whitespace()
            .filter(|w| w.len() > 1)
            .map(|w| w.to_lowercase())
            .collect();

        let key = compute_key(content.as_bytes());
        let marker = marker_for(&key);

        let mut out = String::with_capacity(content.len() / 2);
        let mut changed = false;
        let file_count = order.len();
        for (idx, file) in order.iter().enumerate() {
            if idx >= self.config.max_files {
                let _ = writeln!(
                    out,
                    "[… {} more files with matches — retrieve {marker} …]",
                    file_count - idx
                );
                changed = true;
                break;
            }
            let hits = &by_file[file];
            let kept = self.rank_and_keep(hits, &query_terms);
            for &line in &kept {
                out.push_str(line);
                out.push('\n');
            }
            if hits.len() > kept.len() {
                let _ = writeln!(
                    out,
                    "[… {} more matches in {file} — retrieve {marker} …]",
                    hits.len() - kept.len()
                );
                changed = true;
            }
        }

        if !content.ends_with('\n') && out.ends_with('\n') {
            out.pop();
        }
        if !changed || out.len() >= content.len() {
            return Err(TransformError::skipped(NAME, "nothing to thin"));
        }
        store.put(&key, content);
        Ok(OffloadOutput::from_lengths(content.len(), out, key))
    }

    fn confidence(&self) -> f32 {
        CONFIDENCE
    }
}

impl SearchOffload {
    /// Keep up to `per_file_keep` matches, query-hitting lines first (anchor
    /// selection), then first-seen order. Output preserves the original
    /// first-seen order of the kept lines.
    fn rank_and_keep<'a>(&self, hits: &[&'a str], query_terms: &[String]) -> Vec<&'a str> {
        if hits.len() <= self.config.per_file_keep {
            return hits.to_vec();
        }
        if query_terms.is_empty() {
            return hits[..self.config.per_file_keep].to_vec();
        }
        // Partition into query-hitting and not, preserving order; take from
        // hitting first, then fill from the rest, then restore input order.
        let mut chosen: Vec<usize> = Vec::new();
        for (i, line) in hits.iter().enumerate() {
            let lower = line.to_lowercase();
            if query_terms.iter().any(|t| lower.contains(t.as_str())) {
                chosen.push(i);
                if chosen.len() == self.config.per_file_keep {
                    break;
                }
            }
        }
        if chosen.len() < self.config.per_file_keep {
            for i in 0..hits.len() {
                if !chosen.contains(&i) {
                    chosen.push(i);
                    if chosen.len() == self.config.per_file_keep {
                        break;
                    }
                }
            }
        }
        chosen.sort_unstable();
        chosen.into_iter().map(|i| hits[i]).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::compress::ccr::{extract_keys, InMemoryCcrStore};

    fn offload() -> SearchOffload {
        SearchOffload::default()
    }

    /// `count` matches in `file`, content `fn_<n>`.
    fn cluster(file: &str, count: usize) -> String {
        (0..count)
            .map(|i| format!("{file}:{}:def fn_{i}", i + 1))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn name_and_applies_to() {
        assert_eq!(offload().name(), "search_offload");
        assert_eq!(offload().applies_to(), &[ContentType::SearchResults]);
    }

    #[test]
    fn parse_line_path_handles_windows_paths_and_rejects_noise() {
        // GOLD-ADAPT-HR-01: the regression — a Windows drive path must parse.
        assert_eq!(
            parse_line_path("C:\\repo\\src\\main.rs:42: fn main() {"),
            Some("C:\\repo\\src\\main.rs"),
            "Windows drive path was dropped before HR-01"
        );
        assert_eq!(parse_line_path("D:/a/b.rs:7:x"), Some("D:/a/b.rs"), "forward-slash drive too");
        // Unix paths still parse (no regression).
        assert_eq!(parse_line_path("src/utils.py:42:def foo"), Some("src/utils.py"));
        assert_eq!(parse_line_path("/home/x/f.rs:1: y"), Some("/home/x/f.rs"));
        // Non-hits pass through (None): summary, blank, a timestamped log line that
        // must NOT be mistaken for a `path:line:` hit, and a missing line number.
        assert_eq!(parse_line_path("12 matches across 3 files"), None);
        assert_eq!(parse_line_path(""), None);
        assert_eq!(parse_line_path("WARNING at 12:34: disk full"), None, "spaced prefix is not a path");
        assert_eq!(parse_line_path("nolinenum.py:foo"), None, "missing line number");
    }

    #[test]
    fn windows_path_cluster_thins_after_hr01() {
        // The whole offload now works on Windows-path search output (a no-op before).
        let input: String = (0..40)
            .map(|i| format!("C:\\repo\\src\\big.rs:{}:def fn_{i}", i + 1))
            .collect::<Vec<_>>()
            .join("\n");
        let store = InMemoryCcrStore::new();
        let r = offload()
            .apply(&input, &CompressionContext::default(), &store)
            .expect("Windows-path search output must now thin");
        assert!(r.bytes_saved > 0);
        assert!(r.output.contains("more matches in C:\\repo\\src\\big.rs"));
    }

    #[test]
    fn few_matches_score_zero() {
        assert_eq!(offload().estimate_bloat(""), 0.0);
        assert_eq!(offload().estimate_bloat(&cluster("a.py", 5)), 0.0);
    }

    #[test]
    fn clustered_matches_score_high_and_thin() {
        let input = cluster("utils.py", 100);
        assert!(offload().estimate_bloat(&input) > 0.9);
        let store = InMemoryCcrStore::new();
        let r = offload()
            .apply(&input, &CompressionContext::default(), &store)
            .expect("thins");
        assert!(r.bytes_saved > 0);
        assert!(r.output.contains("more matches in utils.py"));
        // Default per_file_keep=3 → 3 hits survive.
        assert_eq!(r.output.matches("def fn_").count(), 3);
        assert_eq!(store.get(&r.cache_key).as_deref(), Some(input.as_str()));
        assert_eq!(extract_keys(&r.output)[0], r.cache_key);
    }

    #[test]
    fn query_terms_anchor_the_kept_matches() {
        // 20 matches; the relevant one is fn_17. With a query, it must be kept
        // even though it's not in the first 3.
        let input = cluster("big.py", 20);
        let store = InMemoryCcrStore::new();
        let ctx = CompressionContext::with_query("fn_17");
        let r = offload().apply(&input, &ctx, &store).expect("thins");
        assert!(r.output.contains("big.py:18:def fn_17"), "query anchor must survive: {}", r.output);
    }

    #[test]
    fn file_cap_summarises_tail() {
        // 40 single-match files (so per-file thinning never fires), cap 30.
        let input: String = (0..40)
            .map(|i| format!("f{i}.py:1:def only_{i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let store = InMemoryCcrStore::new();
        let r = offload()
            .apply(&input, &CompressionContext::default(), &store)
            .expect("caps files");
        assert!(r.output.contains("more files with matches"));
        assert!(r.output.contains("f0.py"));
        assert!(!r.output.contains("f39.py"));
    }

    #[test]
    fn non_search_lines_pass_through_and_unclustered_skips() {
        // All distinct files, each 1 match → nothing to thin → skip.
        let input: String = (0..15)
            .map(|i| format!("f{i}.py:1:hit"))
            .collect::<Vec<_>>()
            .join("\n");
        let store = InMemoryCcrStore::new();
        assert!(matches!(
            offload().apply(&input, &CompressionContext::default(), &store),
            Err(TransformError::Skipped { .. })
        ));
        assert_eq!(store.len(), 0);
    }
}
