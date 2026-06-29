//! Block-filter: redact `neoth-ignore-start` … `neoth-ignore-end` regions
//! from the text the LLM sees, then restore them after the reply is received.
//!
//! ## Purpose
//!
//! The `code_simplification` skill prompts the LLM to read source files and
//! suggest removals.  Operators annotate intentionally-kept complexity with
//! marker comments so those regions are never simplified away:
//!
//! ```text
//! // neoth-ignore-start
//! fn kept() { /* complex but required */ }
//! // neoth-ignore-end
//! ```
//!
//! At `PreProviderCall` the hook replaces each annotated block with a compact
//! placeholder.  At `PostProviderCall` `restore_blocks` puts the originals
//! back so neither the WAL nor downstream recall ever sees a placeholder.
//!
//! ## Placeholder uniqueness
//!
//! Placeholders embed the **byte-offset** of the original block so a body that
//! happens to mention the placeholder text (e.g. in a code comment) can never
//! collide.  Restoring uses exact-string replacement in insertion order; the
//! embedded offset makes each key unique even when two ignored blocks have the
//! same line count.

/// One redacted region.  `placeholder` is the string inserted into the body;
/// `original` is the full text (from `start_marker` line to `end_marker` line
/// inclusive) that will be restored by `restore_blocks`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilteredBlock {
    /// The placeholder string as it appears in the redacted body.
    /// Used as the search key in `restore_blocks`.
    pub placeholder: String,
    /// The exact original text that was removed, including marker lines.
    pub original: String,
}

/// Scan `body` for `start_marker` / `end_marker` line-pairs and replace each
/// pair (inclusive) with a placeholder derived from `placeholder_template`.
///
/// `placeholder_template` may contain `{lines}` which is substituted with the
/// number of lines in the original block (including marker lines), and
/// `{offset}` which is substituted with the byte-offset of the block start in
/// `body` (makes each placeholder unique even when two blocks have equal line
/// counts).
///
/// Lines are split on `\n`; the trailing newline after the end-marker is
/// preserved if present in the source.
///
/// Returns `(filtered_body, blocks)`.  When no markers are found the body is
/// returned unchanged and `blocks` is empty.
pub fn apply_block_filter(
    body: &str,
    start_marker: &str,
    end_marker: &str,
    placeholder_template: &str,
) -> (String, Vec<FilteredBlock>) {
    let mut filtered = String::with_capacity(body.len());
    let mut blocks: Vec<FilteredBlock> = Vec::new();

    // Track byte-offset into `body` as we walk lines so each placeholder is
    // unique even when two regions have the same line count.
    let mut byte_offset: usize = 0;
    let mut inside = false;
    let mut block_start_offset: usize = 0;
    let mut block_lines: Vec<&str> = Vec::new();

    for line in body.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if !inside {
            if trimmed.contains(start_marker) {
                // Begin collecting the ignored block.
                inside = true;
                block_start_offset = byte_offset;
                block_lines.clear();
                block_lines.push(line);
            } else {
                filtered.push_str(line);
            }
        } else {
            block_lines.push(line);
            if trimmed.contains(end_marker) {
                // Emit placeholder in place of the collected block.
                let original: String = block_lines.concat();
                let line_count = block_lines.len();
                let placeholder = placeholder_template
                    .replace("{lines}", &line_count.to_string())
                    .replace("{offset}", &block_start_offset.to_string());
                // Preserve the trailing newline that would follow the block.
                let placeholder_line = if original.ends_with('\n') {
                    format!("{placeholder}\n")
                } else {
                    placeholder.clone()
                };
                filtered.push_str(&placeholder_line);
                blocks.push(FilteredBlock {
                    placeholder: placeholder_line.clone(),
                    original,
                });
                inside = false;
            }
        }
        byte_offset += line.len();
    }

    // If the body ended inside an open ignore block (malformed — no closing
    // marker) flush it unchanged so we don't lose content silently.
    if inside {
        for line in &block_lines {
            filtered.push_str(line);
        }
        tracing::warn!(
            "block_filter: unclosed `{start_marker}` at byte {block_start_offset} — \
             block passed through unchanged"
        );
    }

    (filtered, blocks)
}

/// Restore previously-redacted blocks into `body`.
///
/// Each `FilteredBlock.placeholder` is replaced (first occurrence, in
/// insertion order) with `FilteredBlock.original`.  If a placeholder is not
/// found in `body` it is silently skipped — this is safe when the PostProvider
/// hook fires on already-restored text or when the model stripped the
/// placeholder from its reply.
pub fn restore_blocks(body: &str, blocks: &[FilteredBlock]) -> String {
    if blocks.is_empty() {
        return body.to_string();
    }
    let mut result = body.to_string();
    for block in blocks {
        if let Some(pos) = result.find(&block.placeholder) {
            result.replace_range(pos..pos + block.placeholder.len(), &block.original);
        }
    }
    result
}

/// Default placeholder template used when the operator omits the field in TOML.
pub fn default_placeholder() -> String {
    "/* neoth-ignore: {lines} lines — intentionally kept (offset {offset}) */".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const START: &str = "neoth-ignore-start";
    const END: &str = "neoth-ignore-end";
    const TMPL: &str = "/* neoth-ignore: {lines} lines (offset {offset}) */";

    // ── apply_block_filter ────────────────────────────────────────────────

    #[test]
    fn no_markers_returns_body_unchanged_and_empty_blocks() {
        let body = "fn foo() {}\nfn bar() {}\n";
        let (filtered, blocks) = apply_block_filter(body, START, END, TMPL);
        assert_eq!(filtered, body);
        assert!(blocks.is_empty());
    }

    #[test]
    fn single_block_is_replaced_with_placeholder() {
        let body = "fn foo() {}\n// neoth-ignore-start\nfn kept() { /* complex */ }\n// neoth-ignore-end\nfn bar() {}\n";
        let (filtered, blocks) = apply_block_filter(body, START, END, TMPL);

        // Non-ignored content passes through.
        assert!(filtered.contains("fn foo()"), "fn foo must survive");
        assert!(filtered.contains("fn bar()"), "fn bar must survive");
        // Ignored region is gone.
        assert!(!filtered.contains("fn kept()"), "kept() must be hidden from LLM");
        assert!(!filtered.contains(START), "start-marker must not appear in filtered body");
        assert!(!filtered.contains(END), "end-marker must not appear in filtered body");
        // A placeholder was injected.
        assert_eq!(blocks.len(), 1);
        assert!(filtered.contains("neoth-ignore"), "placeholder must appear in filtered body");
        // The placeholder reports 3 lines (start-marker line + body + end-marker line).
        assert!(blocks[0].placeholder.contains('3') || blocks[0].placeholder.contains("3 lines"),
            "placeholder must mention 3 lines: {:?}", blocks[0].placeholder);
    }

    #[test]
    fn multiple_blocks_all_replaced() {
        let body = concat!(
            "before\n",
            "// neoth-ignore-start\nfirst ignored\n// neoth-ignore-end\n",
            "middle\n",
            "// neoth-ignore-start\nsecond ignored\n// neoth-ignore-end\n",
            "after\n",
        );
        let (filtered, blocks) = apply_block_filter(body, START, END, TMPL);
        assert!(filtered.contains("before"));
        assert!(filtered.contains("middle"));
        assert!(filtered.contains("after"));
        assert!(!filtered.contains("first ignored"));
        assert!(!filtered.contains("second ignored"));
        assert_eq!(blocks.len(), 2);
        // Placeholders are unique because byte-offsets differ.
        assert_ne!(blocks[0].placeholder, blocks[1].placeholder,
            "placeholders must be unique even when line counts match");
    }

    // ── restore_blocks ────────────────────────────────────────────────────

    #[test]
    fn restore_is_perfect_inverse_of_apply() {
        let body = "fn foo() {}\n// neoth-ignore-start\nfn kept() { /* complex */ }\n// neoth-ignore-end\nfn bar() {}\n";
        let (filtered, blocks) = apply_block_filter(body, START, END, TMPL);
        let restored = restore_blocks(&filtered, &blocks);
        assert_eq!(restored, body, "restore must be a perfect inverse of apply");
    }

    #[test]
    fn restore_multiple_blocks_round_trips() {
        let body = concat!(
            "before\n",
            "// neoth-ignore-start\nfirst\n// neoth-ignore-end\n",
            "between\n",
            "// neoth-ignore-start\nsecond\n// neoth-ignore-end\n",
            "after\n",
        );
        let (filtered, blocks) = apply_block_filter(body, START, END, TMPL);
        let restored = restore_blocks(&filtered, &blocks);
        assert_eq!(restored, body);
    }

    #[test]
    fn restore_on_empty_blocks_is_noop() {
        let body = "no markers here\n";
        let result = restore_blocks(body, &[]);
        assert_eq!(result, body);
    }

    #[test]
    fn restore_missing_placeholder_is_silently_skipped() {
        // If the model's response stripped the placeholder, restore must not panic.
        let block = FilteredBlock {
            placeholder: "/* neoth-ignore: 3 lines (offset 0) */\n".to_string(),
            original: "// neoth-ignore-start\nfn kept() {}\n// neoth-ignore-end\n".to_string(),
        };
        // Body does NOT contain the placeholder (model rewrote it).
        let body = "fn foo() {}\n";
        let result = restore_blocks(body, &[block]);
        // Must not panic and must return the body unchanged.
        assert_eq!(result, body);
    }

    #[test]
    fn unclosed_start_marker_is_passed_through() {
        // Malformed input: start marker with no matching end marker.
        let body = "fn foo() {}\n// neoth-ignore-start\norphan line\n";
        let (filtered, blocks) = apply_block_filter(body, START, END, TMPL);
        // The block content must be preserved (not lost silently).
        assert!(filtered.contains("orphan line"), "unclosed block must pass through");
        assert!(blocks.is_empty(), "no blocks emitted for unclosed region");
    }

    #[test]
    fn custom_markers_work() {
        let body = "a\n#begin-skip\nb\n#end-skip\nc\n";
        let (filtered, blocks) = apply_block_filter(body, "#begin-skip", "#end-skip", "SKIP({lines})");
        assert!(filtered.contains("SKIP(3)"), "custom template applied");
        assert!(!filtered.contains("#begin-skip"));
        let restored = restore_blocks(&filtered, &blocks);
        assert_eq!(restored, body);
    }

    #[test]
    fn toml_round_trip_via_default_placeholder_fn() {
        // Ensure the default_placeholder() function produces a non-empty template
        // that contains the required substitution tokens.
        let tmpl = default_placeholder();
        assert!(tmpl.contains("{lines}"), "default template must contain {{lines}}");
        assert!(tmpl.contains("{offset}"), "default template must contain {{offset}}");
    }
}
