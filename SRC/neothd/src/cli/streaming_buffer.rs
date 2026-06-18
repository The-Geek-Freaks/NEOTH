//! GOLD-ADOPT-24 — streaming-markdown safe-flush buffer.
//!
//! Ported faithfully from goose `crates/goose-cli/src/session/streaming_buffer.rs`
//! (the `MarkdownBuffer` + `find_safe_end` parse-state machine), minus goose's
//! tempfile code-block-truncation bonus (NEOTH renders raw). Accumulates
//! streamed chunks and returns only the prefix that is safe to render — never
//! splitting an open markdown construct (code fence, table, heading, inline
//! code, bold/italic/strikethrough, link/image). Holds the incomplete tail
//! until a later chunk closes it; [`flush`](MarkdownBuffer::flush) releases the
//! remainder unconditionally at stream end.
//!
//! Wired into `cli::chat`'s streaming print loop so a code block streamed token
//! by token isn't printed line-by-line mid-fence (which breaks terminal
//! markdown renderers + looks garbled).

use regex::Regex;
use std::sync::LazyLock;

static INLINE_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(",
        r"\\.",                 // Escaped char (highest priority)
        r"|`+",                 // Inline code (variable length backticks)
        r"|\*\*\*",             // Bold+italic
        r"|\*\*",               // Bold
        r"|\*",                 // Italic
        r"|___",                // Bold+italic (underscore)
        r"|__",                 // Bold (underscore)
        r"|_",                  // Italic (underscore)
        r"|~~",                 // Strikethrough
        r"|\!\[",               // Image start
        r"|\]\(",               // Link URL start
        r"|\[",                 // Link text start
        r"|\]",                 // Bracket close (without following paren)
        r"|\)",                 // Link URL end
        r"|[^\\\*_`~\[\]!()]+", // Plain text (no special chars)
        r"|.",                  // Any other single char
        r")"
    ))
    .unwrap()
});

/// A streaming markdown buffer that tracks open constructs. Accumulates chunks
/// and returns content safe to render, holding back incomplete markdown.
#[derive(Default)]
pub struct MarkdownBuffer {
    buffer: String,
}

/// Current parsing state for markdown constructs.
#[derive(Default, Debug, Clone, PartialEq)]
struct ParseState {
    in_code_block: bool,
    code_fence_char: char,
    code_fence_len: usize,
    in_table: bool,
    pending_heading: bool,
    in_inline_code: bool,
    inline_code_len: usize,
    in_bold: bool,
    in_italic: bool,
    in_strikethrough: bool,
    in_link_text: bool,
    in_link_url: bool,
    in_image_alt: bool,
}

impl ParseState {
    /// True when no markdown construct is currently open.
    fn is_clean(&self) -> bool {
        !self.in_code_block
            && !self.in_table
            && !self.pending_heading
            && !self.in_inline_code
            && !self.in_bold
            && !self.in_italic
            && !self.in_strikethrough
            && !self.in_link_text
            && !self.in_link_url
            && !self.in_image_alt
    }
}

// String slicing here is byte-safe: offsets come only from ASCII anchors
// (newlines, `#`, `|`, fence chars) or from regex token byte-ends over valid
// UTF-8, which always land on char boundaries.
#[allow(clippy::string_slice)]
impl MarkdownBuffer {
    /// Create a new empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a chunk; return the prefix that is now safe to render (everything
    /// up to the last "clean" parse position), or `None` if the buffer holds
    /// only incomplete constructs.
    pub fn push(&mut self, chunk: &str) -> Option<String> {
        self.buffer.push_str(chunk);
        let safe_end = self.find_safe_end();
        if safe_end > 0 {
            let to_render = self.buffer[..safe_end].to_string();
            self.buffer = self.buffer[safe_end..].to_string();
            Some(to_render)
        } else {
            None
        }
    }

    /// Release any remaining buffered content (call at stream end, even with
    /// unclosed constructs).
    pub fn flush(&mut self) -> String {
        std::mem::take(&mut self.buffer)
    }

    /// Last byte position where the parse state is "clean".
    fn find_safe_end(&self) -> usize {
        let mut state = ParseState::default();
        let mut last_safe: usize = 0;
        let bytes = self.buffer.as_bytes();
        let len = bytes.len();
        let mut pos: usize = 0;

        while pos < len {
            let at_line_start = pos == 0 || bytes[pos - 1] == b'\n';

            if at_line_start {
                if let Some(new_pos) = self.process_line_start(&mut state, pos) {
                    pos = new_pos;
                    if state.is_clean() {
                        last_safe = pos;
                    }
                    continue;
                }
            }

            if state.in_code_block {
                while pos < len && bytes[pos] != b'\n' {
                    pos += 1;
                }
                if pos < len {
                    pos += 1;
                }
                continue;
            }

            let remaining = &self.buffer[pos..];
            let line_end = remaining.find('\n').map(|i| pos + i + 1).unwrap_or(len);
            let line_content = &self.buffer[pos..line_end];

            for cap in INLINE_TOKEN_RE.find_iter(line_content) {
                let token = cap.as_str();
                let token_end = pos + cap.end();
                self.process_inline_token(&mut state, token);
                if state.is_clean() {
                    last_safe = token_end;
                }
            }

            if line_end <= len && line_end > pos && bytes[line_end - 1] == b'\n' {
                state.pending_heading = false;
                if state.is_clean() {
                    last_safe = line_end;
                }
            }

            pos = line_end;
        }

        last_safe
    }

    /// Block-level constructs at the start of a line. Returns the new position
    /// after processing, or `None` if no block construct was found.
    fn process_line_start(&self, state: &mut ParseState, pos: usize) -> Option<usize> {
        let remaining = &self.buffer[pos..];

        if state.pending_heading {
            state.pending_heading = false;
        }

        if let Some(fence_result) = self.check_code_fence(remaining, state) {
            return Some(pos + fence_result);
        }

        if state.in_code_block {
            return None;
        }

        if remaining.starts_with('#') {
            let hashes = remaining.chars().take_while(|&c| c == '#').count();
            if hashes <= 6 {
                let after_hashes = &remaining[hashes..];
                if after_hashes.is_empty()
                    || after_hashes.starts_with(' ')
                    || after_hashes.starts_with('\n')
                {
                    state.pending_heading = true;
                    return None;
                }
            }
        }

        if remaining.starts_with('|') {
            state.in_table = true;
            return None;
        }

        if (remaining.starts_with('\n') || remaining.is_empty()) && state.in_table {
            state.in_table = false;
            return Some(pos + 1);
        }

        if state.in_table && !remaining.starts_with('|') {
            state.in_table = false;
        }

        None
    }

    /// Check for a code fence + update state. Returns the position after the
    /// fence line if found.
    fn check_code_fence(&self, line: &str, state: &mut ParseState) -> Option<usize> {
        let trimmed = line.trim_start();
        let fence_char = trimmed.chars().next()?;
        if fence_char != '`' && fence_char != '~' {
            return None;
        }
        let fence_len = trimmed.chars().take_while(|&c| c == fence_char).count();
        if fence_len < 3 {
            return None;
        }
        let after_fence = &trimmed[fence_len..];

        if state.in_code_block {
            if fence_char == state.code_fence_char
                && fence_len >= state.code_fence_len
                && (after_fence.is_empty()
                    || after_fence.starts_with('\n')
                    || after_fence.trim().is_empty())
            {
                state.in_code_block = false;
                state.code_fence_char = '\0';
                state.code_fence_len = 0;
                return Some(line.find('\n').map(|n| n + 1).unwrap_or(line.len()));
            }
        } else {
            state.in_code_block = true;
            state.code_fence_char = fence_char;
            state.code_fence_len = fence_len;
            return Some(line.find('\n').map(|n| n + 1).unwrap_or(line.len()));
        }
        None
    }

    /// Process one inline token + update state.
    fn process_inline_token(&self, state: &mut ParseState, token: &str) {
        if token.starts_with('\\') && token.len() == 2 {
            return;
        }
        if token.starts_with('`') {
            let tick_count = token.len();
            if state.in_inline_code {
                if tick_count == state.inline_code_len {
                    state.in_inline_code = false;
                    state.inline_code_len = 0;
                }
            } else {
                state.in_inline_code = true;
                state.inline_code_len = tick_count;
            }
            return;
        }
        if state.in_inline_code {
            return;
        }
        match token {
            "***" | "___" => {
                if state.in_bold && state.in_italic {
                    state.in_bold = false;
                    state.in_italic = false;
                } else if state.in_bold {
                    state.in_italic = !state.in_italic;
                } else if state.in_italic {
                    state.in_bold = !state.in_bold;
                } else {
                    state.in_bold = true;
                    state.in_italic = true;
                }
            }
            "**" | "__" => state.in_bold = !state.in_bold,
            "*" | "_" => state.in_italic = !state.in_italic,
            "~~" => state.in_strikethrough = !state.in_strikethrough,
            "![" => state.in_image_alt = true,
            "[" if !state.in_link_text && !state.in_image_alt => state.in_link_text = true,
            "](" => {
                if state.in_link_text {
                    state.in_link_text = false;
                    state.in_link_url = true;
                } else if state.in_image_alt {
                    state.in_image_alt = false;
                    state.in_link_url = true;
                }
            }
            ")" if state.in_link_url => state.in_link_url = false,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive chunks through the buffer + return every flushed segment (skipping
    /// None, appending the final flush). Mirrors goose's test harness.
    fn stream(chunks: &[&str]) -> Vec<String> {
        let mut buf = MarkdownBuffer::new();
        let mut out: Vec<String> = chunks.iter().filter_map(|c| buf.push(c)).collect();
        let rest = buf.flush();
        if !rest.is_empty() {
            out.push(rest);
        }
        out
    }

    #[test]
    fn plain_text_streams_through_immediately() {
        assert_eq!(
            stream(&["I'll", " help", " with", " that", "!"]),
            &["I'll", " help", " with", " that", "!"]
        );
    }

    #[test]
    fn bold_split_mid_word_is_held_until_closed() {
        assert_eq!(
            stream(&["Here's the **important", "** part."]),
            &["Here's the ", "**important** part."]
        );
    }

    #[test]
    fn inline_code_split_is_held() {
        assert_eq!(
            stream(&["Use the `println!", "` macro."]),
            &["Use the ", "`println!` macro."]
        );
    }

    #[test]
    fn link_url_split_is_held() {
        assert_eq!(
            stream(&["Check [the docs](https://doc", "s.rs) for more."]),
            &["Check ", "[the docs](https://docs.rs) for more."]
        );
    }

    #[test]
    fn code_block_not_flushed_mid_body_only_after_closing_fence() {
        assert_eq!(
            stream(&[
                "```rust\n",
                "fn main() {\n",
                "    println!(\"hi\");\n",
                "}\n",
                "```\n"
            ]),
            &["```rust\nfn main() {\n    println!(\"hi\");\n}\n```\n"]
        );
    }

    #[test]
    fn nested_fence_with_longer_outer_fence() {
        assert_eq!(
            stream(&["````md\n", "```\ninner\n```\n", "````\n"]),
            &["````md\n```\ninner\n```\n````\n"]
        );
    }

    #[test]
    fn tilde_code_fence() {
        assert_eq!(
            stream(&["~~~bash\n", "echo 'hello'\n", "~", "~~\n"]),
            &["~~~bash\necho 'hello'\n~~~\n"]
        );
    }

    #[test]
    fn unclosed_code_block_flushes_at_end() {
        assert_eq!(stream(&["```\ncode"]), &["```\ncode"]);
    }

    #[test]
    fn heading_split_mid_word_is_held_until_newline() {
        assert_eq!(
            stream(&["# Getting St", "arted\n\nFirst, install..."]),
            &["# Getting Started\n\nFirst, install..."]
        );
    }

    #[test]
    fn table_held_until_blank_line() {
        assert_eq!(
            stream(&[
                "| Name | Value |\n",
                "|------|-------|\n",
                "| foo  | 42 |\n",
                "\nMore"
            ]),
            &["| Name | Value |\n|------|-------|\n| foo  | 42 |\n\nMore"]
        );
    }
}
