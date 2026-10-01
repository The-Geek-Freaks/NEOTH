//! Rust-only, source-bound declaration chunks for code-map prompt recall.
//!
//! This module intentionally has no database or provider dependency.  A
//! caller must prove the raw bytes against the scanner metadata and obtain an
//! exact UTF-8 view before invoking it.  Parse errors and every local budget
//! refusal are represented as an empty result so metadata-only recall keeps
//! working for the file.

use anyhow::{Context, Result, ensure};

use super::walker::Language;

pub(crate) const RUST_CHUNK_TARGET_CHARS: usize = 2_500;
pub(crate) const RUST_CHUNK_MAX_OVERLAP_CHARS: usize = 300;
pub(crate) const MAX_CHUNK_BYTES: usize = 16 * 1024;
pub(crate) const MAX_CHUNKS_PER_FILE: usize = 256;
pub(crate) const MAX_CHUNK_TEXT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CodeChunk {
    pub(crate) path: String,
    pub(crate) source_sha256: String,
    pub(crate) language: Language,
    pub(crate) ordinal: u32,
    pub(crate) start_byte: u64,
    pub(crate) end_byte: u64,
    pub(crate) start_line: u32,
    pub(crate) end_line: u32,
    pub(crate) text: String,
}

/// Return whole Rust declaration chunks in stable source order.
///
/// The Rust grammar emits a `source_file` root whose named children are the
/// declaration-level forms we need.  Adjacent legal nodes may be packed, but
/// no range is sliced at an arbitrary byte boundary.  An error tree or a
/// node that exceeds the persistence ceiling refuses AST recall for the whole
/// file rather than claiming an artificial node boundary.
pub(crate) fn rust_chunks_from_verified_source(
    path: &str,
    source_sha256: &str,
    source: &str,
) -> Result<Vec<CodeChunk>> {
    if path.is_empty()
        || source_sha256.len() != 64
        || !source_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        || source.is_empty()
    {
        return Ok(Vec::new());
    }

    let mut parser = tree_sitter::Parser::new();
    let language = tree_sitter_rust::LANGUAGE;
    parser
        .set_language(&language.into())
        .context("configure Tree-sitter Rust grammar")?;
    let Some(tree) = parser.parse(source, None) else {
        return Ok(Vec::new());
    };
    let root = tree.root_node();
    if root.has_error() || root.kind() != "source_file" {
        return Ok(Vec::new());
    }

    let mut declarations = Vec::new();
    let mut cursor = root.walk();
    for node in root.named_children(&mut cursor) {
        let start = node.start_byte();
        let end = node.end_byte();
        if start >= end
            || end > source.len()
            || !source.is_char_boundary(start)
            || !source.is_char_boundary(end)
        {
            return Ok(Vec::new());
        }
        let text = &source[start..end];
        if text.len() > MAX_CHUNK_BYTES {
            return Ok(Vec::new());
        }
        declarations.push((start, end));
    }
    if declarations.is_empty() {
        return Ok(Vec::new());
    }

    let mut ranges = Vec::new();
    let mut start_index = 0usize;
    let mut end_index = 0usize;
    for next_index in 1..declarations.len() {
        let packed = source
            .get(declarations[start_index].0..declarations[next_index].1)
            .context("Tree-sitter packed chunk range was not UTF-8 aligned")?
            .chars()
            .count();
        if packed <= RUST_CHUNK_TARGET_CHARS {
            end_index = next_index;
        } else {
            ranges.push((declarations[start_index].0, declarations[end_index].1));
            // Reuse as many trailing, complete declaration nodes as fit in
            // the character budget. This retains real syntax-node boundaries
            // and guarantees progress because the new node is always added.
            let mut overlap_start = end_index + 1;
            let mut overlap_chars = 0usize;
            for index in (start_index..=end_index).rev() {
                let candidate_overlap = source
                    .get(declarations[index].0..declarations[end_index].1)
                    .context("Tree-sitter overlap range was not UTF-8 aligned")?
                    .chars()
                    .count();
                let candidate_bytes = declarations[next_index]
                    .1
                    .checked_sub(declarations[index].0)
                    .context("Tree-sitter overlap byte range underflow")?;
                if candidate_overlap > RUST_CHUNK_MAX_OVERLAP_CHARS
                    || candidate_bytes > MAX_CHUNK_BYTES
                {
                    break;
                }
                overlap_start = index;
                overlap_chars = candidate_overlap;
            }
            debug_assert!(overlap_chars <= RUST_CHUNK_MAX_OVERLAP_CHARS);
            start_index = overlap_start;
            end_index = next_index;
        }
    }
    ranges.push((declarations[start_index].0, declarations[end_index].1));
    if ranges.len() > MAX_CHUNKS_PER_FILE {
        return Ok(Vec::new());
    }

    let mut total = 0usize;
    let mut chunks = Vec::with_capacity(ranges.len());
    for (ordinal, (start, end)) in ranges.into_iter().enumerate() {
        let text = source
            .get(start..end)
            .context("Tree-sitter chunk range was not UTF-8 aligned")?;
        ensure!(!text.is_empty(), "Tree-sitter produced an empty chunk");
        total = total
            .checked_add(text.len())
            .context("Rust AST chunk aggregate overflow")?;
        if total > MAX_CHUNK_TEXT_BYTES {
            return Ok(Vec::new());
        }
        let ordinal = u32::try_from(ordinal).context("Rust AST chunk ordinal overflow")?;
        let start_line = u32::try_from(
            source[..start]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count()
                + 1,
        )
        .context("Rust AST chunk start line overflow")?;
        let end_line =
            u32::try_from(source[..end].bytes().filter(|byte| *byte == b'\n').count() + 1)
                .context("Rust AST chunk end line overflow")?;
        chunks.push(CodeChunk {
            path: path.to_owned(),
            source_sha256: source_sha256.to_ascii_lowercase(),
            language: Language::Rust,
            ordinal,
            start_byte: u64::try_from(start).context("Rust AST chunk start offset overflow")?,
            end_byte: u64::try_from(end).context("Rust AST chunk end offset overflow")?,
            start_line,
            end_line,
            text: text.to_owned(),
        });
    }
    Ok(chunks)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn rust_ast_chunks_are_deterministic_node_bounded_and_utf8_safe() {
        let source = "pub fn café() {}\n\npub struct Example { pub field: String }\n";
        let first = rust_chunks_from_verified_source("src/lib.rs", SHA, source).unwrap();
        let second = rust_chunks_from_verified_source("src/lib.rs", SHA, source).unwrap();
        assert_eq!(first, second);
        assert!(!first.is_empty());
        for (ordinal, chunk) in first.iter().enumerate() {
            assert_eq!(chunk.ordinal, ordinal as u32);
            assert_eq!(
                &source[chunk.start_byte as usize..chunk.end_byte as usize],
                chunk.text
            );
            assert!(source.is_char_boundary(chunk.start_byte as usize));
            assert!(source.is_char_boundary(chunk.end_byte as usize));
        }
    }

    #[test]
    fn rust_ast_chunks_target_2500_chars_and_cap_300_char_overlap() {
        let source = (0..16)
            .map(|n| format!("pub fn declaration_{n}_é() {{ {} }}\n", "x".repeat(180)))
            .collect::<String>();
        let chunks = rust_chunks_from_verified_source("src/lib.rs", SHA, &source).unwrap();
        assert!(chunks.len() > 1);
        for pair in chunks.windows(2) {
            assert!(pair[0].text.chars().count() <= RUST_CHUNK_TARGET_CHARS);
            let overlap_start = pair[0].start_byte.max(pair[1].start_byte) as usize;
            let overlap_end = pair[0].end_byte.min(pair[1].end_byte) as usize;
            let overlap = &source[overlap_start..overlap_end];
            assert!(
                !overlap.is_empty(),
                "small declarations should produce actual node overlap"
            );
            assert!(overlap.chars().count() <= RUST_CHUNK_MAX_OVERLAP_CHARS);
            assert!(source.is_char_boundary(overlap_start) && source.is_char_boundary(overlap_end));
        }
    }

    #[test]
    fn unsupported_invalid_or_error_tree_keeps_existing_file_symbol_recall() {
        assert!(
            rust_chunks_from_verified_source("src/lib.rs", SHA, "fn incomplete(")
                .unwrap()
                .is_empty()
        );
        assert!(
            rust_chunks_from_verified_source("", SHA, "fn ok() {}")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn oversize_declaration_refuses_ast_text_without_changing_metadata_recall() {
        let source = format!("pub fn too_large() {{ {} }}", "x".repeat(MAX_CHUNK_BYTES));
        assert!(
            rust_chunks_from_verified_source("src/lib.rs", SHA, &source)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn overlap_is_suppressed_when_a_legal_near_cap_node_would_exceed_persistence_bytes() {
        let prefix = "pub fn overlap_seed() {}\n";
        let declaration = format!(
            "pub const NEAR_CAP: &str = \"{}\";\n",
            "x".repeat(MAX_CHUNK_BYTES - 48)
        );
        let source = format!("{prefix}{declaration}");
        let chunks = rust_chunks_from_verified_source("src/lib.rs", SHA, &source).unwrap();
        assert_eq!(chunks.len(), 2);
        assert!(
            chunks
                .iter()
                .all(|chunk| chunk.text.len() <= MAX_CHUNK_BYTES)
        );
        assert_eq!(chunks[1].start_byte as usize, prefix.len());
        assert!(chunks[1].text.starts_with("pub const NEAR_CAP"));
    }
}
