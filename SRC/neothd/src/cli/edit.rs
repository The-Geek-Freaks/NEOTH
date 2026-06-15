//! GOLD-PROG-09 (OP-01) — `neoth edit`: content-hash "hashline" diffs.
//!
//! A token-efficient edit format (measured ~-61% output tokens vs emitting the
//! full replacement file): instead of re-printing an entire edited file, emit
//! ONLY the changed lines, each anchored by a content hash of the original line
//! at that position:
//!
//! ```text
//! ## hashline v1 lines=<N>
//! @@ <sha256_8> +<lineno>: <new line content>
//! ```
//!
//! The `sha256_8` anchor (first 4 bytes of SHA-256, 8 hex chars) lets
//! [`apply_hashline_diff`] VERIFY it is editing the line it thinks it is — a
//! base that drifted under the diff is rejected, never silently mis-applied.
//! Unchanged lines are omitted; the `lines=<N>` header records the target
//! length so insertions/deletions at the tail reconstruct exactly.
//!
//! Scope (per GOLD-PROG-09 / the tokenopt research): a STANDALONE CLI + the two
//! pure functions. The format is line-index-anchored, so an insertion in the
//! middle shifts every following line (they all re-emit) — a full LCS-anchored
//! variant is a documented follow-up; for the common in-place edit it is
//! compact and round-trips exactly.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Args;
use sha2::{Digest, Sha256};

#[derive(Args, Debug)]
pub struct EditArgs {
    /// The base / original file.
    pub base: PathBuf,
    /// Produce a diff FROM `base` TO this file (prints the diff to stdout).
    #[arg(long)]
    pub new: Option<PathBuf>,
    /// Apply this hashline diff file to `base` and print the reconstructed file.
    #[arg(long)]
    pub apply: Option<PathBuf>,
    /// Emit the diff in the compact content-hash "hashline" format. Defaults to
    /// `freedom.yaml::tokens.hashline_edits` when this flag is absent.
    #[arg(long)]
    pub hashline: bool,
}

const HASHLINE_HEADER: &str = "## hashline v1";

/// 8-hex-char (first 4 bytes of SHA-256) content anchor for one line.
fn anchor(line: &str) -> String {
    let d = Sha256::digest(line.as_bytes());
    format!("{:02x}{:02x}{:02x}{:02x}", d[0], d[1], d[2], d[3])
}

/// Produce a hashline diff transforming `old` into `new`. Each line of `new`
/// that differs from `old` at the same index emits one
/// `@@ <sha256_8(old_line)> +<lineno>: <new_line>`; unchanged lines are omitted.
/// The header records the target line count.
pub fn hashline_diff(old: &str, new: &str) -> String {
    let old_lines: Vec<&str> = old.split('\n').collect();
    let new_lines: Vec<&str> = new.split('\n').collect();
    let mut out = vec![format!("{HASHLINE_HEADER} lines={}", new_lines.len())];
    for (i, nl) in new_lines.iter().enumerate() {
        if old_lines.get(i).copied() != Some(*nl) {
            // Anchor on the OLD line at this index (or the empty string when the
            // new file is longer — apply checks the same empty anchor).
            let old_line = old_lines.get(i).copied().unwrap_or("");
            out.push(format!("@@ {} +{}: {}", anchor(old_line), i, nl));
        }
    }
    out.join("\n")
}

/// Reconstruct the new content from `base` + a hashline `diff`. Verifies every
/// changed line's content-hash anchor against `base` (a drifted base is an
/// error, not a silent mis-apply), then writes the changed lines and sizes the
/// result to the header's recorded length.
pub fn apply_hashline_diff(base: &str, diff: &str) -> Result<String> {
    let base_lines: Vec<&str> = base.split('\n').collect();
    let mut lines = diff.lines();
    let header = lines.next().context("empty hashline diff")?;
    let target_len: usize = header
        .strip_prefix(HASHLINE_HEADER)
        .map(str::trim)
        .and_then(|s| s.strip_prefix("lines="))
        .and_then(|s| s.trim().parse().ok())
        .with_context(|| format!("malformed hashline header: {header:?}"))?;
    // Start from base, resized to the target length (pad with "" / truncate).
    let mut result: Vec<String> = (0..target_len)
        .map(|i| base_lines.get(i).copied().unwrap_or("").to_string())
        .collect();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let rest = line
            .strip_prefix("@@ ")
            .with_context(|| format!("bad hashline change line: {line:?}"))?;
        let (hash, rest) = rest
            .split_once(" +")
            .with_context(|| format!("missing '+N' in: {line:?}"))?;
        let (n_str, content) = rest
            .split_once(": ")
            .with_context(|| format!("missing ': ' in: {line:?}"))?;
        let n: usize = n_str
            .parse()
            .with_context(|| format!("bad line number in: {line:?}"))?;
        if n >= result.len() {
            bail!("hashline change line {n} is beyond the target length {target_len}");
        }
        let base_anchor = base_lines.get(n).copied().unwrap_or("");
        if anchor(base_anchor) != hash {
            bail!(
                "hashline anchor mismatch at line {n}: the base changed under the diff \
                 (diff expects {hash}, base line hashes to {})",
                anchor(base_anchor)
            );
        }
        result[n] = content.to_string();
    }
    Ok(result.join("\n"))
}

/// `neoth edit` dispatch. `hashline_default` is `freedom.yaml::tokens.
/// hashline_edits` (the dispatcher reads it from the loaded config).
pub fn run(args: EditArgs, hashline_default: bool) -> Result<()> {
    let base = std::fs::read_to_string(&args.base)
        .with_context(|| format!("read base {}", args.base.display()))?;

    if let Some(diff_path) = &args.apply {
        let diff = std::fs::read_to_string(diff_path)
            .with_context(|| format!("read diff {}", diff_path.display()))?;
        print!("{}", apply_hashline_diff(&base, &diff)?);
        return Ok(());
    }

    let new_path = args.new.as_ref().context(
        "`neoth edit <base>` needs either --new <file> (to diff) or --apply <diff> (to apply)",
    )?;
    let new = std::fs::read_to_string(new_path)
        .with_context(|| format!("read new {}", new_path.display()))?;

    if args.hashline || hashline_default {
        println!("{}", hashline_diff(&base, &new));
    } else {
        // Non-compact mode: emit the full replacement content.
        print!("{new}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_is_eight_hex_chars_and_content_sensitive() {
        assert_eq!(anchor("hello").len(), 8);
        assert!(anchor("hello").chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(anchor("a"), anchor("b"));
    }

    #[test]
    fn diff_emits_only_changed_lines_in_the_documented_format() {
        let old = "alpha\nbeta\ngamma";
        let new = "alpha\nBETA\ngamma";
        let diff = hashline_diff(old, new);
        assert!(diff.starts_with("## hashline v1 lines=3"));
        // Only line 1 (beta→BETA) changed.
        let changes: Vec<&str> = diff.lines().filter(|l| l.starts_with("@@ ")).collect();
        assert_eq!(changes.len(), 1, "only the one changed line is emitted: {diff}");
        assert_eq!(changes[0], format!("@@ {} +1: BETA", anchor("beta")));
    }

    #[test]
    fn roundtrip_inplace_change() {
        let old = "one\ntwo\nthree";
        let new = "one\nTWO\nthree";
        let diff = hashline_diff(old, new);
        assert_eq!(apply_hashline_diff(old, &diff).unwrap(), new);
    }

    #[test]
    fn roundtrip_appended_tail_lines() {
        let old = "a\nb";
        let new = "a\nb\nc\nd";
        let diff = hashline_diff(old, new);
        assert_eq!(apply_hashline_diff(old, &diff).unwrap(), new);
    }

    #[test]
    fn roundtrip_truncated_tail_lines() {
        let old = "a\nb\nc\nd";
        let new = "a\nb";
        let diff = hashline_diff(old, new);
        assert_eq!(apply_hashline_diff(old, &diff).unwrap(), new);
    }

    #[test]
    fn roundtrip_content_with_colon_and_plus_survives() {
        let old = "key: old\nx";
        let new = "key: new +value: here\nx";
        let diff = hashline_diff(old, new);
        assert_eq!(apply_hashline_diff(old, &diff).unwrap(), new);
    }

    #[test]
    fn apply_rejects_a_drifted_base() {
        let old = "one\ntwo\nthree";
        let new = "one\nTWO\nthree";
        let diff = hashline_diff(old, new);
        // The base changed at line 1 under the diff — the anchor no longer matches.
        let drifted = "one\nDIFFERENT\nthree";
        let err = apply_hashline_diff(drifted, &diff).unwrap_err();
        assert!(err.to_string().contains("anchor mismatch"), "got: {err}");
    }

    #[test]
    fn apply_rejects_a_malformed_header() {
        let err = apply_hashline_diff("base", "not a hashline header\n@@ x +0: y").unwrap_err();
        assert!(err.to_string().contains("malformed hashline header"), "got: {err}");
    }

    #[test]
    fn empty_diff_against_identical_files_roundtrips() {
        let s = "same\nlines";
        let diff = hashline_diff(s, s);
        // No @@ change lines, just the header.
        assert_eq!(diff.lines().filter(|l| l.starts_with("@@ ")).count(), 0);
        assert_eq!(apply_hashline_diff(s, &diff).unwrap(), s);
    }
}
