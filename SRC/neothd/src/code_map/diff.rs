//! Bounded parser for the file and hunk metadata in a unified Git diff.
//!
//! This module deliberately does not run `git`, read the filesystem, or map a
//! hunk to symbols. Its only authority is an already-captured `&str`; callers
//! that obtain a diff must impose their own repository/ref/process boundary.
//! Paths are accepted only in Git's unquoted `a/<repo-relative>` / `b/<repo-
//! relative>` form. Quoted/C-style path records are rejected rather than
//! guessed, because incorrectly decoding a path would weaken the later
//! repository-root boundary.

use std::collections::BTreeMap;
use std::fmt;

/// Maximum accepted diff size before parsing starts.
pub const MAX_DIFF_BYTES: usize = 1_048_576;
/// Maximum distinct file records returned from one diff.
pub const MAX_DIFF_FILES: usize = 256;
/// Maximum hunk records accepted for one file.
pub const MAX_HUNKS_PER_FILE: usize = 2_048;
/// Maximum hunk records accepted for the whole diff.
pub const MAX_TOTAL_HUNKS: usize = 8_192;
/// Maximum lines in either side of one hunk range.
pub const MAX_HUNK_RANGE_LINES: u32 = 100_000;
/// Maximum one-based start line admitted from untrusted hunk metadata.
pub const MAX_HUNK_START_LINE: u32 = 10_000_000;
/// Maximum UTF-8 byte length of one normalized repo-relative path.
pub const MAX_REPO_PATH_BYTES: usize = 4_096;

/// The type of change represented by one diff file record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DiffChange {
    Added,
    Modified,
    Deleted,
    Renamed,
    Binary,
}

/// A half-open line range in a diff side.
///
/// `start` uses Git's one-based convention. For a zero-length range Git may
/// use `0`, which is preserved rather than rewritten to a fictional line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiffRange {
    pub start: u32,
    pub count: u32,
}

impl DiffRange {
    /// Last line included by this range, or `None` for an empty range.
    pub fn last_line(self) -> Option<u32> {
        self.count
            .checked_sub(1)
            .and_then(|offset| self.start.checked_add(offset))
    }
}

/// One `@@ -old +new @@` range pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiffHunk {
    pub old: DiffRange,
    pub new: DiffRange,
}

/// Typed metadata for one changed file.
///
/// Paths never contain an absolute/rooted component, `.`/`..`, backslashes,
/// or an unparsed quoted/C-style escape sequence. `old_path` is absent for
/// additions and `new_path` is absent for deletions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffFile {
    pub change: DiffChange,
    pub old_path: Option<String>,
    pub new_path: Option<String>,
    pub hunks: Vec<DiffHunk>,
}

/// Why a diff was rejected. All errors fail closed; this parser never turns a
/// malformed diff into an empty successful result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiffParseError {
    InputTooLarge { actual: usize, maximum: usize },
    TooManyFiles { maximum: usize },
    TooManyHunks { maximum: usize },
    HunkRangeTooLarge { maximum: u32 },
    PathTooLong { maximum: usize },
    InvalidPath { line: usize, reason: &'static str },
    QuotedPathUnsupported { line: usize },
    MalformedGitHeader { line: usize },
    MalformedFileHeader { line: usize },
    MalformedHunk { line: usize },
    HunkWithoutFile { line: usize },
    ContradictoryFileRecord { line: usize, reason: &'static str },
    MissingFileHeaders { line: usize },
    MissingRenameDestination { line: usize },
    EmptyDiff,
}

impl fmt::Display for DiffParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { actual, maximum } => {
                write!(f, "diff is {actual} bytes; maximum is {maximum}")
            }
            Self::TooManyFiles { maximum } => {
                write!(f, "diff exceeds {maximum} file records")
            }
            Self::TooManyHunks { maximum } => {
                write!(f, "diff exceeds {maximum} hunk records")
            }
            Self::HunkRangeTooLarge { maximum } => {
                write!(f, "hunk range exceeds configured bound {maximum}")
            }
            Self::PathTooLong { maximum } => write!(f, "path exceeds {maximum} bytes"),
            Self::InvalidPath { line, reason } => {
                write!(f, "invalid path at line {line}: {reason}")
            }
            Self::QuotedPathUnsupported { line } => {
                write!(f, "quoted/C-style paths are unsupported at line {line}")
            }
            Self::MalformedGitHeader { line } => {
                write!(f, "malformed diff --git header at line {line}")
            }
            Self::MalformedFileHeader { line } => {
                write!(f, "malformed ---/+++ header at line {line}")
            }
            Self::MalformedHunk { line } => write!(f, "malformed hunk header at line {line}"),
            Self::HunkWithoutFile { line } => {
                write!(f, "hunk without file record at line {line}")
            }
            Self::ContradictoryFileRecord { line, reason } => {
                write!(f, "contradictory file record at line {line}: {reason}")
            }
            Self::MissingFileHeaders { line } => {
                write!(f, "textual diff file is missing ---/+++ headers after line {line}")
            }
            Self::MissingRenameDestination { line } => {
                write!(f, "rename is missing its paired source/destination after line {line}")
            }
            Self::EmptyDiff => f.write_str("diff contains no changed file records"),
        }
    }
}

impl std::error::Error for DiffParseError {}

/// Parse an already-captured unified Git diff into bounded typed file records.
///
/// Returned records are lexically ordered by normalized old/new path and have
/// duplicate hunk ranges removed, so identical input always has one stable
/// representation. A malformed or incomplete record is an error, never an
/// empty success.
pub fn parse_unified_diff(input: &str) -> Result<Vec<DiffFile>, DiffParseError> {
    if input.len() > MAX_DIFF_BYTES {
        return Err(DiffParseError::InputTooLarge {
            actual: input.len(),
            maximum: MAX_DIFF_BYTES,
        });
    }

    let mut files = Vec::new();
    let mut current: Option<PendingFile> = None;
    let mut total_hunks = 0usize;
    let mut awaiting_plus = false;

    for (index, raw_line) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);

        if let Some(pending) = current.as_mut() {
            if pending.hunk_body.is_some() {
                consume_hunk_body_line(pending, line, line_number)?;
                continue;
            }
            if line == "\\ No newline at end of file" {
                if !pending.may_accept_no_newline_marker {
                    return Err(DiffParseError::MalformedHunk { line: line_number });
                }
                pending.may_accept_no_newline_marker = false;
                continue;
            }
            pending.may_accept_no_newline_marker = false;
            if pending.saw_text_hunk
                && !line.starts_with("@@")
                && !line.starts_with("diff --git ")
            {
                return Err(DiffParseError::MalformedHunk { line: line_number });
            }
        }

        if let Some(rest) = line.strip_prefix("diff --git ") {
            if awaiting_plus {
                return Err(DiffParseError::MalformedFileHeader { line: line_number });
            }
            finish_pending(&mut files, current.take(), line_number)?;
            if files.len() >= MAX_DIFF_FILES {
                return Err(DiffParseError::TooManyFiles {
                    maximum: MAX_DIFF_FILES,
                });
            }
            let (old_path, new_path) = parse_git_header(rest, line_number)?;
            current = Some(PendingFile::new(old_path, new_path, line_number));
            continue;
        }

        if let Some(rest) = line.strip_prefix("--- ") {
            let pending = current
                .as_mut()
                .ok_or(DiffParseError::ContradictoryFileRecord {
                    line: line_number,
                    reason: "file header without diff --git record",
                })?;
            if pending.old_header.is_some() || awaiting_plus {
                return Err(DiffParseError::ContradictoryFileRecord {
                    line: line_number,
                    reason: "duplicate --- header",
                });
            }
            pending.old_header = Some(parse_file_header(rest, 'a', line_number)?);
            awaiting_plus = true;
            continue;
        }

        if let Some(rest) = line.strip_prefix("+++ ") {
            let pending = current
                .as_mut()
                .ok_or(DiffParseError::ContradictoryFileRecord {
                    line: line_number,
                    reason: "file header without diff --git record",
                })?;
            if !awaiting_plus || pending.new_header.is_some() {
                return Err(DiffParseError::ContradictoryFileRecord {
                    line: line_number,
                    reason: "+++ header without matching --- header",
                });
            }
            pending.new_header = Some(parse_file_header(rest, 'b', line_number)?);
            awaiting_plus = false;
            continue;
        }

        if line.starts_with("@@") {
            if awaiting_plus {
                return Err(DiffParseError::MalformedFileHeader { line: line_number });
            }
            let pending = current
                .as_mut()
                .ok_or(DiffParseError::HunkWithoutFile { line: line_number })?;
            if pending.old_header.is_none() || pending.new_header.is_none() {
                return Err(DiffParseError::MissingFileHeaders { line: line_number });
            }
            if pending.hunks.len() >= MAX_HUNKS_PER_FILE || total_hunks >= MAX_TOTAL_HUNKS {
                return Err(DiffParseError::TooManyHunks {
                    maximum: MAX_HUNKS_PER_FILE.min(MAX_TOTAL_HUNKS),
                });
            }
            let hunk = parse_hunk(line, line_number)?;
            if hunk.old.count != 0 || hunk.new.count != 0 {
                pending.hunk_body = Some(PendingHunkBody {
                    old_remaining: hunk.old.count,
                    new_remaining: hunk.new.count,
                });
            }
            pending.hunks.push(hunk);
            pending.saw_text_hunk = true;
            total_hunks += 1;
            continue;
        }

        let pending = match current.as_mut() {
            Some(pending) => pending,
            None => continue,
        };
        if let Some(rest) = line.strip_prefix("rename from ") {
            if pending.rename_from.is_some() {
                return Err(DiffParseError::ContradictoryFileRecord {
                    line: line_number,
                    reason: "duplicate rename from",
                });
            }
            pending.rename_from = Some(normalize_repo_path(rest, line_number)?);
        } else if let Some(rest) = line.strip_prefix("rename to ") {
            if pending.rename_to.is_some() {
                return Err(DiffParseError::ContradictoryFileRecord {
                    line: line_number,
                    reason: "duplicate rename to",
                });
            }
            pending.rename_to = Some(normalize_repo_path(rest, line_number)?);
        } else if line == "GIT binary patch" || line.starts_with("Binary files ") {
            pending.binary = true;
        } else if let Some(mode) = line.strip_prefix("new file mode ") {
            validate_mode(mode, line_number)?;
            if pending.new_file_mode {
                return Err(DiffParseError::ContradictoryFileRecord {
                    line: line_number,
                    reason: "duplicate new-file mode",
                });
            }
            pending.new_file_mode = true;
        } else if let Some(mode) = line.strip_prefix("deleted file mode ") {
            validate_mode(mode, line_number)?;
            if pending.deleted_file_mode {
                return Err(DiffParseError::ContradictoryFileRecord {
                    line: line_number,
                    reason: "duplicate deleted-file mode",
                });
            }
            pending.deleted_file_mode = true;
        } else if let Some(mode) = line.strip_prefix("old mode ") {
            validate_mode(mode, line_number)?;
            if pending.old_mode {
                return Err(DiffParseError::ContradictoryFileRecord {
                    line: line_number,
                    reason: "duplicate old mode",
                });
            }
            pending.old_mode = true;
        } else if let Some(mode) = line.strip_prefix("new mode ") {
            validate_mode(mode, line_number)?;
            if pending.new_mode {
                return Err(DiffParseError::ContradictoryFileRecord {
                    line: line_number,
                    reason: "duplicate new mode",
                });
            }
            pending.new_mode = true;
        } else if line.starts_with("index ")
            || line.starts_with("similarity index ")
            || line.starts_with("dissimilarity index ")
            || pending.binary
        {
            // Valid extended header metadata (or opaque GIT binary payload).
        } else {
            return Err(DiffParseError::ContradictoryFileRecord {
                line: line_number,
                reason: "unexpected diff record",
            });
        }
    }

    if awaiting_plus {
        return Err(DiffParseError::MalformedFileHeader {
            line: input.lines().count().saturating_add(1),
        });
    }
    finish_pending(
        &mut files,
        current,
        input.lines().count().saturating_add(1),
    )?;
    if files.is_empty() {
        return Err(DiffParseError::EmptyDiff);
    }

    let mut deduplicated = BTreeMap::<(Option<String>, Option<String>), DiffFile>::new();
    for mut file in files {
        file.hunks.sort_unstable();
        file.hunks.dedup();
        let key = (file.old_path.clone(), file.new_path.clone());
        match deduplicated.get_mut(&key) {
            Some(existing) => {
                if existing.change != file.change {
                    return Err(DiffParseError::ContradictoryFileRecord {
                        line: 0,
                        reason: "same path pair has multiple change kinds",
                    });
                }
                existing.hunks.extend(file.hunks);
                existing.hunks.sort_unstable();
                existing.hunks.dedup();
            }
            None => {
                deduplicated.insert(key, file);
            }
        }
    }
    Ok(deduplicated.into_values().collect())
}

#[derive(Debug)]
struct PendingFile {
    git_old: String,
    git_new: String,
    started_at: usize,
    old_header: Option<Option<String>>,
    new_header: Option<Option<String>>,
    rename_from: Option<String>,
    rename_to: Option<String>,
    hunks: Vec<DiffHunk>,
    hunk_body: Option<PendingHunkBody>,
    may_accept_no_newline_marker: bool,
    saw_text_hunk: bool,
    binary: bool,
    new_file_mode: bool,
    deleted_file_mode: bool,
    old_mode: bool,
    new_mode: bool,
}

impl PendingFile {
    fn new(git_old: String, git_new: String, started_at: usize) -> Self {
        Self {
            git_old,
            git_new,
            started_at,
            old_header: None,
            new_header: None,
            rename_from: None,
            rename_to: None,
            hunks: Vec::new(),
            hunk_body: None,
            may_accept_no_newline_marker: false,
            saw_text_hunk: false,
            binary: false,
            new_file_mode: false,
            deleted_file_mode: false,
            old_mode: false,
            new_mode: false,
        }
    }
}

#[derive(Debug)]
struct PendingHunkBody {
    old_remaining: u32,
    new_remaining: u32,
}

fn consume_hunk_body_line(
    pending: &mut PendingFile,
    line: &str,
    line_number: usize,
) -> Result<(), DiffParseError> {
    if line == "\\ No newline at end of file" {
        if !pending.may_accept_no_newline_marker {
            return Err(DiffParseError::MalformedHunk { line: line_number });
        }
        pending.may_accept_no_newline_marker = false;
        return Ok(());
    }
    let (old_lines, new_lines) = match line.as_bytes().first() {
        Some(b' ') => (1, 1),
        Some(b'-') => (1, 0),
        Some(b'+') => (0, 1),
        _ => return Err(DiffParseError::MalformedHunk { line: line_number }),
    };
    let complete = {
        let body = pending
            .hunk_body
            .as_mut()
            .expect("hunk body state checked by caller");
        if body.old_remaining < old_lines || body.new_remaining < new_lines {
            return Err(DiffParseError::MalformedHunk { line: line_number });
        }
        body.old_remaining -= old_lines;
        body.new_remaining -= new_lines;
        body.old_remaining == 0 && body.new_remaining == 0
    };
    pending.may_accept_no_newline_marker = true;
    if complete {
        pending.hunk_body = None;
    }
    Ok(())
}

fn validate_mode(mode: &str, line: usize) -> Result<(), DiffParseError> {
    if mode.len() != 6 || !mode.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
        return Err(DiffParseError::ContradictoryFileRecord {
            line,
            reason: "invalid file mode",
        });
    }
    Ok(())
}

fn finish_pending(
    files: &mut Vec<DiffFile>,
    pending: Option<PendingFile>,
    line: usize,
) -> Result<(), DiffParseError> {
    let Some(pending) = pending else {
        return Ok(());
    };
    if pending.hunk_body.is_some() {
        return Err(DiffParseError::MalformedHunk { line });
    }
    let has_rename = pending.rename_from.is_some() || pending.rename_to.is_some();
    if has_rename && (pending.rename_from.is_none() || pending.rename_to.is_none()) {
        return Err(DiffParseError::MissingRenameDestination { line });
    }
    if pending.new_file_mode && pending.deleted_file_mode {
        return Err(DiffParseError::ContradictoryFileRecord {
            line,
            reason: "both new-file and deleted-file modes",
        });
    }
    if pending.old_mode != pending.new_mode {
        return Err(DiffParseError::ContradictoryFileRecord {
            line,
            reason: "unpaired old/new mode record",
        });
    }

    let headers_present = pending.old_header.is_some() || pending.new_header.is_some();
    if headers_present && (pending.old_header.is_none() || pending.new_header.is_none()) {
        return Err(DiffParseError::MissingFileHeaders { line });
    }

    let (old_header, new_header) = match (pending.old_header, pending.new_header) {
        (Some(old), Some(new)) => (old, new),
        (None, None) if pending.new_file_mode => (None, Some(pending.git_new.clone())),
        (None, None) if pending.deleted_file_mode => (Some(pending.git_old.clone()), None),
        (None, None) => (Some(pending.git_old.clone()), Some(pending.git_new.clone())),
        _ => unreachable!("partial file headers already rejected"),
    };
    let rename = match (pending.rename_from, pending.rename_to) {
        (Some(from), Some(to)) => Some((from, to)),
        (None, None) => None,
        _ => unreachable!("paired rename already checked"),
    };

    let (change, old_path, new_path) = if pending.binary {
        if let Some((from, to)) = rename.as_ref() {
            if old_header
                .as_deref()
                .is_some_and(|header| header != from.as_str())
                || new_header
                    .as_deref()
                    .is_some_and(|header| header != to.as_str())
            {
                return Err(DiffParseError::ContradictoryFileRecord {
                    line,
                    reason: "binary rename paths disagree with file headers",
                });
            }
        } else if old_header
            .as_deref()
            .is_some_and(|header| header != pending.git_old.as_str())
            || new_header
                .as_deref()
                .is_some_and(|header| header != pending.git_new.as_str())
        {
            return Err(DiffParseError::ContradictoryFileRecord {
                line,
                reason: "binary paths disagree with diff --git header",
            });
        }
        let old = rename.as_ref().map_or(old_header, |(from, _)| Some(from.clone()));
        let new = rename.as_ref().map_or(new_header, |(_, to)| Some(to.clone()));
        (DiffChange::Binary, old, new)
    } else if let Some((from, to)) = rename {
        if old_header.as_deref() != Some(from.as_str())
            || new_header.as_deref() != Some(to.as_str())
        {
            return Err(DiffParseError::ContradictoryFileRecord {
                line,
                reason: "rename paths disagree with file headers",
            });
        }
        (DiffChange::Renamed, Some(from), Some(to))
    } else {
        match (old_header, new_header, pending.new_file_mode, pending.deleted_file_mode) {
            (None, Some(new), _, false) if new == pending.git_new => {
                (DiffChange::Added, None, Some(new))
            }
            (Some(old), None, false, _) if old == pending.git_old => {
                (DiffChange::Deleted, Some(old), None)
            }
            (Some(old), Some(new), false, false)
                if old == pending.git_old && new == pending.git_new && old == new =>
            {
                (DiffChange::Modified, Some(old), Some(new))
            }
            (Some(_), Some(_), false, false) => {
                return Err(DiffParseError::ContradictoryFileRecord {
                    line,
                    reason: "different paths require explicit rename metadata",
                });
            }
            _ => {
                return Err(DiffParseError::ContradictoryFileRecord {
                    line,
                    reason: "headers and file mode disagree",
                });
            }
        }
    };

    if !pending.binary
        && pending.hunks.is_empty()
        && change == DiffChange::Modified
        && !(pending.old_mode && pending.new_mode)
    {
        return Err(DiffParseError::ContradictoryFileRecord {
            line: pending.started_at,
            reason: "modified file has no hunk",
        });
    }
    files.push(DiffFile {
        change,
        old_path,
        new_path,
        hunks: pending.hunks,
    });
    Ok(())
}

fn parse_git_header(rest: &str, line: usize) -> Result<(String, String), DiffParseError> {
    if rest.starts_with('"') || rest.contains('"') || rest.contains('\\') {
        return Err(DiffParseError::QuotedPathUnsupported { line });
    }
    let mut parts = rest.split_ascii_whitespace();
    let old = parts.next().ok_or(DiffParseError::MalformedGitHeader { line })?;
    let new = parts.next().ok_or(DiffParseError::MalformedGitHeader { line })?;
    if parts.next().is_some() {
        return Err(DiffParseError::MalformedGitHeader { line });
    }
    Ok((
        parse_prefixed_path(old, 'a', line)?,
        parse_prefixed_path(new, 'b', line)?,
    ))
}

fn parse_file_header(
    rest: &str,
    side: char,
    line: usize,
) -> Result<Option<String>, DiffParseError> {
    let token = rest.split_once('\t').map_or(rest, |(path, _)| path);
    if token.is_empty() || token.starts_with('"') || token.contains('"') || token.contains('\\') {
        return Err(DiffParseError::QuotedPathUnsupported { line });
    }
    if token == "/dev/null" {
        return Ok(None);
    }
    parse_prefixed_path(token, side, line).map(Some)
}

fn parse_prefixed_path(path: &str, side: char, line: usize) -> Result<String, DiffParseError> {
    let prefix = if side == 'a' { "a/" } else { "b/" };
    let relative = path
        .strip_prefix(prefix)
        .ok_or(DiffParseError::MalformedFileHeader { line })?;
    normalize_repo_path(relative, line)
}

fn normalize_repo_path(path: &str, line: usize) -> Result<String, DiffParseError> {
    if path.len() > MAX_REPO_PATH_BYTES {
        return Err(DiffParseError::PathTooLong {
            maximum: MAX_REPO_PATH_BYTES,
        });
    }
    if path.is_empty() {
        return Err(DiffParseError::InvalidPath {
            line,
            reason: "empty path",
        });
    }
    if path.starts_with('/') || path.starts_with('\\') || path.contains('\\') {
        return Err(DiffParseError::InvalidPath {
            line,
            reason: "absolute or Windows-separated path",
        });
    }
    if path.as_bytes().get(1) == Some(&b':') || path.contains(':') {
        return Err(DiffParseError::InvalidPath {
            line,
            reason: "drive-qualified or colon path",
        });
    }
    if path.bytes().any(|byte| byte == 0 || byte.is_ascii_control()) {
        return Err(DiffParseError::InvalidPath {
            line,
            reason: "control character",
        });
    }
    if path
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(DiffParseError::InvalidPath {
            line,
            reason: "empty, current-directory, or parent-directory component",
        });
    }
    if path.split('/').any(is_windows_device_component) {
        return Err(DiffParseError::InvalidPath {
            line,
            reason: "Windows device-name component",
        });
    }
    Ok(path.to_string())
}

fn is_windows_device_component(component: &str) -> bool {
    let trimmed = component.trim_end_matches(['.', ' ']);
    let stem = trimmed.split_once('.').map_or(trimmed, |(stem, _)| stem);
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (upper.len() == 4
            && (upper.starts_with("COM") || upper.starts_with("LPT"))
            && matches!(upper.as_bytes()[3], b'1'..=b'9'))
        || matches!(
            upper.as_str(),
            "COM¹" | "COM²" | "COM³" | "LPT¹" | "LPT²" | "LPT³"
        )
}

fn parse_hunk(line: &str, line_number: usize) -> Result<DiffHunk, DiffParseError> {
    let remainder = line
        .strip_prefix("@@ ")
        .and_then(|rest| {
            rest.strip_suffix(" @@")
                .or_else(|| rest.split_once(" @@").map(|(ranges, _)| ranges))
        })
        .ok_or(DiffParseError::MalformedHunk { line: line_number })?;
    let mut ranges = remainder.split_ascii_whitespace();
    let old = ranges.next().ok_or(DiffParseError::MalformedHunk { line: line_number })?;
    let new = ranges.next().ok_or(DiffParseError::MalformedHunk { line: line_number })?;
    if ranges.next().is_some() || !old.starts_with('-') || !new.starts_with('+') {
        return Err(DiffParseError::MalformedHunk { line: line_number });
    }
    Ok(DiffHunk {
        old: parse_range(&old[1..], line_number)?,
        new: parse_range(&new[1..], line_number)?,
    })
}

fn parse_range(value: &str, line: usize) -> Result<DiffRange, DiffParseError> {
    let (start, count) = match value.split_once(',') {
        Some((start, count)) => (start, count),
        None => (value, "1"),
    };
    if start.is_empty() || count.is_empty() || count.contains(',') {
        return Err(DiffParseError::MalformedHunk { line });
    }
    let start = start
        .parse::<u32>()
        .map_err(|_| DiffParseError::MalformedHunk { line })?;
    let count = count
        .parse::<u32>()
        .map_err(|_| DiffParseError::MalformedHunk { line })?;
    if start == 0 && count != 0 {
        return Err(DiffParseError::MalformedHunk { line });
    }
    if count != 0 && start.checked_add(count - 1).is_none() {
        return Err(DiffParseError::MalformedHunk { line });
    }
    if start > MAX_HUNK_START_LINE || count > MAX_HUNK_RANGE_LINES {
        return Err(DiffParseError::HunkRangeTooLarge {
            maximum: MAX_HUNK_RANGE_LINES,
        });
    }
    Ok(DiffRange { start, count })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_addition_and_omitted_hunk_counts() {
        let files = parse_unified_diff(
            "diff --git a/src/new.rs b/src/new.rs\nnew file mode 100644\n--- /dev/null\n+++ b/src/new.rs\n@@ -0,0 +1 @@\n+fn new_file() {}\n",
        )
        .unwrap();
        assert_eq!(files[0].change, DiffChange::Added);
        assert_eq!(files[0].new_path.as_deref(), Some("src/new.rs"));
        assert_eq!(files[0].hunks[0].new, DiffRange { start: 1, count: 1 });
    }

    #[test]
    fn parses_multiple_hunks_and_deduplicates_ranges_deterministically() {
        let input = concat!(
            "diff --git a/src/a.rs b/src/a.rs\n--- a/src/a.rs\n+++ b/src/a.rs\n",
            "@@ -10 +10 @@\n-a\n+b\n@@ -2 +2,2 @@\n-a\n+b\n+c\n",
            "@@ -10 +10 @@\n-a\n+b\n",
        );
        let files = parse_unified_diff(input).unwrap();
        assert_eq!(files[0].hunks.len(), 2);
        assert_eq!(files[0].hunks[0].old, DiffRange { start: 2, count: 1 });
        assert_eq!(files[0].hunks[1].new, DiffRange { start: 10, count: 1 });
    }

    #[test]
    fn parses_delete_rename_and_binary_records() {
        let input = concat!(
            "diff --git a/old.rs b/old.rs\ndeleted file mode 100644\n",
            "--- a/old.rs\n+++ /dev/null\n@@ -1 +0,0 @@\n-fn old() {}\n",
            "diff --git a/from.rs b/to.rs\nsimilarity index 100%\n",
            "rename from from.rs\nrename to to.rs\n",
            "diff --git a/assets/logo.png b/assets/logo.png\n",
            "Binary files a/assets/logo.png and b/assets/logo.png differ\n",
        );
        let files = parse_unified_diff(input).unwrap();
        assert_eq!(
            files.iter().map(|file| file.change).collect::<Vec<_>>(),
            vec![DiffChange::Binary, DiffChange::Renamed, DiffChange::Deleted]
        );
        assert!(files
            .iter()
            .any(|file| file.old_path.as_deref() == Some("old.rs") && file.new_path.is_none()));
    }

    #[test]
    fn parses_empty_add_delete_and_mode_only_records() {
        let input = concat!(
            "diff --git a/empty-add.txt b/empty-add.txt\nnew file mode 100644\n",
            "index 0000000..e69de29\ndiff --git a/empty-delete.txt b/empty-delete.txt\n",
            "deleted file mode 100644\nindex e69de29..0000000\n",
            "diff --git a/scripts/run.sh b/scripts/run.sh\nold mode 100644\n",
            "new mode 100755\n",
        );
        let files = parse_unified_diff(input).unwrap();
        assert!(files.iter().any(|file| {
            file.change == DiffChange::Added
                && file.new_path.as_deref() == Some("empty-add.txt")
                && file.hunks.is_empty()
        }));
        assert!(files.iter().any(|file| {
            file.change == DiffChange::Deleted
                && file.old_path.as_deref() == Some("empty-delete.txt")
                && file.hunks.is_empty()
        }));
        assert!(files.iter().any(|file| {
            file.change == DiffChange::Modified
                && file.new_path.as_deref() == Some("scripts/run.sh")
                && file.hunks.is_empty()
        }));
    }

    #[test]
    fn accepts_crlf_and_unicode_paths() {
        let input = concat!(
            "diff --git a/src/grüße.rs b/src/grüße.rs\r\n",
            "--- a/src/grüße.rs\r\n+++ b/src/grüße.rs\r\n",
            "@@ -1,0 +1,1 @@\r\n+fn hallo() {}\r\n",
        );
        let files = parse_unified_diff(input).unwrap();
        assert_eq!(files[0].new_path.as_deref(), Some("src/grüße.rs"));
    }

    #[test]
    fn retains_zero_length_ranges() {
        let files = parse_unified_diff(
            "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n@@ -0,0 +0,0 @@\n",
        )
        .unwrap();
        assert_eq!(files[0].hunks[0].old, DiffRange { start: 0, count: 0 });
        assert_eq!(files[0].hunks[0].new.last_line(), None);
    }

    #[test]
    fn rejects_traversal_absolute_and_quoted_paths() {
        for path in [
            "a/../secret b/../secret",
            "a//etc/passwd b//etc/passwd",
            "a/NUL b/NUL",
            "a/COM¹.txt b/COM¹.txt",
            "\"a/a b\" \"b/a b\"",
        ] {
            let input = format!("diff --git {path}\n");
            assert!(parse_unified_diff(&input).is_err(), "{path}");
        }
    }

    #[test]
    fn rejects_malformed_or_unassigned_hunks_without_empty_success() {
        assert_eq!(parse_unified_diff("").unwrap_err(), DiffParseError::EmptyDiff);
        assert!(matches!(
            parse_unified_diff("@@ -1 +1 @@\n"),
            Err(DiffParseError::HunkWithoutFile { .. })
        ));
        assert!(matches!(
            parse_unified_diff(
                "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n@@ -one +1 @@\n"
            ),
            Err(DiffParseError::MalformedHunk { .. })
        ));
        assert!(matches!(
            parse_unified_diff(
                "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n@@ -1 +1 @@\n"
            ),
            Err(DiffParseError::MalformedHunk { .. })
        ));
        assert!(matches!(
            parse_unified_diff(
                concat!(
                    "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n",
                    "@@ -1 +1 @@\n-a\n+b\n+unexpected\n",
                )
            ),
            Err(DiffParseError::MalformedHunk { .. })
        ));
    }

    #[test]
    fn result_order_is_lexical_and_repeatable() {
        let input = concat!(
            "diff --git a/z.rs b/z.rs\n--- a/z.rs\n+++ b/z.rs\n",
            "@@ -1 +1 @@\n-z\n+z\n",
            "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n",
            "@@ -1 +1 @@\n-a\n+a\n",
        );
        let first = parse_unified_diff(input).unwrap();
        let second = parse_unified_diff(input).unwrap();
        assert_eq!(first, second);
        assert_eq!(first[0].new_path.as_deref(), Some("a.rs"));
    }

    #[test]
    fn rejects_input_and_hunk_caps() {
        assert!(matches!(
            parse_unified_diff(&"x".repeat(MAX_DIFF_BYTES + 1)),
            Err(DiffParseError::InputTooLarge { .. })
        ));
        let mut input = String::from(
            "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n",
        );
        for _ in 0..=MAX_HUNKS_PER_FILE {
            input.push_str("@@ -1 +1 @@\n-a\n+b\n");
        }
        assert!(matches!(parse_unified_diff(&input), Err(DiffParseError::TooManyHunks { .. })));
        assert!(matches!(
            parse_unified_diff(
                "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n@@ -1,100001 +1,1 @@\n"
            ),
            Err(DiffParseError::HunkRangeTooLarge { .. })
        ));
        assert!(matches!(
            parse_unified_diff(
                "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n@@ -0,1 +1 @@\n"
            ),
            Err(DiffParseError::MalformedHunk { .. })
        ));
    }
}
