//! GOLD-ADOPT-18 — subdirectory hint auto-injection (goose `hints/` port).
//!
//! As the LLM issues MCP tool calls with `path` / `command` arguments, the
//! [`SubdirHintTracker`] notices which directories the agent is working in and,
//! the FIRST time a directory under the working dir is entered, loads that
//! dir's `.neothhints` / `AGENTS.md` into the next prompt — so per-directory
//! conventions reach the model without bloating every turn.
//!
//! Ported from goose's `SubdirectoryHintTracker` (`crates/goose/src/hints/`),
//! NEOTH-simplified:
//!   - hint files are `.neothhints` + `AGENTS.md`,
//!   - gitignore-respecting via the `ignore` crate (already a dep) — a hint
//!     file matched by `.gitignore` is skipped,
//!   - each directory's hints load **exactly once** per session (the ancestor
//!     chain leaf→working-dir is walked, so a deep jump still picks up parent
//!     hints, but no dir is re-injected when a sibling is later entered),
//!   - each hint file is size-capped,
//!   - **scope guard:** goose's `@file` import-expansion (`import_files.rs`) is
//!     deliberately NOT ported — a hint file is read verbatim. Add it later if
//!     operators want transclusion.
//!
//! Pure + IO-light: the tracker takes path STRINGS + a base dir, so its core is
//! unit-testable without a live MCP server or a daemon.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use ignore::gitignore::{Gitignore, GitignoreBuilder};

/// Per-directory hint files, highest-priority first.
const HINT_FILENAMES: [&str; 2] = [".neothhints", "AGENTS.md"];

/// Cap on a single hint file's injected bytes (truncated on a char boundary).
const MAX_HINT_BYTES: usize = 16 * 1024;

/// Cap on queued candidate dirs between drains (review F: bound memory against a
/// tool-call sequence that floods distinct path tokens).
const MAX_PENDING_DIRS: usize = 256;
/// Cap on unique dirs tracked per session (bounds `loaded_dirs` growth).
const MAX_LOADED_DIRS: usize = 512;

/// Object keys whose string value is a FILE path (→ its parent dir is entered).
const FILE_KEYS: [&str; 5] = ["path", "file", "filename", "file_path", "filepath"];
/// Object keys whose string value is itself a DIRECTORY.
const DIR_KEYS: [&str; 5] = ["dir", "directory", "cwd", "cd", "folder"];

/// One directory's loaded hints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedHint {
    pub dir: PathBuf,
    /// Formatted block ready to append to the prompt.
    pub content: String,
}

/// Session-scoped tracker of which subdirectories the agent has entered (via
/// tool-call path args) and whose hints have already been loaded.
#[derive(Debug, Default)]
pub struct SubdirHintTracker {
    loaded_dirs: HashSet<PathBuf>,
    pending_dirs: Vec<PathBuf>,
    /// Canonical working dir — the containment base, built once on first load
    /// (the working dir is stable for a session).
    wd_canon: Option<PathBuf>,
    /// Session `.gitignore` (built from the canonical working dir), built once.
    gitignore: Option<Gitignore>,
}

impl SubdirHintTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a candidate dir, honouring the pending-dir cap.
    fn push_pending(&mut self, dir: PathBuf) {
        if self.pending_dirs.len() < MAX_PENDING_DIRS {
            self.pending_dirs.push(dir);
        }
    }

    /// Note the directories implied by one tool call's `arguments`. Pure +
    /// allocation-light: it only collects candidate dirs into `pending_dirs`;
    /// [`Self::load_new_hints`] does the IO. Non-object args / missing keys are
    /// a no-op (never panics on arbitrary JSON).
    pub fn record_tool_arguments(&mut self, arguments: &serde_json::Value, working_dir: &Path) {
        let Some(obj) = arguments.as_object() else {
            return;
        };
        for key in FILE_KEYS {
            if let Some(s) = obj.get(key).and_then(|v| v.as_str()) {
                if let Some(dir) = resolve_parent_dir(s, working_dir) {
                    self.push_pending(dir);
                }
            }
        }
        for key in DIR_KEYS {
            if let Some(s) = obj.get(key).and_then(|v| v.as_str()) {
                if let Some(dir) = resolve_dir(s, working_dir) {
                    self.push_pending(dir);
                }
            }
        }
        // A shell-ish `command` string: treat path-looking tokens as files.
        if let Some(cmd) = obj.get("command").and_then(|v| v.as_str()) {
            for tok in cmd.split_whitespace() {
                if tok.starts_with('-') {
                    continue;
                }
                if tok.contains('/') || tok.contains('\\') || tok.contains('.') {
                    if let Some(dir) = resolve_parent_dir(tok, working_dir) {
                        self.push_pending(dir);
                    }
                }
            }
        }
    }

    /// Load the hints for any newly-entered directory under `working_dir`.
    /// Drains `pending_dirs`; for each candidate, walks the ancestor chain
    /// leaf→`working_dir` (exclusive) and loads each dir's hints EXACTLY ONCE
    /// per session. Directories outside `working_dir` (or equal to it) are
    /// ignored. Returns the freshly-loaded blocks (empty when nothing new).
    pub fn load_new_hints(&mut self, working_dir: &Path) -> Vec<LoadedHint> {
        let pending = std::mem::take(&mut self.pending_dirs);
        if pending.is_empty() {
            return Vec::new();
        }
        // Build the containment base + session gitignore once (working_dir is
        // stable). The base is CANONICAL so the containment check below resolves
        // symlinks — closing the escape where a symlinked subdir lexically
        // passes `starts_with` but really points outside the project.
        if self.wd_canon.is_none() {
            self.wd_canon = Some(
                working_dir
                    .canonicalize()
                    .unwrap_or_else(|_| working_dir.to_path_buf()),
            );
        }
        if self.gitignore.is_none() {
            self.gitignore = Some(build_gitignore(
                self.wd_canon.as_deref().unwrap_or(working_dir),
            ));
        }
        let wd_canon = self
            .wd_canon
            .clone()
            .unwrap_or_else(|| working_dir.to_path_buf());
        let gitignore = self.gitignore.clone().unwrap_or_else(Gitignore::empty);

        let mut out = Vec::new();
        for leaf in pending {
            // Lexical ancestor chain leaf..working_dir (exclusive), root-first so
            // hints arrive outer→inner.
            let mut chain: Vec<PathBuf> = leaf
                .ancestors()
                .take_while(|d| d.starts_with(working_dir) && *d != working_dir)
                .map(|d| d.to_path_buf())
                .collect();
            chain.reverse();
            for dir in chain {
                if self.loaded_dirs.len() >= MAX_LOADED_DIRS {
                    break;
                }
                // `insert` returns false when already present → dedup + mark
                // attempted (so a dir with no hint file isn't re-stat'd).
                if !self.loaded_dirs.insert(dir.clone()) {
                    continue;
                }
                // HIGH (review): resolve symlinks + re-verify the REAL path is
                // strictly inside the project. canonicalize requires existence,
                // so a non-existent / unreadable dir is skipped (fail-closed).
                let Ok(dir_canon) = dir.canonicalize() else {
                    continue;
                };
                if !dir_canon.starts_with(&wd_canon) || dir_canon == wd_canon {
                    continue;
                }
                if let Some(content) = load_single_dir_hints(&dir_canon, &wd_canon, &gitignore) {
                    // Report the lexical dir (clean display); the read used the
                    // canonical one.
                    out.push(LoadedHint { dir, content });
                }
            }
        }
        out
    }
}

/// Lexically resolve `token` against `working_dir` (no FS touch), then return
/// its PARENT directory — the dir a file lives in.
fn resolve_parent_dir(token: &str, working_dir: &Path) -> Option<PathBuf> {
    let resolved = resolve_dir(token, working_dir)?;
    resolved.parent().map(|d| d.to_path_buf())
}

/// Lexically resolve `token` against `working_dir` (absolute → as-is; relative →
/// joined), normalising `.`/`..` so `starts_with(working_dir)` is accurate and
/// can't be fooled by a `wd/../escape` prefix match.
fn resolve_dir(token: &str, working_dir: &Path) -> Option<PathBuf> {
    let path = Path::new(token);
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        working_dir.join(path)
    };
    Some(normalize_lexical(&joined))
}

/// Collapse `.` and `..` components lexically (no symlink/FS resolution). A
/// leading `..` that would escape the root is dropped (clamped at root).
fn normalize_lexical(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    // Nothing to pop (at/above root) — keep the prefix/root
                    // anchored, drop the stray `..`.
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Read one CANONICAL directory's hint files (NOT its ancestors), gitignore-
/// respecting + size-capped. Each hint file is itself canonicalised + re-checked
/// to be inside `wd_canon` (closes a file-level symlink escape). `None` when the
/// dir isn't real or carries no non-empty, in-bounds hint.
fn load_single_dir_hints(
    dir_canon: &Path,
    wd_canon: &Path,
    gitignore: &Gitignore,
) -> Option<String> {
    if !dir_canon.is_dir() {
        return None;
    }
    let mut parts = Vec::new();
    for fname in HINT_FILENAMES {
        let path = dir_canon.join(fname);
        if !path.is_file() {
            continue;
        }
        // File-level containment: a symlinked hint file pointing outside the
        // project must not be read.
        let Ok(file_canon) = path.canonicalize() else {
            continue;
        };
        if !file_canon.starts_with(wd_canon) {
            continue;
        }
        // gitignore-respect: an operator who .gitignore'd a local hints file
        // doesn't want it pulled into the model's context. Both the gitignore
        // root and `file_canon` are canonical, so the relative match is sound.
        if gitignore.matched(&file_canon, false).is_ignore() {
            continue;
        }
        if let Ok(body) = std::fs::read_to_string(&file_canon) {
            let capped = cap_chars(&body, MAX_HINT_BYTES);
            if !capped.trim().is_empty() {
                parts.push(format!("--- {} ---\n{}", fname, capped));
            }
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(format!(
            "### Subdirectory hints ({})\n{}",
            dir_canon.display(),
            parts.join("\n")
        ))
    }
}

/// Truncate `s` to at most `max` bytes on a char boundary, appending a marker
/// when truncated.
fn cap_chars(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n…[hint truncated]", &s[..end])
}

/// Build a `Gitignore` for `working_dir` from the git root down (hierarchical),
/// mirroring git's semantics — used to skip a hint file the operator ignored.
fn build_gitignore(working_dir: &Path) -> Gitignore {
    let git_root = find_git_root(working_dir);
    let mut dirs: Vec<&Path> = Vec::new();
    let mut cur = working_dir;
    loop {
        dirs.push(cur);
        match git_root {
            Some(root) if cur == root => break,
            _ => match cur.parent() {
                Some(p) if git_root.is_some() => cur = p,
                _ => break,
            },
        }
    }
    let mut builder = GitignoreBuilder::new(working_dir);
    for dir in dirs {
        let gi = dir.join(".gitignore");
        if gi.is_file() {
            builder.add(&gi);
        }
    }
    builder.build().unwrap_or_else(|_| Gitignore::empty())
}

fn find_git_root(start: &Path) -> Option<&Path> {
    let mut cur = start;
    loop {
        if cur.join(".git").exists() {
            return Some(cur);
        }
        cur = cur.parent()?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn args(json: serde_json::Value) -> serde_json::Value {
        json
    }

    #[test]
    fn non_object_args_are_a_noop() {
        let mut t = SubdirHintTracker::new();
        t.record_tool_arguments(&serde_json::json!("a string"), Path::new("/wd"));
        t.record_tool_arguments(&serde_json::json!(42), Path::new("/wd"));
        // No panic, nothing pending.
        assert!(t.pending_dirs.is_empty());
    }

    #[test]
    fn path_arg_records_parent_dir() {
        let wd = Path::new("/project");
        let mut t = SubdirHintTracker::new();
        t.record_tool_arguments(&args(serde_json::json!({"path": "src/auth/login.rs"})), wd);
        assert_eq!(t.pending_dirs, vec![PathBuf::from("/project/src/auth")]);
    }

    #[test]
    fn dir_and_command_keys_recorded() {
        let wd = Path::new("/project");
        let mut t = SubdirHintTracker::new();
        t.record_tool_arguments(&args(serde_json::json!({"dir": "crates/core"})), wd);
        t.record_tool_arguments(
            &args(serde_json::json!({"command": "cargo test -p core src/lib.rs"})),
            wd,
        );
        assert!(
            t.pending_dirs
                .contains(&PathBuf::from("/project/crates/core"))
        );
        // `src/lib.rs` token → parent `src`; flags (`-p`) skipped.
        assert!(t.pending_dirs.contains(&PathBuf::from("/project/src")));
    }

    #[test]
    fn normalize_lexical_collapses_dotdot() {
        assert_eq!(
            normalize_lexical(Path::new("/a/b/../c")),
            PathBuf::from("/a/c")
        );
        assert_eq!(
            normalize_lexical(Path::new("/a/./b")),
            PathBuf::from("/a/b")
        );
    }

    #[test]
    fn loads_hint_once_and_dedups() {
        let dir = tempdir().unwrap();
        let wd = dir.path();
        let sub = wd.join("module");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join(".neothhints"), "Use the Foo pattern here.").unwrap();

        let mut t = SubdirHintTracker::new();
        // Enter the subdir twice.
        t.record_tool_arguments(&args(serde_json::json!({"path": "module/x.rs"})), wd);
        let first = t.load_new_hints(wd);
        assert_eq!(first.len(), 1, "first entry loads the hint");
        assert!(first[0].content.contains("Foo pattern"));
        assert!(first[0].content.contains("Subdirectory hints"));

        t.record_tool_arguments(&args(serde_json::json!({"path": "module/y.rs"})), wd);
        let second = t.load_new_hints(wd);
        assert!(second.is_empty(), "same dir does not re-load");
    }

    #[test]
    fn deep_jump_picks_up_ancestor_hints() {
        let dir = tempdir().unwrap();
        let wd = dir.path();
        let a = wd.join("a");
        let abc = a.join("b").join("c");
        fs::create_dir_all(&abc).unwrap();
        fs::write(a.join("AGENTS.md"), "A-level rule").unwrap();
        fs::write(abc.join(".neothhints"), "C-level rule").unwrap();

        let mut t = SubdirHintTracker::new();
        // Jump straight to a/b/c/file — must pick up both a and a/b/c hints.
        t.record_tool_arguments(&args(serde_json::json!({"path": "a/b/c/file.rs"})), wd);
        let loaded = t.load_new_hints(wd);
        let joined: String = loaded.iter().map(|h| h.content.clone()).collect();
        assert!(joined.contains("A-level rule"), "{joined}");
        assert!(joined.contains("C-level rule"), "{joined}");
    }

    #[test]
    fn dirs_outside_working_dir_are_ignored() {
        let dir = tempdir().unwrap();
        let wd = dir.path().join("project");
        fs::create_dir_all(&wd).unwrap();
        let mut t = SubdirHintTracker::new();
        // Absolute path escaping the working dir.
        t.record_tool_arguments(&args(serde_json::json!({"path": "/etc/passwd"})), &wd);
        assert!(t.load_new_hints(&wd).is_empty());
        // `..`-escape is normalised + clamped, never loads outside wd.
        t.record_tool_arguments(&args(serde_json::json!({"path": "../../../secret/x"})), &wd);
        assert!(t.load_new_hints(&wd).is_empty());
    }

    #[test]
    fn working_dir_itself_is_not_a_subdir_hint() {
        let dir = tempdir().unwrap();
        let wd = dir.path();
        fs::write(wd.join(".neothhints"), "root hint").unwrap();
        let mut t = SubdirHintTracker::new();
        // A file directly in wd → parent is wd → excluded (root hints are the
        // NEOTH.md/operator_md job, not the subdir tracker).
        t.record_tool_arguments(&args(serde_json::json!({"path": "main.rs"})), wd);
        assert!(t.load_new_hints(wd).is_empty());
    }

    #[test]
    fn gitignored_hint_file_is_skipped() {
        let dir = tempdir().unwrap();
        let wd = dir.path();
        // Make it a git root so build_gitignore loads the .gitignore.
        fs::create_dir_all(wd.join(".git")).unwrap();
        fs::write(wd.join(".gitignore"), "module/.neothhints\n").unwrap();
        let sub = wd.join("module");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join(".neothhints"), "ignored hint").unwrap();

        let mut t = SubdirHintTracker::new();
        t.record_tool_arguments(&args(serde_json::json!({"path": "module/x.rs"})), wd);
        let loaded = t.load_new_hints(wd);
        assert!(
            loaded.is_empty(),
            "a .gitignore'd hint file must be skipped"
        );
    }

    #[test]
    fn pending_dirs_are_capped() {
        let wd = Path::new("/project");
        let mut t = SubdirHintTracker::new();
        // Flood far past the cap with distinct path tokens.
        for i in 0..(MAX_PENDING_DIRS + 500) {
            t.record_tool_arguments(&serde_json::json!({ "path": format!("d{i}/f.rs") }), wd);
        }
        assert!(
            t.pending_dirs.len() <= MAX_PENDING_DIRS,
            "pending_dirs must be bounded, got {}",
            t.pending_dirs.len()
        );
    }

    #[test]
    fn hint_content_is_size_capped() {
        let big = "x".repeat(MAX_HINT_BYTES + 5000);
        let capped = cap_chars(&big, MAX_HINT_BYTES);
        assert!(capped.len() <= MAX_HINT_BYTES + 32);
        assert!(capped.contains("hint truncated"));
    }
}
