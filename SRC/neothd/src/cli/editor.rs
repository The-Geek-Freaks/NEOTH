//! GOLD-ADOPT-24 — compose a chat prompt in an external `$EDITOR`.
//!
//! Ported from goose `crates/goose-cli/src/session/editor.rs` (the
//! resolve-editor + temp-file + extract-user-input logic), adapted to NEOTH:
//! since `neoth chat` is one-shot (no REPL), this is the `neoth chat --edit`
//! FLAG (open an editor to compose the prompt before sending), not a mid-session
//! slash command. Goose's CWD symlink is DROPPED — it needs elevated privileges
//! on Windows (NEOTH's primary build target) and only bought a prettier temp
//! filename; we open the `NamedTempFile` path directly.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use tempfile::{Builder, NamedTempFile};

const PROMPT_MARKER: &str = "# Your prompt:";

/// Resolve the editor command: `$VISUAL`, then `$EDITOR`. `None` when neither
/// is set (or both empty).
pub fn resolve_editor_command() -> Option<String> {
    resolve_editor_from_sources(
        std::env::var("VISUAL").ok().as_deref(),
        std::env::var("EDITOR").ok().as_deref(),
    )
}

/// Inner resolution (testable): first non-empty of VISUAL, EDITOR.
fn resolve_editor_from_sources(visual: Option<&str>, editor: Option<&str>) -> Option<String> {
    [visual, editor]
        .into_iter()
        .flatten()
        .find(|c| !c.trim().is_empty())
        .map(str::to_string)
}

/// The markdown scaffold the operator edits. The prompt goes under
/// [`PROMPT_MARKER`]; everything from the marker to EOF (or the context heading)
/// is the prompt.
fn build_template(prefill: Option<&str>) -> String {
    let mut s = String::from("# NEOTH Prompt Editor\n# (write your prompt below the marker, save + quit)\n\n");
    s.push_str(PROMPT_MARKER);
    s.push_str("\n\n");
    if let Some(p) = prefill {
        if !p.trim().is_empty() {
            s.push_str(p);
            s.push('\n');
        }
    }
    s
}

fn create_temp_file(prefill: Option<&str>) -> Result<NamedTempFile> {
    let f = Builder::new()
        .prefix("neoth_prompt_")
        .suffix(".md")
        .tempfile()
        .context("create editor temp file")?;
    std::fs::write(f.path(), build_template(prefill)).context("write editor template")?;
    Ok(f)
}

/// Spawn the editor on `file_path` with inherited stdio + wait. Errors on a
/// non-zero editor exit.
fn launch_editor(editor_cmd: &str, file_path: &Path) -> Result<()> {
    let parts: Vec<&str> = editor_cmd.split_whitespace().collect();
    let Some((bin, pre_args)) = parts.split_first() else {
        anyhow::bail!("empty editor command");
    };
    let status = Command::new(bin)
        .args(pre_args)
        .arg(file_path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("launch editor `{bin}`"))?;
    if !status.success() {
        anyhow::bail!("editor exited non-zero ({})", status.code().unwrap_or(-1));
    }
    Ok(())
}

/// Open `$EDITOR` on a scaffold, read it back, and return `(prompt,
/// has_meaningful_content)`. `prefill` seeds the prompt section (e.g. the
/// operator's partial `neoth chat "..."` message).
pub fn get_editor_input(editor_cmd: &str, prefill: Option<&str>) -> Result<(String, bool)> {
    let temp = create_temp_file(prefill)?;
    launch_editor(editor_cmd, temp.path())?;
    let mut content = String::new();
    std::fs::File::open(temp.path())
        .context("reopen editor temp file")?
        .read_to_string(&mut content)
        .context("read edited prompt")?;
    let user_input = extract_user_input(&content);
    let meaningful = !user_input.trim().is_empty();
    Ok((user_input, meaningful))
}

/// Pull the operator's prompt out of the saved scaffold: everything after the
/// [`PROMPT_MARKER`] up to the optional context heading, trimmed. With no
/// marker (operator rewrote the whole file), the whole content is the prompt.
fn extract_user_input(content: &str) -> String {
    let Some(start) = content.find(PROMPT_MARKER) else {
        return content.trim().to_string();
    };
    let after = &content[start + PROMPT_MARKER.len()..];
    let section = match after.find("# Recent conversation for context") {
        Some(pos) => &after[..pos],
        None => after,
    };
    section.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_prefers_visual_then_editor_skipping_empty() {
        assert_eq!(resolve_editor_from_sources(Some("vim"), Some("nano")).as_deref(), Some("vim"));
        assert_eq!(resolve_editor_from_sources(Some(""), Some("nano")).as_deref(), Some("nano"));
        assert_eq!(resolve_editor_from_sources(Some("  "), Some("code -w")).as_deref(), Some("code -w"));
        assert_eq!(resolve_editor_from_sources(None, None), None);
        assert_eq!(resolve_editor_from_sources(Some(""), Some("")), None);
    }

    #[test]
    fn template_carries_marker_and_prefill() {
        let t = build_template(Some("scan the host"));
        assert!(t.contains(PROMPT_MARKER));
        assert!(t.contains("scan the host"));
        let empty = build_template(None);
        assert!(empty.contains(PROMPT_MARKER));
        assert!(!empty.contains("Recent conversation"));
    }

    #[test]
    fn extract_pulls_prompt_after_marker() {
        let content = "# NEOTH Prompt Editor\n\n# Your prompt:\n\nWrite a haiku about Rust\n";
        assert_eq!(extract_user_input(content), "Write a haiku about Rust");
    }

    #[test]
    fn extract_stops_at_context_heading() {
        let content = "# Your prompt:\n\nthe real ask\n\n# Recent conversation for context (newest first):\n\nold stuff\n";
        assert_eq!(extract_user_input(content), "the real ask");
    }

    #[test]
    fn extract_no_marker_returns_whole_trimmed() {
        assert_eq!(extract_user_input("  just freeform text  "), "just freeform text");
    }

    #[test]
    fn extract_empty_prompt_section_is_empty() {
        let content = "# NEOTH Prompt Editor\n\n# Your prompt:\n\n   \n";
        assert_eq!(extract_user_input(content), "");
    }
}
