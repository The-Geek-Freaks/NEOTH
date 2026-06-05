//! P1 — no cloud STT/TTS/Vision call may bypass the audited wrappers.
//!
//! The audited dispatchers (`media::stt_provider::transcribe_and_audit`,
//! `media::tts_cloud::synth_and_audit`, `media::video_dispatch::dispatch_video_analysis`)
//! are the ONLY paths that emit the `0xCC`/`0xCD`/`0xC9` audit frames and honour
//! `media.required_audit_for_cloud_media`. A new feature that calls a provider's
//! `transcribe()` / `synth()` / `synthesize()` DIRECTLY would ship audio/text/
//! frames to the cloud with no audit trail — exactly the gap the P0 wrappers
//! close.
//!
//! This source-scan guard fails the build if any `.transcribe(` / `.synth(` /
//! `.synthesize(` CALL appears outside `src/media/` (where the wrappers, the
//! provider impls, and their tests legitimately live). Adding a new caller
//! elsewhere is then a deliberate, reviewed act: route it through the audited
//! wrapper, or extend the allowlist in this file with justification.

use std::fs;
use std::path::{Path, PathBuf};

/// Directories/files where calling a cloud-media provider method directly is
/// legitimate: the audited wrappers + the provider adapters + their tests all
/// live under `src/media/`.
const ALLOWED_PREFIXES: &[&str] = &["src/media/"];

/// Method-call patterns (NOTE the leading dot — `fn transcribe(` definitions and
/// `synthesized_payload(` are deliberately NOT matched, only `.method(` calls).
const FORBIDDEN_PATTERNS: &[&str] = &[".transcribe(", ".synth(", ".synthesize("];

#[test]
fn no_cloud_media_call_bypasses_the_audited_wrappers() {
    let src_root = manifest_dir().join("src");
    let mut violations = Vec::new();
    walk_rs(&src_root, &mut |path, content| {
        let rel = relative_to_crate(&path);
        if ALLOWED_PREFIXES.iter().any(|p| rel.starts_with(p)) {
            return;
        }
        for pattern in FORBIDDEN_PATTERNS {
            for (line_no, line) in content.lines().enumerate() {
                if !line.contains(pattern) {
                    continue;
                }
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("//!")
                {
                    continue;
                }
                violations.push(format!(
                    "{}:{}: `{}` calls a cloud-media provider directly — route it through the \
                     audited wrapper (transcribe_and_audit / synth_and_audit / \
                     dispatch_video_analysis) or allowlist this path with justification",
                    rel,
                    line_no + 1,
                    pattern.trim_start_matches('.').trim_end_matches('('),
                ));
            }
        }
    });

    assert!(
        violations.is_empty(),
        "cloud-media audit-bypass invariant violated:\n  {}",
        violations.join("\n  "),
    );
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn relative_to_crate(path: &Path) -> String {
    let root = manifest_dir();
    let rel = path.strip_prefix(&root).unwrap_or(path);
    rel.to_string_lossy().replace('\\', "/")
}

fn walk_rs(dir: &Path, f: &mut dyn FnMut(PathBuf, String)) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_rs(&path, f);
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        f(path, content);
    }
}
