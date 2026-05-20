//! End-to-end smoke test for the R-9 multimodal ingest pipeline.
//!
//! Runs the actual `neothd` binary as a subprocess (the real CLI
//! surface operators hit) and verifies the JSON contract of
//! `neothd ingest --output json`. Doesn't depend on the CLIP / whisper
//! model caches — the test image is synthesized, embed_status is
//! checked for "model not cached" vs "ok", and the contract verifies
//! the metadata shape holds in both states.

use std::process::Command;

/// Synth a 16×16 red PNG so the test doesn't need a binary fixture
/// committed to the repo.
fn synth_red_png(path: &std::path::Path) {
    let mut img = image::RgbImage::new(16, 16);
    for pixel in img.pixels_mut() {
        *pixel = image::Rgb([255, 0, 0]);
    }
    img.save(path).expect("encode + write png");
}

fn neothd_bin() -> &'static str {
    env!("CARGO_BIN_EXE_neothd")
}

/// Run `neothd <args>` with logging silenced so the JSON payload is the
/// only thing on stdout. Tracing logs at warn+ still go to stderr and
/// are captured for assertion when a test expects errors.
fn run_neothd(args: &[&std::ffi::OsStr]) -> std::process::Output {
    Command::new(neothd_bin())
        .args(args)
        .env("NEOTH_LOG", "error")
        .output()
        .expect("spawn neothd")
}

#[test]
fn ingest_image_returns_well_formed_json() {
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("red.png");
    synth_red_png(&img);
    let db = dir.path().join("views.db");
    let wal = dir.path().join("000001.wal");

    let output = run_neothd(&[
        std::ffi::OsStr::new("--output"),
        std::ffi::OsStr::new("json"),
        std::ffi::OsStr::new("ingest"),
        img.as_os_str(),
        std::ffi::OsStr::new("--db"),
        db.as_os_str(),
        std::ffi::OsStr::new("--wal-segment"),
        wal.as_os_str(),
        std::ffi::OsStr::new("--no-persist"),
        std::ffi::OsStr::new("--no-audit"),
    ]);
    assert!(
        output.status.success(),
        "ingest failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let body: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("ingest stdout must be JSON");
    assert_eq!(body["kind"], "image");
    assert_eq!(body["embed_persisted"], false, "--no-persist must hold");
    assert_eq!(body["metadata"]["width"], 16);
    assert_eq!(body["metadata"]["height"], 16);
    let embed_status = body["metadata"]["embed_status"]
        .as_str()
        .expect("embed_status string");
    assert!(
        matches!(embed_status, "ok" | "model not cached" | "embed failed"),
        "unexpected embed_status: {embed_status}"
    );
}

#[test]
fn ingest_unknown_extension_exits_nonzero_with_message() {
    let dir = tempfile::tempdir().unwrap();
    let weird = dir.path().join("file.xyz");
    std::fs::write(&weird, b"garbage").unwrap();

    let output = run_neothd(&[
        std::ffi::OsStr::new("ingest"),
        weird.as_os_str(),
        std::ffi::OsStr::new("--no-persist"),
        std::ffi::OsStr::new("--no-audit"),
    ]);

    assert!(
        !output.status.success(),
        "unknown extension must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("infer asset kind") || stderr.contains("supported"),
        "stderr must surface the supported-list, got: {stderr}"
    );
}

#[test]
fn ingest_missing_path_exits_nonzero() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope.png");
    let output = run_neothd(&[
        std::ffi::OsStr::new("ingest"),
        missing.as_os_str(),
        std::ffi::OsStr::new("--no-persist"),
        std::ffi::OsStr::new("--no-audit"),
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not exist") || stderr.contains("not found"),
        "stderr must describe the missing-file cause, got: {stderr}"
    );
}

#[test]
fn models_list_includes_clip_and_whisper() {
    // Sanity check the `neoth models list` CLI surface — proves the
    // command is wired + the catalogue ships the two known models.
    let output = run_neothd(&[
        std::ffi::OsStr::new("--output"),
        std::ffi::OsStr::new("json"),
        std::ffi::OsStr::new("models"),
        std::ffi::OsStr::new("list"),
    ]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("clip"));
    assert!(stdout.contains("whisper"));
}

#[test]
fn cost_estimate_local_provider_reports_zero_eur() {
    // C-14: `neoth cost estimate` must return well-formed JSON and a
    // zero euro figure for local providers (no pricing table entry =
    // free tier). This is the operator-facing guarantee that the
    // pre-call cost transparency contract is wired end-to-end.
    let output = run_neothd(&[
        std::ffi::OsStr::new("--output"),
        std::ffi::OsStr::new("json"),
        std::ffi::OsStr::new("cost"),
        std::ffi::OsStr::new("--provider"),
        std::ffi::OsStr::new("local_qwen"),
        std::ffi::OsStr::new("--model"),
        std::ffi::OsStr::new("Qwen/Qwen2.5-3B-Instruct"),
        std::ffi::OsStr::new("hello world"),
    ]);
    assert!(
        output.status.success(),
        "cost estimate failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let body: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("cost estimate stdout must be JSON");
    assert_eq!(body["provider"], "local_qwen");
    assert!(body["input_tokens"].is_number());
    assert!(body["output_tokens_est"].is_number());
    // Local provider = free tier — total must be zero.
    assert_eq!(body["total_eur"].as_f64().unwrap_or(-1.0), 0.0);
}

#[test]
fn cost_estimate_cloud_provider_reports_nonzero_eur() {
    let output = run_neothd(&[
        std::ffi::OsStr::new("--output"),
        std::ffi::OsStr::new("json"),
        std::ffi::OsStr::new("cost"),
        std::ffi::OsStr::new("--provider"),
        std::ffi::OsStr::new("openai_api"),
        std::ffi::OsStr::new("--model"),
        std::ffi::OsStr::new("gpt-4o"),
        // Big-ish prompt so the token approximation produces a
        // measurable cost.
        std::ffi::OsStr::new(&"hello world ".repeat(50)),
    ]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let body: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON");
    let total = body["total_eur"].as_f64().expect("total_eur present");
    assert!(
        total > 0.0,
        "expected non-zero cost for gpt-4o, got {total}"
    );
}

#[test]
fn cost_estimate_empty_prompt_exits_nonzero() {
    let output = run_neothd(&[std::ffi::OsStr::new("cost"), std::ffi::OsStr::new("")]);
    assert!(!output.status.success());
}
