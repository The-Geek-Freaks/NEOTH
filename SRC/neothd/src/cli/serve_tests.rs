//! GOLD-ARCH-01: the `#[cfg(test)] mod tests` body of `cli/serve.rs`, split into
//! its own file (declared `#[path]` from serve.rs) to keep serve.rs under the
//! 1500-LOC acceptance gate. `super::*` resolves to `cli::serve` (the parent).

use super::*;
// GOLD-ARCH-01: these pipeline helpers moved to `serve_pipeline`.
use crate::cli::serve_pipeline::{channel_skill_allowlist, emit_channel_privilege_blocked};
use crate::wal::frame::decode_frame;
use std::io::Write;
use tempfile::tempdir;
use tokio::fs::read;

// Sets NEOTH_CONSENT_BYPASS (process-global) — hold the crate-wide
// env lock across the run_serve().await so it can't race another env
// test. The awaited serve path never re-locks it (bounded hold).
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn serve_one_shot_writes_boot_frame() {
    let _env = crate::test_env::lock();
    // Arrange: freedom.yaml + segment paths in temp dir
    let dir = tempdir().unwrap();
    let cfg_path = dir.path().join("freedom.yaml");
    let mut f = std::fs::File::create(&cfg_path).unwrap();
    f.write_all(b"operator_id: alice\nrole: developer\nprovider_kind: claude_cli\n")
        .unwrap();

    let seg_path = dir.path().join("000001.wal");

    let args = ServeArgs {
        config: Some(cfg_path),
        wal_segment: Some(seg_path.clone()),
        one_shot: true,
        allow_clock_rollback: false,
    };

    // V03-08 consent gate would block this test against the real
    // `~/.neoth/consent/claude_cli.granted` marker. Bypass via env var
    // — this test pins WAL writer + BOOT frame shape, not consent.
    // SAFETY: tests run single-threaded under `cargo test` only on the
    // serve module so no other test races this var; restored below.
    unsafe {
        std::env::set_var("NEOTH_CONSENT_BYPASS", "1");
    }
    let result = run_serve(args).await;
    unsafe {
        std::env::remove_var("NEOTH_CONSENT_BYPASS");
    }
    result.expect("serve one-shot");

    // Assert: file exists; has SegmentHeader at offset 0; boot frame after.
    let bytes = read(&seg_path).await.unwrap();
    use crate::wal::segment_header::{SEGMENT_HEADER_LEN, SegmentHeader};
    assert!(
        bytes.len() > SEGMENT_HEADER_LEN + 104,
        "WAL must hold SegmentHeader + at least one frame"
    );
    let sh =
        SegmentHeader::from_le_bytes(bytes[..SEGMENT_HEADER_LEN].try_into().expect("60 bytes"))
            .expect("SegmentHeader CRC must pass");
    assert_eq!(&sh.magic, b"NEOT-SEG");
    let dec = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).expect("decode boot frame");
    assert_eq!(dec.header.event_type, EVENT_TYPE_BOOT);
    let payload_str = std::str::from_utf8(dec.payload).unwrap();
    assert!(payload_str.contains("\"operator_id\":\"alice\""));
    assert!(payload_str.contains("\"daemon_version\""));
}

#[tokio::test]
async fn serve_fails_with_helpful_error_when_freedom_yaml_missing() {
    let dir = tempdir().unwrap();
    let cfg_path = dir.path().join("nope.yaml");
    let seg_path = dir.path().join("000001.wal");
    let args = ServeArgs {
        config: Some(cfg_path),
        wal_segment: Some(seg_path),
        one_shot: true,
        allow_clock_rollback: false,
    };
    let err = run_serve(args).await.unwrap_err();
    assert!(err.to_string().contains("neoth init"));
}

// ── SC-11 channel-path tool_allowlist threading (Session 28d) ─────────
fn skill_with_allowlist(id: &str, kws: &[&str], allow: &[&str]) -> crate::skills::schema::Skill {
    crate::skills::schema::Skill {
        manifest: crate::skills::schema::SkillManifest {
            id: id.to_string(),
            description: format!("test skill {id}"),
            version: "1.0.0".to_string(),
            trigger_keywords: kws.iter().map(|s| (*s).to_string()).collect(),
            system_prompt: format!("you are {id}"),
            tool_allowlist: allow.iter().map(|s| (*s).to_string()).collect(),
            author: None,
            tags: vec![],
            homepage: None,
            source: None,
            modes: vec![],
            enabled: true,
            delegate_to: None,
            model: None,
            paths: vec![],
            effort: None,
            loop_trigger: false,
            visibility: Default::default(),
        },
        path: std::path::PathBuf::from(format!("/tmp/{id}/skill.yaml")),
        content_hash: String::new(),
    }
}

#[test]
fn channel_skill_allowlist_none_when_no_skill_matched() {
    // No skill matched this inbound ⇒ gate allows every tool.
    assert_eq!(channel_skill_allowlist(None), None);
}

#[test]
fn channel_skill_allowlist_some_empty_for_default_manifest() {
    // A matched skill with the default (empty) allowlist ⇒ Some(empty),
    // which the gate also treats as "allow all" — distinct from None
    // but behaviourally equivalent at the gate.
    let s = skill_with_allowlist("news", &["news"], &[]);
    assert_eq!(channel_skill_allowlist(Some(&s)), Some(vec![]));
}

#[test]
fn channel_skill_allowlist_carries_restrictive_list() {
    // The SC-11 regression guard: a matched skill's NON-EMPTY allowlist
    // must survive to the dispatch loop, not be dropped to None like the
    // pre-fix channel path did.
    let s = skill_with_allowlist("ops", &["deploy"], &["fs.read", "shell.run"]);
    assert_eq!(
        channel_skill_allowlist(Some(&s)),
        Some(vec!["fs.read".to_string(), "shell.run".to_string()])
    );
}

#[test]
fn channel_route_then_allowlist_preserves_restriction_end_to_end() {
    // Compose the exact channel derivation: route() picks the skill,
    // channel_skill_allowlist() extracts its allowlist. A restrictive
    // allowlist must reach the gate — proving the channel path no longer
    // bypasses skill-scoped tool restriction.
    let skills = vec![skill_with_allowlist("ops", &["deploy"], &["fs.read"])];
    let m = crate::skills::route("please deploy the service", &skills)
        .expect("skill should match 'deploy'");
    let allow = channel_skill_allowlist(Some(m.skill));
    assert_eq!(allow, Some(vec!["fs.read".to_string()]));
}

// ── ADV-09: channel privilege-block audit frame (0x3C) ────────────

#[tokio::test]
async fn emit_channel_privilege_blocked_writes_0x3c_frame() {
    // The privilege ceiling itself (destructive action from a channel →
    // ChannelPrivilegeBlocked) is unit-tested in slash::action_dispatch;
    // this pins the AUDIT frame the serve.rs channel path emits when it
    // rejects such an action — exactly one 0x3C frame carrying the
    // channel + numeric sender + action wire-name, NO message text.
    let dir = tempdir().unwrap();
    let seg = dir.path().join("priv.wal");
    let (writer, _join) = crate::wal::writer::spawn(seg.clone()).unwrap();
    emit_channel_privilege_blocked(&writer, "telegram", "4242", "autonomy_level").await;

    let bytes = std::fs::read(&seg).unwrap();
    let hdr = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
    let mut cursor = hdr.header_len();
    let mut found = 0usize;
    while cursor < bytes.len() {
        let dec = match decode_frame(&bytes[cursor..]) {
            Ok(d) => d,
            Err(_) => break,
        };
        if dec.header.event_type == crate::wal::events::EVENT_TYPE_CHANNEL_PRIVILEGE_BLOCKED {
            let v: serde_json::Value = serde_json::from_slice(dec.payload).unwrap();
            assert_eq!(v["channel"], "telegram");
            assert_eq!(v["sender_id"], "4242");
            assert_eq!(v["action"], "autonomy_level");
            assert!(
                v.get("text").is_none(),
                "audit frame must carry no message text"
            );
            found += 1;
        }
        let total = dec.header.total_len as usize;
        if total == 0 {
            break;
        }
        cursor = cursor.saturating_add(total);
    }
    assert_eq!(
        found, 1,
        "expected exactly one 0x3C CHANNEL_PRIVILEGE_BLOCKED frame"
    );
}

#[tokio::test]
async fn emit_required_audit_survives_append_failure_without_aborting() {
    // GOLD-COR-04 / A-11: when a security audit frame CANNOT be written
    // (here: an oversize payload makes `append` reject synchronously, the
    // same failure class as a quota-full WAL), the helper must NOT panic
    // and must NOT propagate — the guarded action already happened, so the
    // operation continues; the loss is surfaced loud at error level
    // (audit_loss=true) instead. We assert the no-panic + no-frame outcome;
    // the error-level log is the documented side effect.
    let dir = tempdir().unwrap();
    let seg = dir.path().join("audit.wal");
    let (writer, _join) = crate::wal::writer::spawn(seg.clone()).unwrap();

    // First a VALID frame, so the segment + its header exist on disk and we
    // have a known-good baseline of exactly one HOOK_BLOCKED frame.
    emit_required_audit(
        &writer,
        crate::wal::events::EVENT_TYPE_HOOK_BLOCKED,
        "HOOK_BLOCKED",
        b"{\"ok\":1}".to_vec(),
    )
    .await;

    let oversize = vec![0u8; crate::wal::writer::MAX_PAYLOAD_BYTES + 1];
    // Returns normally (no panic, no Err to unwrap) despite the failed write.
    emit_required_audit(
        &writer,
        crate::wal::events::EVENT_TYPE_HOOK_BLOCKED,
        "HOOK_BLOCKED",
        oversize,
    )
    .await;

    // The rejected oversize frame must NOT have landed — only the valid one.
    let bytes = std::fs::read(&seg).unwrap();
    let hdr = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
    let mut cursor = hdr.header_len();
    let mut hook_frames = 0usize;
    while cursor < bytes.len() {
        let dec = match decode_frame(&bytes[cursor..]) {
            Ok(d) => d,
            Err(_) => break,
        };
        if dec.header.event_type == crate::wal::events::EVENT_TYPE_HOOK_BLOCKED {
            hook_frames += 1;
        }
        let total = dec.header.total_len as usize;
        if total == 0 {
            break;
        }
        cursor = cursor.saturating_add(total);
    }
    assert_eq!(
        hook_frames, 1,
        "exactly the one valid frame must land; the oversize one must be dropped"
    );
}
