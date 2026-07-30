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

#[cfg(feature = "cluster")]
#[test]
fn membership_outbox_replay_is_wired_before_any_carrier_supervisor_start() {
    let source = include_str!("serve.rs");
    let replay = source
        .find("startup_membership.drain_outbox")
        .expect("daemon membership startup replay");
    let blocking_worker = source[..replay]
        .rfind("tokio::task::spawn_blocking")
        .expect("membership replay blocking worker");
    let carrier_start = source
        .find("spawn_runtime_supervisor")
        .expect("cluster carrier supervisor start");
    assert!(
        blocking_worker < replay && replay < carrier_start,
        "membership projection/audit replay must complete before any carrier can start"
    );
    let between = &source[replay..carrier_start];
    assert!(between.contains("replay membership outbox before carrier startup"));
}

#[tokio::test]
async fn serve_one_shot_writes_boot_frame_and_binds_custom_instance_home() {
    // Arrange: freedom.yaml + segment paths in temp dir
    let dir = tempdir().unwrap();
    let cfg_path = dir.path().join("freedom.yaml");
    let mut f = std::fs::File::create(&cfg_path).unwrap();
    f.write_all(b"operator_id: alice\nrole: developer\nprovider_kind: claude_cli\n")
        .unwrap();

    let seg_path = dir.path().join("wal").join("000001.wal");
    crate::consent::grant(dir.path(), crate::cli::init::ProviderKind::ClaudeCli)
        .expect("persist the exact durable consent fixture used by one-shot serve");

    let args = ServeArgs {
        config: Some(cfg_path),
        wal_segment: Some(seg_path.clone()),
        one_shot: true,
        allow_clock_rollback: false,
    };

    run_serve(args).await.expect("serve one-shot");

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
    assert!(
        dir.path().join("wal/hmac.key").is_file(),
        "custom config parent must own the WAL HMAC key"
    );
    assert!(
        dir.path().join("clock.floor").is_file(),
        "custom config parent must own the anti-rollback clock floor"
    );
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
    assert!(format!("{err:#}").contains("neoth init"));
}

#[tokio::test]
async fn serve_rejects_malformed_hook_set_before_wal_or_runtime_start() {
    let dir = tempdir().unwrap();
    let cfg_path = dir.path().join("freedom.yaml");
    std::fs::write(
        &cfg_path,
        b"operator_id: alice\nrole: developer\nprovider_kind: claude_cli\n",
    )
    .unwrap();
    let hooks = dir.path().join("hooks");
    std::fs::create_dir(&hooks).unwrap();
    std::fs::write(hooks.join("broken.toml"), b"not = [valid").unwrap();
    let seg_path = dir.path().join("malformed-hook.wal");

    let error = run_serve(ServeArgs {
        config: Some(cfg_path),
        wal_segment: Some(seg_path.clone()),
        one_shot: true,
        allow_clock_rollback: false,
    })
    .await
    .unwrap_err();

    assert!(error.to_string().contains("daemon startup refused"));
    assert!(
        !seg_path.exists(),
        "hook parsing must complete before the WAL or runtime services start"
    );
}

#[tokio::test]
async fn on_session_start_block_is_audited_and_vetoes_startup() {
    let dir = tempdir().unwrap();
    let cfg_path = dir.path().join("freedom.yaml");
    std::fs::write(
        &cfg_path,
        b"operator_id: alice\nrole: developer\nprovider_kind: claude_cli\n",
    )
    .unwrap();
    let hooks = dir.path().join("hooks");
    std::fs::create_dir(&hooks).unwrap();
    std::fs::write(
        hooks.join("stop.toml"),
        b"name = \"stop\"\nstage = \"on_session_start\"\n[action]\nkind = \"block\"\nreason = \"maintenance\"\n",
    )
    .unwrap();
    let seg_path = dir.path().join("wal").join("blocked-start-000001.wal");

    let error = run_serve(ServeArgs {
        config: Some(cfg_path),
        wal_segment: Some(seg_path.clone()),
        one_shot: true,
        allow_clock_rollback: false,
    })
    .await
    .unwrap_err();

    assert!(error.to_string().contains("blocked daemon startup"));
    let bytes = read(&seg_path).await.unwrap();
    let header = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
    let frame = decode_frame(&bytes[header.header_len()..]).unwrap();
    assert_eq!(
        frame.header.event_type,
        crate::wal::events::EVENT_TYPE_HOOK_BLOCKED
    );
    let payload: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
    assert_eq!(payload["name"], "stop");
    assert_eq!(payload["reason"], "maintenance");
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
    // which the gate treats as "no MCP tools" — distinct from None.
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

// ── NEOTH-AUDIT-CRON-FLEET-LIFECYCLE-01: cron_spec_fingerprint unit tests ──
//
// These tests are pure (no I/O, no async) because `cron_spec_fingerprint` is
// a deterministic function over FreedomConfig values. They verify the three
// correctness invariants:
//   1. Stability: same config → same fingerprint (no false positives on no-op reloads).
//   2. Sensitivity: a relevant field change → different fingerprint (no false negatives).
//   3. Isolation: a field irrelevant to a key does NOT shift its fingerprint.

#[test]
fn cron_fingerprint_is_deterministic() {
    let cfg = crate::config::FreedomConfig::default();
    assert_eq!(
        cron_spec_fingerprint(crate::cli::serve_tasks::CronKey::BgMonitor, &cfg),
        cron_spec_fingerprint(crate::cli::serve_tasks::CronKey::BgMonitor, &cfg),
        "fingerprint must be stable for identical configs",
    );
}

#[test]
fn cron_fingerprint_detects_interval_change() {
    let mut cfg = crate::config::FreedomConfig::default();
    cfg.bg_monitor.interval_secs = 60;
    let before = cron_spec_fingerprint(crate::cli::serve_tasks::CronKey::BgMonitor, &cfg);
    cfg.bg_monitor.interval_secs = 300;
    let after = cron_spec_fingerprint(crate::cli::serve_tasks::CronKey::BgMonitor, &cfg);
    assert_ne!(
        before, after,
        "changing interval_secs must shift the BgMonitor fingerprint",
    );
}

#[cfg(feature = "cluster")]
#[test]
fn cron_fingerprint_swarm_restarts_only_for_sampler_changes() {
    use std::collections::HashSet;

    use crate::cli::serve_tasks::{CronKey::ResourceSnapshot, plan_cron_fleet_reload};

    let mut cfg = crate::config::FreedomConfig::default();
    let before = cron_spec_fingerprint(ResourceSnapshot, &cfg);
    cfg.swarm.interval_secs = 45;
    let interval_changed = cron_spec_fingerprint(ResourceSnapshot, &cfg);
    assert_ne!(before, interval_changed);

    let running = HashSet::from([ResourceSnapshot]);
    let desired = HashSet::from([ResourceSnapshot]);
    let fingerprint_changed = HashSet::from([ResourceSnapshot]);
    let (to_stop, to_start) = plan_cron_fleet_reload(&running, &desired, &fingerprint_changed);
    assert_eq!(to_stop, vec![ResourceSnapshot]);
    assert_eq!(to_start, vec![ResourceSnapshot]);

    cfg.swarm.stale_after_secs = 900;
    let dashboard_only_changed = cron_spec_fingerprint(ResourceSnapshot, &cfg);
    assert_eq!(
        interval_changed, dashboard_only_changed,
        "dashboard-only stale threshold must not restart the sampler"
    );
}

#[test]
fn cron_fingerprint_ignores_unrelated_fields() {
    let mut cfg = crate::config::FreedomConfig::default();
    cfg.bg_monitor.interval_secs = 60;
    let before = cron_spec_fingerprint(crate::cli::serve_tasks::CronKey::BgMonitor, &cfg);
    // Changing a field relevant only to ObsidianSync must NOT affect BgMonitor.
    cfg.obsidian_vault = Some("~/vault".to_string());
    let after = cron_spec_fingerprint(crate::cli::serve_tasks::CronKey::BgMonitor, &cfg);
    assert_eq!(
        before, after,
        "obsidian_vault change must NOT shift BgMonitor fingerprint",
    );
}

#[test]
fn cron_fingerprint_obsidian_sync_detects_vault_change() {
    let mut cfg = crate::config::FreedomConfig::default();
    cfg.obsidian_vault = Some("~/vault1".to_string());
    let before = cron_spec_fingerprint(crate::cli::serve_tasks::CronKey::ObsidianSync, &cfg);
    cfg.obsidian_vault = Some("~/vault2".to_string());
    let after = cron_spec_fingerprint(crate::cli::serve_tasks::CronKey::ObsidianSync, &cfg);
    assert_ne!(
        before, after,
        "vault path change must shift ObsidianSync fingerprint",
    );
}

#[test]
fn cron_fingerprint_obsidian_sync_ignores_bg_monitor_field() {
    let mut cfg = crate::config::FreedomConfig::default();
    cfg.obsidian_vault = Some("~/vault".to_string());
    let before = cron_spec_fingerprint(crate::cli::serve_tasks::CronKey::ObsidianSync, &cfg);
    cfg.bg_monitor.interval_secs = 999;
    let after = cron_spec_fingerprint(crate::cli::serve_tasks::CronKey::ObsidianSync, &cfg);
    assert_eq!(
        before, after,
        "bg_monitor change must NOT shift ObsidianSync fingerprint",
    );
}

#[test]
fn cron_fingerprint_self_map_detects_source_dir_change() {
    let mut cfg = crate::config::FreedomConfig::default();
    cfg.self_map_source_dir = Some("/src/v1".to_string());
    let before = cron_spec_fingerprint(crate::cli::serve_tasks::CronKey::SelfMap, &cfg);
    cfg.self_map_source_dir = Some("/src/v2".to_string());
    let after = cron_spec_fingerprint(crate::cli::serve_tasks::CronKey::SelfMap, &cfg);
    assert_ne!(
        before, after,
        "source_dir change must shift SelfMap fingerprint",
    );
}

#[test]
fn cron_fingerprint_self_map_detects_interval_change() {
    let mut cfg = crate::config::FreedomConfig::default();
    cfg.self_map_interval_secs = Some(3600);
    let before = cron_spec_fingerprint(crate::cli::serve_tasks::CronKey::SelfMap, &cfg);
    cfg.self_map_interval_secs = Some(7200);
    let after = cron_spec_fingerprint(crate::cli::serve_tasks::CronKey::SelfMap, &cfg);
    assert_ne!(
        before, after,
        "interval_secs change must shift SelfMap fingerprint",
    );
}

#[test]
fn cron_fingerprint_obsidian_vault_reader_detects_enabled_toggle() {
    let mut cfg = crate::config::FreedomConfig::default();
    cfg.obsidian_vault = Some("~/v".to_string());
    cfg.obsidian_vault_reader_enabled = false;
    let before = cron_spec_fingerprint(crate::cli::serve_tasks::CronKey::ObsidianVaultReader, &cfg);
    cfg.obsidian_vault_reader_enabled = true;
    let after = cron_spec_fingerprint(crate::cli::serve_tasks::CronKey::ObsidianVaultReader, &cfg);
    assert_ne!(
        before, after,
        "reader_enabled toggle must shift ObsidianVaultReader fingerprint",
    );
}

// ── NEOTH-AUDIT-CHANNEL-CREDENTIAL-ATOMICITY-01: credential load tests ──

#[test]
fn credentials_startup_load_fallback_is_explicit_not_silent() {
    // Verify that `Credentials::load_or_default` on a missing file returns
    // Ok(default) — confirming the startup warn path only fires on real errors,
    // not on a fresh install that has no credentials.yaml yet.
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does_not_exist.yaml");
    let result = crate::config::credentials::Credentials::load_or_default(&missing);
    assert!(
        result.is_ok(),
        "missing credentials.yaml must return Ok(default), not Err",
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
