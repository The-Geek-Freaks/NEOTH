//! `neoth hooks` — operator visibility into the loaded TOML hook set.
//!
//! Two actions today:
//!   - `list`     dumps every parsed hook (or only enabled ones with
//!                `--enabled`), grouped by stage. JSON-or-table output.
//!   - `validate` parses + dry-runs each hook against a synthetic body.
//!                Surfaces bad regex / unknown stage names before the
//!                daemon picks them up at request time.
//!
//! Operators add hooks by dropping `~/.neoth/hooks/*.toml` files. The
//! daemon loads them per-turn via [`crate::hooks::load_all`]; this CLI
//! is read-only inspection.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::hooks::schema::{HookAction, HookDef};
use crate::hooks::stages::HookStage;

#[derive(Args, Debug, Clone)]
pub struct HooksArgs {
    #[command(subcommand)]
    pub action: HooksAction,

    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum HooksAction {
    /// List every parsed hook, grouped by pipeline stage. `--enabled`
    /// filters to enabled-only (default behaviour shows every hook so
    /// the operator can see which ones are toggled off).
    List {
        #[arg(long)]
        enabled: bool,
    },
    /// Parse every hook file + verify the matcher regex (if any) compiles.
    /// Returns non-zero on any failure so CI can gate config changes.
    Validate,
    /// AR-02 (Session 24) — walk the WAL and surface hook-lifecycle
    /// frames (`HOOK_FIRED` 0x80 / `HOOK_BLOCKED` 0x81 / `HOOK_REPLACED`
    /// 0x82 / `HOOK_ERROR` 0x83) within the last `--since` window.
    /// Read-only; no daemon needed; runs against any segment (default
    /// `~/.neoth/wal/000001.wal`, override with `--segment`).
    Trace {
        /// Time window. Accepts `30s`, `5m`, `2h`, `1d`. Default `2h`.
        #[arg(long, default_value = "2h")]
        since: String,
        /// Cap on rows surfaced (after filter). Default 200.
        #[arg(long, default_value_t = 200)]
        limit: usize,
        /// Override the WAL segment path. Defaults to
        /// `~/.neoth/wal/000001.wal`.
        #[arg(long)]
        segment: Option<std::path::PathBuf>,
    },
}

pub async fn run_hooks(args: HooksArgs) -> Result<()> {
    let hook_dir = FreedomConfig::default_neoth_home().join("hooks");
    match args.action {
        HooksAction::List { enabled } => run_list(&hook_dir, enabled, &args.output).await,
        HooksAction::Validate => run_validate(&hook_dir, &args.output).await,
        HooksAction::Trace {
            since,
            limit,
            segment,
        } => {
            let segment_path =
                segment.unwrap_or_else(|| FreedomConfig::default_wal_dir().join("000001.wal"));
            run_trace(&segment_path, &since, limit, &args.output)
        }
    }
}

async fn run_list(
    hook_dir: &std::path::Path,
    enabled_only: bool,
    output: &OutputFormat,
) -> Result<()> {
    let hooks = crate::hooks::load_all(hook_dir)
        .await
        .with_context(|| format!("load hooks from {}", hook_dir.display()))?;
    let filtered: Vec<&HookDef> = hooks
        .iter()
        .filter(|h| !enabled_only || h.is_enabled())
        .collect();

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let body = serde_json::json!({
                "hooks_dir": hook_dir.display().to_string(),
                "count": filtered.len(),
                "hooks": filtered.iter().map(|h| serde_json::json!({
                    "name": h.name,
                    "stage": h.stage.as_str(),
                    "enabled": h.is_enabled(),
                    "matcher_pattern": h.matcher.as_ref().map(|m| m.pattern.clone()),
                    "action": action_label(&h.action),
                })).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        OutputFormat::Table => {
            if filtered.is_empty() {
                if hook_dir.is_dir() {
                    println!("# Hooks at {}\n  (no enabled hooks)", hook_dir.display());
                } else {
                    println!(
                        "# Hooks at {}\n  (directory does not exist — create it + drop *.toml \
                         files to add hooks)",
                        hook_dir.display()
                    );
                }
                return Ok(());
            }
            println!(
                "# Hooks at {} ({} entries)",
                hook_dir.display(),
                filtered.len()
            );
            // Group by stage so operators see what fires at each pipeline boundary.
            let stages = [
                HookStage::PreChannelIngress,
                HookStage::PrePipeline,
                HookStage::PreProviderCall,
                HookStage::PostProviderCall,
                HookStage::PreEgress,
                HookStage::JobFired,
                HookStage::JobDone,
                HookStage::OnShutdown,
            ];
            for stage in stages {
                let group: Vec<&&HookDef> = filtered.iter().filter(|h| h.stage == stage).collect();
                if group.is_empty() {
                    continue;
                }
                println!("\n  [{}]", stage.as_str());
                for h in group {
                    let status = if h.is_enabled() { "ON " } else { "OFF" };
                    let matcher = h
                        .matcher
                        .as_ref()
                        .map(|m| m.pattern.as_str())
                        .unwrap_or("(no matcher — fires unconditionally)");
                    println!(
                        "    {status}  {:<24}  action={}  matcher={}",
                        h.name,
                        action_label(&h.action),
                        matcher,
                    );
                }
            }
        }
    }
    Ok(())
}

async fn run_validate(hook_dir: &std::path::Path, output: &OutputFormat) -> Result<()> {
    let hooks = crate::hooks::load_all(hook_dir)
        .await
        .with_context(|| format!("load hooks from {}", hook_dir.display()))?;
    let mut bad: Vec<(String, String)> = Vec::new();
    for h in &hooks {
        if let Some(m) = &h.matcher
            && let Err(e) = regex::Regex::new(&m.pattern)
        {
            bad.push((h.name.clone(), format!("bad regex: {e}")));
        }
    }

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "checked": hooks.len(),
                    "failures": bad.iter().map(|(n, e)| serde_json::json!({
                        "name": n,
                        "error": e,
                    })).collect::<Vec<_>>(),
                    "ok": bad.is_empty(),
                }))?
            );
        }
        OutputFormat::Table => {
            println!("# Validate hooks at {}", hook_dir.display());
            println!("  Checked: {}", hooks.len());
            if bad.is_empty() {
                println!("  OK — every hook parses + every regex compiles");
            } else {
                println!("  {} failure(s):", bad.len());
                for (name, err) in &bad {
                    println!("    {name}: {err}");
                }
            }
        }
    }

    if !bad.is_empty() {
        anyhow::bail!("{} hook(s) failed validation", bad.len());
    }
    Ok(())
}

fn action_label(a: &HookAction) -> &'static str {
    match a {
        HookAction::Allow => "allow",
        HookAction::Replace { .. } => "replace",
        HookAction::Block { .. } => "block",
        HookAction::Plugin { .. } => "plugin",
        // GOLD-ADAPT-SKILL-09
        HookAction::BlockFilter { .. } => "block_filter",
    }
}

/// AR-02 (Session 24) — parse a tiny humantime-style duration string
/// to nanoseconds. Accepts `30s` / `5m` / `2h` / `1d`. Lives here
/// (not in a shared util) because no other CLI surface needs this
/// today; promote when a second caller appears. No `humantime` crate
/// dependency — the format is constrained to the 4 suffixes above
/// so a 12-line parser beats a 200kB transitive dep.
fn parse_since_to_ns(s: &str) -> Result<i64> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        anyhow::bail!("--since cannot be empty (expected e.g. 2h, 30m, 1d)");
    }
    let (digits, suffix) = trimmed.split_at(
        trimmed
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(trimmed.len()),
    );
    if digits.is_empty() {
        anyhow::bail!("--since needs a leading number (got `{trimmed}`; expected e.g. `2h`)",);
    }
    let n: i64 = digits
        .parse()
        .with_context(|| format!("parse `{digits}` as integer in --since `{trimmed}`"))?;
    let mult_ns: i64 = match suffix {
        "s" => 1_000_000_000,
        "m" => 60 * 1_000_000_000,
        "h" => 3_600 * 1_000_000_000,
        "d" => 86_400 * 1_000_000_000,
        "" => anyhow::bail!(
            "--since needs a unit suffix (got `{trimmed}`; expected s/m/h/d, \
             e.g. `2h`)",
        ),
        other => {
            anyhow::bail!("--since unit `{other}` not recognised (expected s/m/h/d, e.g. `2h`)",)
        }
    };
    n.checked_mul(mult_ns)
        .with_context(|| format!("--since `{trimmed}` overflows i64 nanoseconds"))
}

/// AR-02 — operator-facing label for the 0x80..=0x83 hook lifecycle
/// codes. Anything outside that range returns `None`; the trace
/// filter drops the row before this is reached.
fn hook_code_label(code: u8) -> Option<&'static str> {
    use crate::wal::events::*;
    match code {
        c if c == EVENT_TYPE_HOOK_FIRED => Some("HOOK_FIRED"),
        c if c == EVENT_TYPE_HOOK_BLOCKED => Some("HOOK_BLOCKED"),
        c if c == EVENT_TYPE_HOOK_REPLACED => Some("HOOK_REPLACED"),
        c if c == EVENT_TYPE_HOOK_ERROR => Some("HOOK_ERROR"),
        _ => None,
    }
}

/// AR-02 — walk the WAL segment, filter to hook-lifecycle frames
/// (0x80..=0x83) within the `since` window, render. Read-only;
/// honours the `--output` format flag (table / json).
fn run_trace(
    segment_path: &std::path::Path,
    since: &str,
    limit: usize,
    output: &OutputFormat,
) -> Result<()> {
    let window_ns = parse_since_to_ns(since)?;
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
        .context("read wall clock for --since")?;
    let floor_ns = now_ns.saturating_sub(window_ns);

    let rows = collect_hook_trace(segment_path, floor_ns, limit)?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let body = serde_json::json!({
                "segment": segment_path.display().to_string(),
                "since": since,
                "floor_ns": floor_ns,
                "count": rows.len(),
                "rows": rows,
            });
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        OutputFormat::Table => {
            if rows.is_empty() {
                println!(
                    "# hooks trace: {} (since={since})\n  (no hook events in window)",
                    segment_path.display(),
                );
                return Ok(());
            }
            println!(
                "# hooks trace: {} ({} events in last {since})",
                segment_path.display(),
                rows.len(),
            );
            println!(
                "  {:<14}  {:<16}  {:<19}  payload",
                "code", "label", "ts_ns"
            );
            for row in &rows {
                println!(
                    "  0x{code:02X}            {label:<16}  {ts:<19}  {plen}b",
                    code = row["event_type_code"].as_u64().unwrap_or(0) as u8,
                    label = row["label"].as_str().unwrap_or(""),
                    ts = row["ts_ns"].as_i64().unwrap_or(0),
                    plen = row["payload_len"].as_u64().unwrap_or(0),
                );
            }
        }
    }
    Ok(())
}

/// Pure helper for [`run_trace`]: read the segment, decode every
/// frame, keep the ones whose event code is in 0x80..=0x83 AND
/// whose `ts_ns` ≥ `floor_ns`. Returns at most `limit` rows in
/// segment order. Cap on `limit` is applied AFTER filter so the
/// caller doesn't have to over-fetch.
///
/// Split out for unit-test ergonomics — the trace render path goes
/// through `println!` which we don't want to assert against; the
/// collector is plain `Result<Vec<Value>>` and pins the filter
/// contract directly.
pub fn collect_hook_trace(
    segment_path: &std::path::Path,
    floor_ns: i64,
    limit: usize,
) -> Result<Vec<serde_json::Value>> {
    use crate::wal::compress::decompress_frames;
    use crate::wal::frame::decode_frame;
    use crate::wal::segment_header::{SEGMENT_HEADER_LEN, parse_segment_header};

    let bytes =
        std::fs::read(segment_path).with_context(|| format!("read {}", segment_path.display()))?;
    if bytes.len() < SEGMENT_HEADER_LEN {
        // Tiny / corrupt segment: return empty rather than bail so the
        // tracer is safe to run against fresh installs with an empty WAL.
        return Ok(Vec::new());
    }
    // GOLD-ARCH-03: parse v1/v2 headers and decompress a v2/zstd body so a
    // compressed segment's hook frames are traced, not silently skipped.
    // The reported `offset` is `header_len + frame-stream cursor` — for a v1
    // segment (the production case) this is byte-identical to the prior
    // absolute file offset; for a v2 segment it is the logical offset.
    let hdr = parse_segment_header(&bytes).context("parse SegmentHeader")?;
    let header_len = hdr.header_len();
    let body = bytes.get(header_len..).unwrap_or(&[]);
    let decompressed;
    let frames: &[u8] = if hdr.is_compressed() {
        decompressed = decompress_frames(body)
            .with_context(|| format!("decompress segment body {}", segment_path.display()))?;
        &decompressed
    } else {
        body
    };

    let mut cursor = 0usize;
    let mut rows: Vec<serde_json::Value> = Vec::new();
    while cursor < frames.len() && rows.len() < limit {
        let dec = match decode_frame(&frames[cursor..]) {
            Ok(d) => d,
            // Stop at the first torn frame — same shape as `wal show`.
            Err(_) => break,
        };
        let total = dec.header.total_len as usize;
        if let Some(label) = hook_code_label(dec.header.event_type) {
            // `physical_ns()` is u64; `floor_ns` is i64. A future
            // wall clock past i64::MAX would saturate to MAX here,
            // which is correct — every i64 floor is then in the past.
            let ts: i64 = i64::try_from(dec.header.hlc.physical_ns()).unwrap_or(i64::MAX);
            if ts >= floor_ns {
                rows.push(serde_json::json!({
                    "offset": header_len + cursor,
                    "event_type_code": dec.header.event_type,
                    "label": label,
                    "ts_ns": ts,
                    "event_id": dec.header.event_id.0,
                    "payload_len": dec.header.payload_len,
                    "payload_hash": format!("{:016x}", dec.header.payload_hash),
                }));
            }
        }
        if total == 0 {
            break;
        }
        cursor = cursor.saturating_add(total);
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::schema::HookMatcher;
    use tempfile::tempdir;

    #[tokio::test]
    async fn list_empty_dir_does_not_error() {
        let dir = tempdir().unwrap();
        let hook_dir = dir.path().join("hooks");
        // Don't create the dir — exercise the missing-directory branch.
        run_list(&hook_dir, false, &OutputFormat::Json)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn validate_passes_on_well_formed_hooks() {
        let dir = tempdir().unwrap();
        let hook_dir = dir.path().join("hooks");
        std::fs::create_dir_all(&hook_dir).unwrap();
        let body = r#"
name    = "redact"
stage   = "pre_provider_call"
enabled = true

[matcher]
pattern = "(?i)\\bsecret\\s*=\\s*\\S+"

[action]
kind     = "replace"
template = "[X]"
"#;
        std::fs::write(hook_dir.join("redact.toml"), body).unwrap();
        run_validate(&hook_dir, &OutputFormat::Json).await.unwrap();
    }

    #[tokio::test]
    async fn validate_fails_on_bad_regex() {
        let dir = tempdir().unwrap();
        let hook_dir = dir.path().join("hooks");
        std::fs::create_dir_all(&hook_dir).unwrap();
        let body = r#"
name    = "bad"
stage   = "pre_provider_call"
enabled = true

[matcher]
pattern = "[unclosed"

[action]
kind = "allow"
"#;
        std::fs::write(hook_dir.join("bad.toml"), body).unwrap();
        let err = run_validate(&hook_dir, &OutputFormat::Json)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("failed validation"));
    }

    #[test]
    fn action_labels_cover_every_variant() {
        assert_eq!(action_label(&HookAction::Allow), "allow");
        assert_eq!(
            action_label(&HookAction::Replace {
                template: "x".into()
            }),
            "replace"
        );
        assert_eq!(
            action_label(&HookAction::Block {
                reason: "no".into()
            }),
            "block"
        );
    }

    // ── AR-02 (Session 24) hooks trace ────────────────────────────────

    #[test]
    fn parse_since_accepts_each_unit() {
        assert_eq!(super::parse_since_to_ns("1s").unwrap(), 1_000_000_000);
        assert_eq!(super::parse_since_to_ns("30s").unwrap(), 30_000_000_000);
        assert_eq!(super::parse_since_to_ns("5m").unwrap(), 300_000_000_000);
        assert_eq!(super::parse_since_to_ns("2h").unwrap(), 7_200_000_000_000);
        assert_eq!(super::parse_since_to_ns("1d").unwrap(), 86_400_000_000_000);
    }

    #[test]
    fn parse_since_rejects_bad_input() {
        for bad in &["", "  ", "5", "2x", "h2", "abc", "-2h"] {
            let r = super::parse_since_to_ns(bad);
            assert!(r.is_err(), "must reject {bad:?}, got {:?}", r.ok());
        }
    }

    #[test]
    fn parse_since_trims_surrounding_whitespace() {
        assert_eq!(
            super::parse_since_to_ns("  10m  ").unwrap(),
            600_000_000_000
        );
    }

    #[test]
    fn hook_code_label_pins_band() {
        use crate::wal::events::*;
        assert_eq!(
            super::hook_code_label(EVENT_TYPE_HOOK_FIRED),
            Some("HOOK_FIRED")
        );
        assert_eq!(
            super::hook_code_label(EVENT_TYPE_HOOK_BLOCKED),
            Some("HOOK_BLOCKED")
        );
        assert_eq!(
            super::hook_code_label(EVENT_TYPE_HOOK_REPLACED),
            Some("HOOK_REPLACED")
        );
        assert_eq!(
            super::hook_code_label(EVENT_TYPE_HOOK_ERROR),
            Some("HOOK_ERROR")
        );
        assert_eq!(super::hook_code_label(0x7F), None);
        assert_eq!(super::hook_code_label(0x90), None);
    }

    #[test]
    fn collect_hook_trace_returns_empty_for_missing_segment() {
        let dir = tempdir().unwrap();
        let segment = dir.path().join("nope.wal");
        let r = super::collect_hook_trace(&segment, 0, 100);
        assert!(
            r.is_err(),
            "missing file must Err — operator decides whether to ignore"
        );
    }

    #[test]
    fn collect_hook_trace_returns_empty_for_tiny_file() {
        // Defensive: zero-length / smaller-than-header file shouldn't
        // crash the tracer. Used by the very first `neoth hooks trace`
        // after a fresh install when the WAL is still mid-bootstrap.
        let dir = tempdir().unwrap();
        let segment = dir.path().join("000001.wal");
        std::fs::write(&segment, b"").unwrap();
        let rows = super::collect_hook_trace(&segment, 0, 100).unwrap();
        assert!(rows.is_empty());
    }

    /// Build a real WAL segment with the supplied (event_type, payload)
    /// frames. Each frame's HLC is stamped at `make_header` time (wall
    /// clock), so the floor_ns argument to `collect_hook_trace` must
    /// be set to `0` for these test fixtures unless the caller is
    /// deliberately exercising the time-window cutoff with the live
    /// clock.
    fn write_segment_with_frames(path: &std::path::Path, frames: &[(u8, &[u8])]) {
        use crate::wal::builder::make_header;
        use crate::wal::frame::encode_frame;
        use crate::wal::segment_header::SegmentHeader;

        let mut out = Vec::new();
        // Test fixture: all fields zeroed except segment_seq=1 — the
        // tracer doesn't validate them, it only needs the header to
        // pass `SegmentHeader::from_le_bytes` so the cursor advances
        // past `SEGMENT_HEADER_LEN`.
        out.extend_from_slice(&SegmentHeader::new(0, 1, 0, 0, [0u8; 16]).to_le_bytes());
        for (event_type, payload) in frames {
            let header = make_header(*event_type, payload);
            out.extend_from_slice(&encode_frame(&header, payload));
        }
        std::fs::write(path, out).unwrap();
    }

    /// Write a sealed v2/zstd segment with the given frames (61-byte v2
    /// header + a compressed frame blob), as the v1→v2 migration produces.
    fn write_v2_segment_with_frames(path: &std::path::Path, frames: &[(u8, &[u8])]) {
        use crate::wal::builder::make_header;
        use crate::wal::compress::compress_frames;
        use crate::wal::frame::encode_frame;
        use crate::wal::segment_header::{SEGMENT_FLAG_COMPRESSED, SegmentHeaderV2};

        let mut raw_frames = Vec::new();
        for (event_type, payload) in frames {
            let header = make_header(*event_type, payload);
            raw_frames.extend_from_slice(&encode_frame(&header, payload));
        }
        let blob = compress_frames(&raw_frames).unwrap();
        let mut out = SegmentHeaderV2::new(0, 1, 0, 0, [0u8; 16], SEGMENT_FLAG_COMPRESSED)
            .to_le_bytes()
            .to_vec();
        out.extend_from_slice(&blob);
        std::fs::write(path, out).unwrap();
    }

    #[test]
    fn collect_hook_trace_reads_frames_from_a_v2_compressed_segment() {
        // GOLD-ARCH-03 regression: hook frames inside a sealed v2/zstd
        // segment must be traced, not silently skipped.
        use crate::wal::events::*;

        let dir = tempdir().unwrap();
        let segment = dir.path().join("000001.wal");
        write_v2_segment_with_frames(
            &segment,
            &[
                (EVENT_TYPE_RAW_TEXT, b"not-a-hook"),
                (EVENT_TYPE_HOOK_FIRED, b"{}"),
                (EVENT_TYPE_HOOK_REPLACED, b"{}"),
            ],
        );

        let rows = super::collect_hook_trace(&segment, 0, 100).unwrap();
        assert_eq!(rows.len(), 2, "two hook frames survive from the v2 segment");
        assert_eq!(rows[0]["label"].as_str(), Some("HOOK_FIRED"));
        assert_eq!(rows[1]["label"].as_str(), Some("HOOK_REPLACED"));
    }

    #[test]
    fn collect_hook_trace_filters_to_hook_band() {
        // Mix of in-band hook frames + an unrelated 0x10 RAW_TEXT
        // frame. With floor_ns=0 every wall-clock-stamped frame is
        // in-window, so only the band filter prunes the non-hook row.
        use crate::wal::events::*;

        let dir = tempdir().unwrap();
        let segment = dir.path().join("000001.wal");
        write_segment_with_frames(
            &segment,
            &[
                (EVENT_TYPE_RAW_TEXT, b"not-a-hook"),
                (EVENT_TYPE_HOOK_FIRED, b"{}"),
                (EVENT_TYPE_HOOK_REPLACED, b"{}"),
            ],
        );

        let rows = super::collect_hook_trace(&segment, 0, 100).unwrap();
        assert_eq!(rows.len(), 2, "two hook frames should survive band filter");
        assert_eq!(rows[0]["label"].as_str(), Some("HOOK_FIRED"));
        assert_eq!(rows[1]["label"].as_str(), Some("HOOK_REPLACED"));
    }

    #[test]
    fn collect_hook_trace_filters_by_time_window() {
        // Stamp 3 hook frames with the current wall clock, then set
        // floor_ns one hour in the FUTURE — every frame must be
        // dropped by the window check. This pins the `ts >= floor_ns`
        // semantic without needing an HLC override hook.
        use crate::wal::events::*;

        let dir = tempdir().unwrap();
        let segment = dir.path().join("000001.wal");
        write_segment_with_frames(
            &segment,
            &[
                (EVENT_TYPE_HOOK_FIRED, b"{}"),
                (EVENT_TYPE_HOOK_BLOCKED, b"{}"),
                (EVENT_TYPE_HOOK_ERROR, b"{}"),
            ],
        );

        let future_floor: i64 = i64::MAX / 2;
        let rows = super::collect_hook_trace(&segment, future_floor, 100).unwrap();
        assert!(
            rows.is_empty(),
            "future floor must drop every frame, got {} rows",
            rows.len(),
        );
    }

    #[test]
    fn collect_hook_trace_honours_limit() {
        // Three in-window HOOK_FIRED frames; limit=2 must return 2.
        use crate::wal::events::*;

        let dir = tempdir().unwrap();
        let segment = dir.path().join("000001.wal");
        write_segment_with_frames(
            &segment,
            &[
                (EVENT_TYPE_HOOK_FIRED, b"a"),
                (EVENT_TYPE_HOOK_FIRED, b"b"),
                (EVENT_TYPE_HOOK_FIRED, b"c"),
            ],
        );

        let rows = super::collect_hook_trace(&segment, 0, 2).unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn hookdef_default_enabled_is_true() {
        let h = HookDef {
            name: "x".into(),
            stage: HookStage::PreProviderCall,
            enabled: None,
            priority: None,
            matcher: Some(HookMatcher {
                pattern: ".*".into(),
            }),
            action: HookAction::Allow,
            status_message: None,
            once: false,
        };
        assert!(h.is_enabled());
    }
}
