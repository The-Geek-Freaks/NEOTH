//! `neoth cost` — cost transparency.
//!
//! Two surfaces:
//!   - `neoth cost <PROMPT>` — C-14 EX-ANTE estimate: dry-run a provider call's
//!     projected token count + euro cost BEFORE dispatching (no LLM invoked).
//!   - `neoth cost top-sessions` — GOLD-ADAPT-VIEW-01 EX-POST attribution: rank
//!     past sessions by total LLM token spend, scanned from the WAL audit trail.
//!
//! ## VIEW-01: "cost" = tokens, not dollars
//!
//! The ex-post attribution is measured in TOKENS (input + output), not euros:
//! NEOTH is model-version-agnostic (no hardcoded per-model price table may gate
//! a new model), and a `claude_cli` subscription session has no per-token price
//! at all. Tokens are the honest, provider-neutral spend metric. (The ex-ante
//! `estimate` keeps its euro projection — that is an explicit pre-flight choice
//! over the configured provider, not a historical attribution.)

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::Result;
use clap::{Args, Subcommand};
use serde::Deserialize;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::providers::cost::{predict, render_preview};
use crate::providers::meter::Meter;

/// Bucket key for `0x21` frames whose payload has no (or empty) `session_id`
/// — frames written before VIEW-01, plus channel-pipeline frames that do not
/// yet thread a session id. Shown explicitly so the operator sees the
/// un-attributed spend rather than it silently vanishing.
const UNATTRIBUTED: &str = "(unattributed)";

#[derive(Args, Debug, Clone)]
#[command(args_conflicts_with_subcommands = true)]
pub struct CostArgs {
    /// Sub-surface. When omitted, runs the ex-ante `estimate` over `PROMPT`.
    #[command(subcommand)]
    pub action: Option<CostAction>,

    /// Prompt text to estimate. Use `-` to read from stdin. (estimate surface)
    #[arg(value_name = "PROMPT")]
    pub prompt: Option<String>,

    /// Override the active provider for the estimate. Defaults to
    /// `freedom.yaml::provider_kind`.
    #[arg(long, value_name = "NAME")]
    pub provider: Option<String>,

    /// Override the active model for the estimate. Defaults to
    /// `freedom.yaml::provider_model`.
    #[arg(long, value_name = "MODEL")]
    pub model: Option<String>,

    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CostAction {
    /// GOLD-ADAPT-VIEW-01 — rank past sessions by total LLM token spend
    /// (scanned from the WAL `0x21 PROVIDER_RESPONSE` audit frames).
    TopSessions {
        /// How many sessions to show (highest spend first).
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
}

pub async fn run_cost(args: CostArgs) -> Result<()> {
    // VIEW-01 ex-post attribution surface.
    if let Some(CostAction::TopSessions { limit }) = args.action {
        return run_top_sessions(limit, args.output);
    }
    // C-14 ex-ante estimate surface (default).
    run_estimate(args).await
}

// ─────────────────────────── C-14 estimate ───────────────────────────

async fn run_estimate(args: CostArgs) -> Result<()> {
    let prompt = resolve_prompt(&args).await?;
    let cfg = FreedomConfig::load_from_default_path_or_default()?;

    let provider = args
        .provider
        .clone()
        .or_else(|| cfg.provider_kind.map(|p| format!("{p:?}").to_lowercase()))
        .unwrap_or_else(|| "openai_api".to_string());
    let model = args
        .model
        .clone()
        .or_else(|| cfg.provider_model.clone())
        .unwrap_or_else(|| "gpt-5.5".to_string());

    // Use a fresh meter — CLI is one-shot, so we don't have rolling
    // window data here. The estimator will fall back to the default
    // output-token guess for cold meters.
    let meter = Meter::with_default_window();
    let estimate = predict(&provider, &model, &prompt, &meter);

    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let body = serde_json::json!({
                "provider": provider,
                "model": model,
                "input_tokens": estimate.input_tokens,
                "output_tokens_est": estimate.output_tokens_est,
                "input_eur": estimate.input_eur,
                "output_eur": estimate.output_eur,
                "total_eur": estimate.total_eur,
            });
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        OutputFormat::Table => {
            println!("{}", render_preview(&provider, &model, &estimate));
        }
    }
    Ok(())
}

async fn resolve_prompt(args: &CostArgs) -> Result<String> {
    if let Some(p) = &args.prompt {
        if p == "-" {
            use tokio::io::AsyncReadExt;
            let mut buf = String::new();
            tokio::io::stdin().read_to_string(&mut buf).await?;
            return Ok(buf);
        }
        if !p.trim().is_empty() {
            return Ok(p.clone());
        }
    }
    anyhow::bail!("no prompt supplied. Pass it as the first argument or `-` for stdin.");
}

// ─────────────────────── VIEW-01 top-sessions ───────────────────────

/// Fields read out of a `0x21 PROVIDER_RESPONSE` payload. `serde(default)`-
/// tolerant: a frame written before VIEW-01 (no `session_id`) buckets as
/// `(unattributed)` and still contributes its tokens; a `null` token field
/// coerces to 0.
#[derive(Deserialize)]
struct CostFrame {
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
}

/// Per-session usage rollup.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct SessionCost {
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Number of `0x21` replies attributed to this session.
    pub responses: u64,
    pub models: BTreeSet<String>,
    /// Most-recent reply wall-clock (unix secs), from the frame HLC.
    pub last_ts_unix: i64,
}

impl SessionCost {
    pub fn total_tokens(&self) -> u64 {
        self.input_tokens.saturating_add(self.output_tokens)
    }
}

/// Scan every `*.wal` segment in `wal_dir`, bucketing `0x21 PROVIDER_RESPONSE`
/// usage by payload `session_id`. Unreadable segments / undecodable frames are
/// skipped, never fatal — a partially-corrupt tail must not blind the report.
/// Mirrors the proven scan in [`crate::daemon::token_anomaly_cron`].
pub fn scan_cost_by_session(wal_dir: &Path) -> BTreeMap<String, SessionCost> {
    let mut by_session: BTreeMap<String, SessionCost> = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(wal_dir) else {
        return by_session;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("wal") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(hdr) = crate::wal::segment_header::parse_segment_header(&bytes) else {
            continue;
        };
        let mut cursor = hdr.header_len();
        while cursor < bytes.len() {
            let dec = match crate::wal::frame::decode_frame(&bytes[cursor..]) {
                Ok(d) => d,
                Err(_) => break, // torn tail — stop this segment, never fatal
            };
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            if dec.header.event_type == crate::wal::events::EVENT_TYPE_PROVIDER_RESPONSE {
                if let Ok(p) = serde_json::from_slice::<CostFrame>(dec.payload) {
                    let key = match p.session_id {
                        Some(s) if !s.is_empty() => s,
                        _ => UNATTRIBUTED.to_string(),
                    };
                    let ts = (dec.header.hlc.physical_ns() / 1_000_000_000) as i64;
                    let e = by_session.entry(key).or_default();
                    e.input_tokens = e.input_tokens.saturating_add(p.input_tokens);
                    e.output_tokens = e.output_tokens.saturating_add(p.output_tokens);
                    e.responses = e.responses.saturating_add(1);
                    if let Some(m) = p.model {
                        if !m.is_empty() {
                            e.models.insert(m);
                        }
                    }
                    if ts > e.last_ts_unix {
                        e.last_ts_unix = ts;
                    }
                }
            }
            cursor = cursor.saturating_add(total);
        }
    }
    by_session
}

/// Rank sessions by total tokens (desc), tie-broken by response count (desc)
/// then session id (asc, deterministic). Returns at most `limit` rows.
pub fn top_sessions(
    by_session: &BTreeMap<String, SessionCost>,
    limit: usize,
) -> Vec<(String, SessionCost)> {
    let mut rows: Vec<(String, SessionCost)> = by_session
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    rows.sort_by(|a, b| {
        b.1.total_tokens()
            .cmp(&a.1.total_tokens())
            .then(b.1.responses.cmp(&a.1.responses))
            .then(a.0.cmp(&b.0))
    });
    rows.truncate(limit);
    rows
}

/// Short, human-recognisable session id: trailing chars (after any `:` prefix).
fn short_id(id: &str) -> String {
    if id == UNATTRIBUTED {
        return id.to_string();
    }
    let core = id.rsplit(':').next().unwrap_or(id);
    let n = core.chars().count();
    if n <= 12 {
        core.to_string()
    } else {
        format!("…{}", core.chars().skip(n - 11).collect::<String>())
    }
}

/// Pure render of the ranked rows — factored out so it is unit-testable without
/// capturing stdout.
fn render_top_sessions(rows: &[(String, SessionCost)], output: OutputFormat) -> Result<String> {
    let json_rows: Vec<serde_json::Value> = rows
        .iter()
        .map(|(id, c)| {
            serde_json::json!({
                "session_id": id,
                "input_tokens": c.input_tokens,
                "output_tokens": c.output_tokens,
                "total_tokens": c.total_tokens(),
                "responses": c.responses,
                "models": c.models.iter().cloned().collect::<Vec<_>>(),
                "last_ts_unix": c.last_ts_unix,
            })
        })
        .collect();
    Ok(match output {
        OutputFormat::Json => format!("{}\n", serde_json::to_string_pretty(&json_rows)?),
        OutputFormat::Jsonl => {
            let mut s = String::new();
            for r in &json_rows {
                s.push_str(&serde_json::to_string(r)?);
                s.push('\n');
            }
            s
        }
        OutputFormat::Table => {
            let mut s = String::new();
            s.push_str("# top sessions by LLM token spend (input+output; cost = tokens, not $)\n");
            if rows.is_empty() {
                s.push_str("  (no PROVIDER_RESPONSE frames found in the WAL)\n");
                return Ok(s);
            }
            s.push_str(&format!(
                "  {:<3} {:<14} {:>10} {:>10} {:>10} {:>5}  {}\n",
                "#", "session", "in_tok", "out_tok", "total", "resp", "models"
            ));
            for (i, (id, c)) in rows.iter().enumerate() {
                s.push_str(&format!(
                    "  {:<3} {:<14} {:>10} {:>10} {:>10} {:>5}  {}\n",
                    i + 1,
                    short_id(id),
                    c.input_tokens,
                    c.output_tokens,
                    c.total_tokens(),
                    c.responses,
                    c.models.iter().cloned().collect::<Vec<_>>().join(","),
                ));
            }
            s
        }
    })
}

fn run_top_sessions(limit: usize, output: OutputFormat) -> Result<()> {
    let wal_dir = FreedomConfig::default_wal_dir();
    let by_session = scan_cost_by_session(&wal_dir);
    let rows = top_sessions(&by_session, limit);
    print!("{}", render_top_sessions(&rows, output)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cost_estimate_with_explicit_provider_returns_zero_for_local() {
        let args = CostArgs {
            action: None,
            prompt: Some("hello world".into()),
            provider: Some("local_qwen".into()),
            model: Some("Qwen/Qwen2.5-3B-Instruct".into()),
            output: OutputFormat::Json,
        };
        // run_cost prints to stdout — we just verify it doesn't error.
        // The price-lookup table guarantees zero for local providers.
        run_cost(args).await.expect("dry-run must not fail");
    }

    #[tokio::test]
    async fn cost_estimate_errors_on_empty_prompt() {
        let args = CostArgs {
            action: None,
            prompt: Some("   ".into()),
            provider: Some("openai_api".into()),
            model: Some("gpt-4o".into()),
            output: OutputFormat::Json,
        };
        let err = run_cost(args).await.unwrap_err();
        assert!(err.to_string().contains("no prompt"));
    }

    // ── VIEW-01 top-sessions ──────────────────────────────────────────

    async fn write_response(
        writer: &crate::wal::writer::WalWriterHandle,
        session: Option<&str>,
        model: &str,
        inp: u64,
        out: u64,
    ) {
        let mut payload = serde_json::json!({
            "model": model,
            "input_tokens": inp,
            "output_tokens": out,
        });
        if let Some(s) = session {
            payload["session_id"] = serde_json::json!(s);
        }
        let bytes = serde_json::to_vec(&payload).unwrap();
        let header = crate::wal::HeaderBuilder::new(
            crate::wal::events::EVENT_TYPE_PROVIDER_RESPONSE,
            &bytes,
        )
        .build();
        writer.append(header, bytes).await.unwrap();
    }

    #[tokio::test]
    async fn top_sessions_aggregates_and_ranks_by_total_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg).unwrap();
        // session A: 2 replies, 300 total. session B: 1 reply, 500 total.
        write_response(&writer, Some("sess-A"), "claude", 100, 50).await;
        write_response(&writer, Some("sess-A"), "claude", 100, 50).await;
        write_response(&writer, Some("sess-B"), "gpt", 200, 300).await;
        // a frame with NO session_id → (unattributed)
        write_response(&writer, None, "local", 10, 5).await;
        drop(writer);
        let _ = join.await;

        let by = scan_cost_by_session(dir.path());
        assert_eq!(by.get("sess-A").unwrap().total_tokens(), 300);
        assert_eq!(by.get("sess-A").unwrap().responses, 2);
        assert_eq!(by.get("sess-B").unwrap().total_tokens(), 500);
        assert_eq!(by.get(UNATTRIBUTED).unwrap().total_tokens(), 15);

        let rows = top_sessions(&by, 10);
        assert_eq!(rows[0].0, "sess-B"); // 500
        assert_eq!(rows[1].0, "sess-A"); // 300
        assert_eq!(rows[2].0, UNATTRIBUTED); // 15
        assert_eq!(
            rows[0].1.models.iter().cloned().collect::<Vec<_>>(),
            vec!["gpt"]
        );
    }

    #[tokio::test]
    async fn top_sessions_limit_truncates_ranking() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg).unwrap();
        for i in 0..5 {
            write_response(&writer, Some(&format!("s{i}")), "m", (i + 1) * 100, 0).await;
        }
        drop(writer);
        let _ = join.await;
        let by = scan_cost_by_session(dir.path());
        let rows = top_sessions(&by, 2);
        assert_eq!(rows.len(), 2, "limit caps the rows");
        assert_eq!(rows[0].0, "s4", "highest spend first");
    }

    #[test]
    fn scan_missing_dir_is_empty_not_fatal() {
        let by = scan_cost_by_session(Path::new("/no/such/wal/dir/xyz"));
        assert!(by.is_empty());
    }

    #[test]
    fn render_table_empty_is_graceful() {
        let out = render_top_sessions(&[], OutputFormat::Table).unwrap();
        assert!(out.contains("no PROVIDER_RESPONSE frames"), "got: {out}");
    }

    #[test]
    fn render_json_carries_total_and_models() {
        let c = SessionCost {
            input_tokens: 100,
            output_tokens: 40,
            responses: 1,
            models: ["claude".to_string()].into_iter().collect(),
            last_ts_unix: 0,
        };
        let rows = vec![("sess-X".to_string(), c)];
        let out = render_top_sessions(&rows, OutputFormat::Json).unwrap();
        let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(v[0]["total_tokens"], 140);
        assert_eq!(v[0]["session_id"], "sess-X");
        assert_eq!(v[0]["models"][0], "claude");
    }

    #[test]
    fn short_id_keeps_unattributed_label() {
        assert_eq!(short_id(UNATTRIBUTED), UNATTRIBUTED);
        assert_eq!(short_id("short"), "short");
        assert!(short_id("session:0123456789abcdef").starts_with('…'));
    }
}
