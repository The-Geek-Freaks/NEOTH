//! `neoth recon` — gated operator-recon over ProjectDiscovery's `uncover` +
//! `tlsx` (see `crate::recon`). Refused under Strict autonomy (NEOTH does
//! nothing external there); every run is audit-logged.

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::permissions::AutonomyLevel;
use crate::recon::{self, tlsx, uncover};

#[derive(Args, Debug, Clone)]
pub struct ReconArgs {
    #[command(subcommand)]
    pub action: ReconAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ReconAction {
    /// Discover exposed hosts via search engines (passive — uses YOUR engine API
    /// keys, configured in uncover's own config/env; NEOTH never sees them).
    Uncover {
        /// Search query in the engine's syntax, e.g. 'title:"GitLab"'.
        #[arg(short = 'q', long)]
        query: String,
        /// Engines to query (comma-separated): shodan,censys,fofa,quake,…
        #[arg(short = 'e', long, value_delimiter = ',', default_value = "shodan")]
        engine: Vec<String>,
        /// Maximum results.
        #[arg(short = 'l', long, default_value_t = 100)]
        limit: u32,
    },
    /// Grab TLS/cert intelligence (active — connects to each host:port).
    Tlsx {
        /// Target host(s) / IP / CIDR (comma-separated).
        #[arg(short = 'u', long = "host", value_delimiter = ',', required = true)]
        host: Vec<String>,
        /// Port(s), comma-separated. Defaults to tlsx's own default (443).
        #[arg(short = 'p', long, value_delimiter = ',')]
        port: Vec<String>,
    },
    /// Show which recon binaries are installed + where.
    Doctor,
}

pub async fn run_recon(args: ReconArgs, output: OutputFormat) -> Result<()> {
    match args.action {
        ReconAction::Doctor => doctor(output),
        ReconAction::Uncover {
            query,
            engine,
            limit,
        } => {
            let autonomy = gate()?;
            let home = FreedomConfig::default_neoth_home();
            let results = uncover::run(&query, &engine, limit).await?;
            recon::audit(
                "uncover",
                &format!("q={query:?} engines={engine:?}"),
                results.len(),
            );
            let args_hash = hash_args(&format!("q={query}|e={}", engine.join(",")));
            emit_recon_run(&home, "uncover", &args_hash, results.len(), autonomy).await;
            emit_uncover(&results, output)
        }
        ReconAction::Tlsx { host, port } => {
            let autonomy = gate()?;
            let home = FreedomConfig::default_neoth_home();
            let results = tlsx::run(&host, &port).await?;
            recon::audit("tlsx", &format!("hosts={host:?}"), results.len());
            let args_hash = hash_args(&format!("u={}|p={}", host.join(","), port.join(",")));
            emit_recon_run(&home, "tlsx", &args_hash, results.len(), autonomy).await;
            emit_tlsx(&results, output)
        }
    }
}

/// Recon is an external/active capability — refused under Strict autonomy.
/// Returns the live autonomy level so the caller can stamp it into the audit.
fn gate() -> Result<AutonomyLevel> {
    // Fail CLOSED: a missing/corrupt/unreadable freedom.yaml must NOT
    // silently drop to the Standard default and let an external/active
    // recon run — assume the strictest level so the gate below refuses.
    let autonomy = match FreedomConfig::load_from_default_path() {
        Ok(c) => c.autonomy,
        Err(_) => AutonomyLevel::Strict,
    };
    if autonomy == AutonomyLevel::Strict {
        anyhow::bail!(
            "recon is refused under Strict autonomy — raise it (`neoth autonomy set standard`) to allow external recon"
        );
    }
    Ok(autonomy)
}

/// Stable hex hash of a recon invocation's args. The raw query / target hosts
/// are NEVER written to the WAL (a Shodan dork or victim list is sensitive) —
/// only this fingerprint, so a reader can correlate runs without leaking intent.
fn hash_args(s: &str) -> String {
    format!("{:016x}", xxhash_rust::xxh3::xxh3_64(s.as_bytes()))
}

/// Audit a recon run to the WAL at the MCP/computer-use level: forward
/// `RECON_RUN` to the live daemon over the audit-RPC channel (it owns the single
/// WAL writer), or append a one-shot frame directly when no daemon is running.
/// Best-effort — an audit gap never fails the recon command.
async fn emit_recon_run(
    home: &std::path::Path,
    tool: &str,
    args_hash: &str,
    result_count: usize,
    autonomy: AutonomyLevel,
) {
    let operator_id = FreedomConfig::load_from_default_path()
        .ok()
        .and_then(|c| c.operator_id);
    let payload = serde_json::to_vec(&serde_json::json!({
        "tool": tool,
        "args_hash": args_hash,
        "result_count": result_count,
        "autonomy_level": autonomy.as_str(),
        "operator_id": operator_id,
        "ts_unix": crate::time::now_unix_secs(),
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    let event_type = crate::wal::events::EVENT_TYPE_RECON_RUN;

    let pidfile = crate::daemon::pidfile::default_pidfile();
    let daemon_live = matches!(
        crate::daemon::pidfile::live_daemon_pid(&pidfile),
        Ok(Some(_))
    );
    if daemon_live {
        if let Err(e) =
            crate::daemon::audit_rpc::try_post_audit_frame(home, event_type, &payload).await
        {
            tracing::debug!(error = %e, "recon RECON_RUN audit forward failed (best-effort)");
        }
    } else {
        let segment = home.join("wal").join("000001.wal");
        if let Some(parent) = segment.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok((writer, join)) = crate::wal::spawn(segment) {
            let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
            let _ = writer.append(header, payload).await;
            drop(writer);
            let _ = join.await;
        }
    }
}

fn emit_uncover(results: &[uncover::UncoverResult], output: OutputFormat) -> Result<()> {
    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        for r in results {
            println!("{}", serde_json::to_string(r)?);
        }
        return Ok(());
    }
    if results.is_empty() {
        println!("uncover: no hosts found.");
        return Ok(());
    }
    println!("uncover — {} host(s):", results.len());
    for r in results {
        let loc = if r.host.is_empty() {
            r.ip.clone()
        } else {
            format!("{} ({})", r.host, r.ip)
        };
        println!("  {}:{}  [{}]", loc, r.port, r.source);
    }
    Ok(())
}

fn emit_tlsx(results: &[tlsx::TlsxResult], output: OutputFormat) -> Result<()> {
    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        for r in results {
            println!("{}", serde_json::to_string(r)?);
        }
        return Ok(());
    }
    if results.is_empty() {
        println!("tlsx: no probes succeeded.");
        return Ok(());
    }
    println!("tlsx — {} probe(s):", results.len());
    for r in results {
        let flags = [(r.expired, "EXPIRED"), (r.self_signed, "SELF-SIGNED")]
            .iter()
            .filter(|(b, _)| *b)
            .map(|(_, s)| *s)
            .collect::<Vec<_>>()
            .join(",");
        let loc = if r.host.is_empty() { &r.ip } else { &r.host };
        println!(
            "  {}:{}  {} {}  CN={}{}",
            loc,
            r.port,
            r.tls_version,
            r.cipher,
            r.subject_cn,
            if flags.is_empty() {
                String::new()
            } else {
                format!("  [{flags}]")
            }
        );
    }
    Ok(())
}

fn doctor(output: OutputFormat) -> Result<()> {
    let tools = [
        ("uncover", uncover::BINARY, uncover::INSTALL_HINT),
        ("tlsx", tlsx::BINARY, tlsx::INSTALL_HINT),
    ];
    let rows: Vec<_> = tools
        .iter()
        .map(|(name, bin, hint)| (*name, recon::locate(bin), *hint))
        .collect();
    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        println!(
            "{}",
            serde_json::json!({
                "tools": rows.iter().map(|(n, p, _)| serde_json::json!({
                    "tool": n, "installed": p.is_some(),
                    "path": p.as_ref().map(|p| p.display().to_string()),
                })).collect::<Vec<_>>()
            })
        );
        return Ok(());
    }
    println!("NEOTH recon tools:");
    for (name, path, hint) in rows {
        match path {
            Some(p) => println!("  ✓ {name:<8} {}", p.display()),
            None => println!("  ✗ {name:<8} not installed — `{hint}`"),
        }
    }
    Ok(())
}
