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
            gate()?;
            let results = uncover::run(&query, &engine, limit).await?;
            recon::audit(
                "uncover",
                &format!("q={query:?} engines={engine:?}"),
                results.len(),
            );
            emit_uncover(&results, output)
        }
        ReconAction::Tlsx { host, port } => {
            gate()?;
            let results = tlsx::run(&host, &port).await?;
            recon::audit("tlsx", &format!("hosts={host:?}"), results.len());
            emit_tlsx(&results, output)
        }
    }
}

/// Recon is an external/active capability — refused under Strict autonomy.
fn gate() -> Result<()> {
    let autonomy = FreedomConfig::load_from_default_path()
        .map(|c| c.autonomy)
        .unwrap_or_default();
    if autonomy == AutonomyLevel::Strict {
        anyhow::bail!(
            "recon is refused under Strict autonomy — raise it (`neoth autonomy set standard`) to allow external recon"
        );
    }
    Ok(())
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
