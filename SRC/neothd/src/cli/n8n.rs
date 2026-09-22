//! `neoth n8n {adopt,status,workflows}`.
//!
//! Adoption binds an operator-supplied, already-running literal-loopback n8n
//! instance. It never installs, starts, discovers, or owns an n8n process.

use std::io::{BufRead, IsTerminal, Read};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::LoopbackHttpEndpoint;
use crate::installers::n8n_starter_workflows::{NEOTH_HTTP_BASE, all_known_workflows};
use crate::integrations::state::JobId;

const MAX_N8N_API_KEY_BYTES: u64 = 8 * 1024;

#[derive(Args, Debug, Clone)]
pub struct N8nArgs {
    #[command(subcommand)]
    pub action: N8nAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum N8nAction {
    /// Adopt an already-running n8n API at an exact literal-loopback origin.
    Adopt {
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        api_key_stdin: bool,
    },
    /// Read durable adoption status. This does not make a live HTTP request.
    Status {
        #[arg(long)]
        job: Option<String>,
    },
    /// List NEOTH workflow templates bundled in the binary.
    Workflows,
}

pub async fn run_n8n(args: N8nArgs, output: OutputFormat) -> Result<()> {
    match args.action {
        N8nAction::Adopt { endpoint, api_key_stdin } => run_adopt(&endpoint, api_key_stdin, output).await,
        N8nAction::Status { job } => run_status(job.as_deref(), output),
        N8nAction::Workflows => run_workflows(output),
    }
}

async fn run_adopt(endpoint: &str, api_key_stdin: bool, output: OutputFormat) -> Result<()> {
    let endpoint = LoopbackHttpEndpoint::parse(endpoint).map_err(anyhow::Error::msg)?;
    let home = crate::config::FreedomConfig::default_neoth_home();
    if !api_key_stdin {
        let service = crate::integrations::n8n::open_n8n_job_service(&home)?;
        let job = crate::integrations::n8n::enqueue_required_input_failure(
            &service, &endpoint, crate::integrations::JobRequester::Cli,
        )?;
        return render_adopt_job(&job, output);
    }
    if std::io::stdin().is_terminal() { return Err(anyhow!("--api-key-stdin requires piped standard input")); }
    let api_key = read_api_key_from_stdin().await?;
    let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel();
    let cancellation_task = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = cancel_tx.send(());
        }
    });
    let result = crate::integrations::n8n::adopt_at_with_cancel(
        &home, endpoint, api_key, &mut cancel_rx,
    ).await;
    cancellation_task.abort();
    let job = result?;
    render_adopt_job(&job, output)
}

/// Read one key line with both a byte and wall-clock bound. The blocking stdin
/// read lives on one detached, narrow thread, so a producer that leaves a pipe
/// open cannot keep Tokio's blocking pool or runtime shutdown alive.
async fn read_api_key_from_stdin() -> Result<crate::secret::SecretString> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    thread::spawn(move || {
        let _ = sender.send(read_api_key_line(std::io::stdin().lock()));
    });
    tokio::time::timeout(Duration::from_secs(5), receiver)
        .await
        .map_err(|_| anyhow!("n8n API key input timed out"))?
        .map_err(|_| anyhow!("n8n API key input could not be read"))?
}

fn read_api_key_line(mut reader: impl BufRead) -> Result<crate::secret::SecretString> {
    let mut input = zeroize::Zeroizing::new(Vec::new());
    reader.take(MAX_N8N_API_KEY_BYTES + 2)
        .read_until(b'\n', &mut input)
        .context("read bounded n8n API key from standard input")?;
    if input.last() == Some(&b'\n') { input.pop(); if input.last() == Some(&b'\r') { input.pop(); } }
    if input.len() > MAX_N8N_API_KEY_BYTES as usize { return Err(anyhow!("n8n API key input exceeds the bounded line length")); }
    let key = match String::from_utf8(std::mem::take(&mut *input)) {
        Ok(value) => crate::secret::SecretString::from(value),
        Err(error) => {
            use zeroize::Zeroize;
            let mut rejected = error.into_bytes();
            rejected.zeroize();
            return Err(anyhow!("n8n API key input is not UTF-8"));
        }
    };
    if key.expose().is_empty() || key.expose().chars().any(char::is_control) {
        return Err(anyhow!("n8n API key input must be nonempty and contain no control characters"));
    }
    Ok(key)
}

fn render_adopt_job(job: &crate::integrations::IntegrationJob, output: OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!("{}", serde_json::json!({
            "job_id": job.job_id, "state": job.state, "failure_code": job.failure.as_ref().map(|failure| &failure.code),
        })),
        OutputFormat::Table => {
            println!("n8n adoption job: {}", job.job_id);
            println!("state: {}", job.state);
            if let Some(failure) = &job.failure { println!("failure: {} — {}", failure.code, failure.redacted_message); }
        }
    }
    if let Some(failure) = &job.failure {
        return Err(anyhow!("n8n adoption job {} failed: {}", job.job_id, failure.code));
    }
    Ok(())
}

fn run_status(selected_job: Option<&str>, output: OutputFormat) -> Result<()> {
    let selected_job = selected_job.map(JobId::parse).transpose().map_err(anyhow::Error::msg)?;
    let view = crate::integrations::n8n::status_at(&crate::config::FreedomConfig::default_neoth_home(), selected_job.as_ref())?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!("{}", serde_json::to_string(&view)?),
        OutputFormat::Table => {
            println!("configured endpoint: {}", view.configured_endpoint.as_ref().map(LoopbackHttpEndpoint::as_str).unwrap_or("unconfigured"));
            println!("API key: {}", if view.api_key_present { "present" } else { "absent" });
            match &view.job {
                Some(job) => {
                    println!("job: {} ({})", job.id, job.state);
                    println!("progress: {}/{}", job.completed_steps, job.total_steps);
                    if let Some(step) = &job.current_step { println!("current step: {step}"); }
                    if let Some(code) = &job.failure_code { println!("failure: {code}"); }
                }
                None => println!("job: none"),
            }
        }
    }
    Ok(())
}

fn run_workflows(output: OutputFormat) -> Result<()> {
    let workflows = all_known_workflows();
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let rows: Vec<_> = workflows.iter().map(|w| serde_json::json!({"slug": w.slug, "name": w.name, "description": w.description})).collect();
            println!("{}", serde_json::json!({ "workflows": rows }));
        }
        OutputFormat::Table => {
            for workflow in &workflows { println!("• {}  [{}]\n    {}", workflow.name, workflow.slug, workflow.description); }
            println!("\n{} workflow(s). Import into n8n; they POST to {NEOTH_HTTP_BASE}.", workflows.len());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdin_key_line_accepts_exact_limit_with_lf_and_crlf() {
        for ending in [b"\n".as_slice(), b"\r\n".as_slice()] {
            let mut bytes = vec![b'a'; MAX_N8N_API_KEY_BYTES as usize];
            bytes.extend_from_slice(ending);
            let key = read_api_key_line(std::io::Cursor::new(bytes)).unwrap();
            assert_eq!(key.expose().len(), MAX_N8N_API_KEY_BYTES as usize);
        }
    }

    #[test]
    fn stdin_key_line_rejects_oversize_invalid_utf8_and_controls() {
        let mut oversize = vec![b'a'; MAX_N8N_API_KEY_BYTES as usize + 1];
        oversize.push(b'\n');
        assert!(read_api_key_line(std::io::Cursor::new(oversize)).is_err());
        assert!(read_api_key_line(std::io::Cursor::new(vec![0xff, b'\n'])).is_err());
        assert!(read_api_key_line(std::io::Cursor::new(vec![b'a', 0, b'\n'])).is_err());
    }
}
