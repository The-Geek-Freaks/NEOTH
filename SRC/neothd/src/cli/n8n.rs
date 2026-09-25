//! `neoth n8n {install,repair,backup,restore,uninstall,purge,adopt,status,import-workflows,workflows}`.
//!
//! Adoption binds an operator-supplied, already-running literal-loopback n8n
//! instance. It never installs, starts, discovers, or owns an n8n process.

use std::io::{BufRead, IsTerminal};
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
    /// Start the pinned, NEOTH-owned Docker n8n runtime and prove its API key.
    Install {
        /// Literal loopback host port; the container is always bound to 127.0.0.1.
        #[arg(long)]
        port: Option<u16>,
        /// Read an already-issued n8n API key from piped standard input.
        #[arg(long, conflicts_with = "bootstrap_owner")]
        api_key_stdin: bool,
        /// Create the first n8n owner and API key inside an unexposed,
        /// networkless bootstrap container before publishing the runtime.
        #[arg(long, conflicts_with = "api_key_stdin")]
        bootstrap_owner: bool,
        /// Reattach the exact retained volume recorded by this Ready uninstall job.
        #[arg(long, conflicts_with_all = ["bootstrap_owner", "port"])]
        reuse_uninstall: Option<String>,
    },
    /// Restore the receipt-owned container with its pinned image, retained volume and stored API key.
    Repair,
    /// Stop the owned runtime, archive its complete data volume, and restore its running state.
    /// Repeating an interrupted backup reconciles custody without repeating an uncertain copy.
    Backup,
    /// Validate a receipt-owned backup in an isolated candidate volume. The live n8n runtime is unchanged.
    Restore {
        /// Ready backup job whose verified archive is the only restore source.
        #[arg(long)]
        backup: String,
    },
    /// Remove the exact NEOTH-managed container and retain its data volume.
    /// Repeating an interrupted command reconciles absence without retrying deletion.
    Uninstall,
    /// Permanently delete the owned data volume retained by a completed uninstall.
    /// Without --confirm, show the exact target and required confirmation only.
    Purge {
        /// Ready uninstall job whose receipt identifies the retained volume.
        #[arg(long)]
        uninstall: String,
        /// Exact confirmation phrase shown by this command without --confirm.
        #[arg(long)]
        confirm: Option<String>,
    },
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
    /// Import all bundled inactive workflows into an already-ready managed n8n binding.
    ImportWorkflows,
    /// List NEOTH workflow templates bundled in the binary.
    Workflows,
}

pub async fn run_n8n(args: N8nArgs, output: OutputFormat) -> Result<()> {
    match args.action {
        N8nAction::Install {
            port,
            api_key_stdin,
            bootstrap_owner,
            reuse_uninstall,
        } => {
            run_install(
                port,
                api_key_stdin,
                bootstrap_owner,
                reuse_uninstall.as_deref(),
                output,
            )
            .await
        }
        N8nAction::Repair => run_repair(output).await,
        N8nAction::Backup => run_backup(output).await,
        N8nAction::Restore { backup } => run_restore(&backup, output).await,
        N8nAction::Uninstall => run_uninstall(output).await,
        N8nAction::Purge { uninstall, confirm } => {
            run_purge(&uninstall, confirm.as_deref(), output).await
        }
        N8nAction::Adopt {
            endpoint,
            api_key_stdin,
        } => run_adopt(&endpoint, api_key_stdin, output).await,
        N8nAction::Status { job } => run_status(job.as_deref(), output),
        N8nAction::ImportWorkflows => run_import_workflows(output).await,
        N8nAction::Workflows => run_workflows(output),
    }
}

async fn run_backup(output: OutputFormat) -> Result<()> {
    use crate::integrations::n8n::managed_runtime::managed_backup;

    let home = crate::config::FreedomConfig::default_neoth_home();
    let job = managed_backup::backup_managed_at(&home).await?;
    let receipt = managed_backup::completed_receipt_at(&home, &job).map_err(anyhow::Error::msg)?;
    if job.state == crate::integrations::JobState::Ready && receipt.is_none() {
        return Err(anyhow!("n8n backup has no verified completion receipt"));
    }
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "job_id": job.job_id,
                "state": job.state,
                "operation": "backup",
                "receipt": receipt,
                "failure_code": job.failure.as_ref().map(|failure| &failure.code),
            })
        ),
        OutputFormat::Table => {
            println!("n8n backup job: {}", job.job_id);
            println!("state: {}", job.state);
            if let Some(receipt) = &receipt {
                print_backup_receipt(receipt)?;
            }
            if let Some(failure) = &job.failure {
                println!("failure: {} — {}", failure.code, failure.redacted_message);
            }
        }
    }
    if job.state != crate::integrations::JobState::Ready {
        return Err(anyhow!(
            "n8n backup job {} requires reconciliation (state: {})",
            job.job_id,
            job.state,
        ));
    }
    Ok(())
}

async fn run_restore(backup: &str, output: OutputFormat) -> Result<()> {
    let backup = parse_restore_backup_id(backup)?;
    let home = crate::config::FreedomConfig::default_neoth_home();
    let job = crate::integrations::n8n::managed_runtime::managed_restore::restore_managed_at(
        &home, &backup,
    )
    .await?;
    let receipt = crate::integrations::n8n::managed_runtime::managed_restore::completed_receipt_at(
        &home, &job,
    )
    .map_err(anyhow::Error::msg)?;
    if job.state == crate::integrations::JobState::Ready && receipt.is_none() {
        return Err(anyhow!("n8n restore has no verified completion receipt"));
    }
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "job_id": job.job_id,
                "state": job.state,
                "operation": "restore",
                "backup_job_id": backup,
                "receipt": receipt,
                "live_n8n": "unchanged",
                "failure_code": job.failure.as_ref().map(|failure| &failure.code),
            })
        ),
        OutputFormat::Table => {
            println!("n8n restore job: {}", job.job_id);
            println!("state: {}", job.state);
            println!("backup job: {backup}");
            println!("candidate: isolated retained volume validation");
            println!("live n8n: unchanged");
            if let Some(receipt) = &receipt {
                println!("candidate validation: verified");
                println!("workflows validated: {}", receipt.workflow_count);
                println!("credentials validated: {}", receipt.credential_count);
                println!(
                    "credential decryption proven: {}",
                    receipt.credential_decryption_proven
                );
            }
            if let Some(failure) = &job.failure {
                println!("failure: {} — {}", failure.code, failure.redacted_message);
            }
        }
    }
    if job.state != crate::integrations::JobState::Ready || receipt.is_none() {
        return Err(anyhow!(
            "n8n restore job {} requires reconciliation (state: {})",
            job.job_id,
            job.state,
        ));
    }
    Ok(())
}

fn parse_restore_backup_id(value: &str) -> Result<JobId> {
    JobId::parse(value.to_owned())
        .map_err(anyhow::Error::msg)
        .context("n8n restore --backup must be a canonical v7 UUID")
}

fn print_backup_receipt(
    receipt: &crate::integrations::n8n::managed_runtime::managed_backup::BackupReceiptView,
) -> Result<()> {
    let fields = serde_json::to_value(receipt)?;
    if let Some(fields) = fields.as_object() {
        for (name, value) in fields {
            let label = name.replace('_', " ");
            if let Some(value) = value.as_str() {
                println!("{label}: {value}");
            } else {
                println!("{label}: {value}");
            }
        }
    }
    Ok(())
}

async fn run_repair(output: OutputFormat) -> Result<()> {
    let home = crate::config::FreedomConfig::default_neoth_home();
    let job =
        crate::integrations::n8n::managed_runtime::managed_repair::repair_managed_at(&home).await?;
    let action =
        crate::integrations::n8n::managed_runtime::managed_repair::completed_action_at(&home, &job)
            .map_err(anyhow::Error::msg)?;
    if job.state == crate::integrations::JobState::Ready && action.is_none() {
        return Err(anyhow!("n8n repair has no verified completion receipt"));
    }
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "job_id": job.job_id,
                "state": job.state,
                "operation": "repair",
                "action": action,
                "failure_code": job.failure.as_ref().map(|failure| &failure.code),
            })
        ),
        OutputFormat::Table => {
            println!("n8n repair job: {}", job.job_id);
            println!("state: {}", job.state);
            if let Some(action) = action {
                println!("action: {action}");
            }
            if let Some(failure) = &job.failure {
                println!("failure: {} — {}", failure.code, failure.redacted_message);
            }
        }
    }
    if let Some(failure) = &job.failure {
        return Err(anyhow!(
            "n8n repair job {} failed: {}",
            job.job_id,
            failure.code
        ));
    }
    if job.state != crate::integrations::JobState::Ready {
        return Err(anyhow!(
            "n8n repair job {} did not reach Ready (state: {})",
            job.job_id,
            job.state
        ));
    }
    Ok(())
}

async fn run_uninstall(output: OutputFormat) -> Result<()> {
    let home = crate::config::FreedomConfig::default_neoth_home();
    let job =
        crate::integrations::n8n::managed_runtime::managed_uninstall::uninstall_managed_at(&home)
            .await?;
    let disposition =
        crate::integrations::n8n::managed_runtime::managed_uninstall::disposition(&job);
    let cleanup =
        crate::integrations::n8n::managed_runtime::managed_uninstall::cleanup_disposition_at(
            &home, &job,
        )
        .ok()
        .flatten()
        .unwrap_or("unknown_or_preserved");
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "job_id": job.job_id,
                "operation": "uninstall",
                "state": job.state,
                "disposition": disposition,
                "config_cleanup": cleanup,
                "data_volume_policy": "retain",
                "failure_code": job.failure.as_ref().map(|failure| &failure.code),
            })
        ),
        OutputFormat::Table => {
            println!("n8n uninstall job: {}", job.job_id);
            println!("state: {}", job.state);
            println!("disposition: {disposition}");
            println!("configuration cleanup: {cleanup}");
            println!("data volume policy: retain");
            if let Some(failure) = &job.failure {
                println!("failure: {} — {}", failure.code, failure.redacted_message);
            }
        }
    }
    if job.state != crate::integrations::JobState::Ready {
        return Err(anyhow!(
            "n8n uninstall job {} requires reconciliation (state: {}, disposition: {})",
            job.job_id,
            job.state,
            disposition,
        ));
    }
    Ok(())
}

async fn run_purge(
    uninstall: &str,
    confirmation: Option<&str>,
    output: OutputFormat,
) -> Result<()> {
    use crate::integrations::n8n::managed_purge;

    let uninstall_id = JobId::parse(uninstall.to_owned())?;
    let home = crate::config::FreedomConfig::default_neoth_home();
    let Some(confirmation) = confirmation else {
        let plan = managed_purge::prepare_purge_at(&home, &uninstall_id)?;
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => println!(
                "{}",
                serde_json::json!({
                    "operation": "purge",
                    "state": "confirmation_required",
                    "uninstall_job_id": plan.uninstall_job_id,
                    "volume": plan.volume,
                    "confirmation": plan.confirmation,
                })
            ),
            OutputFormat::Table => {
                println!("Retained n8n data volume: {}", plan.volume);
                println!("Source uninstall job: {}", plan.uninstall_job_id);
                println!("Purge permanently deletes the workflows and data in this volume.");
                println!(
                    "To proceed, repeat this command with --confirm {:?}.",
                    plan.confirmation
                );
            }
        }
        return Ok(());
    };
    let job = managed_purge::purge_retained_volume_at(&home, &uninstall_id, confirmation).await?;
    let ready = job.state == crate::integrations::JobState::Ready;
    let disposition = if ready {
        "volume_removed"
    } else {
        "reconciliation_required"
    };
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "job_id": job.job_id,
                "operation": "purge",
                "state": job.state,
                "disposition": disposition,
                "uninstall_job_id": uninstall_id,
                "failure_code": job.failure.as_ref().map(|failure| &failure.code),
            })
        ),
        OutputFormat::Table => {
            println!("n8n purge job: {}", job.job_id);
            println!("state: {}", job.state);
            println!("disposition: {disposition}");
        }
    }
    if !ready {
        anyhow::bail!("n8n purge requires reconciliation; an uncertain deletion is not retried");
    }
    Ok(())
}

async fn run_import_workflows(output: OutputFormat) -> Result<()> {
    let job = crate::integrations::n8n::import_managed_workflows_at(
        &crate::config::FreedomConfig::default_neoth_home(),
    )
    .await?;
    render_import_job(&job, output)
}

fn render_import_job(
    job: &crate::integrations::IntegrationJob,
    output: OutputFormat,
) -> Result<()> {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "job_id": job.job_id,
                "state": job.state,
                "operation": "import_inactive_workflows",
                "failure_code": job.failure.as_ref().map(|failure| &failure.code),
            })
        ),
        OutputFormat::Table => {
            println!("n8n inactive-workflow import job: {}", job.job_id);
            println!("state: {}", job.state);
            if let Some(failure) = &job.failure {
                println!("failure: {} — {}", failure.code, failure.redacted_message);
            }
        }
    }
    if let Some(failure) = &job.failure {
        return Err(anyhow!(
            "n8n workflow import job {} failed: {}",
            job.job_id,
            failure.code
        ));
    }
    if job.state != crate::integrations::JobState::Ready {
        return Err(anyhow!(
            "n8n workflow import job {} did not reach Ready (state: {})",
            job.job_id,
            job.state
        ));
    }
    Ok(())
}

async fn run_install(
    port: Option<u16>,
    api_key_stdin: bool,
    bootstrap_owner: bool,
    reuse_uninstall: Option<&str>,
    output: OutputFormat,
) -> Result<()> {
    if !api_key_stdin && !bootstrap_owner {
        return Err(anyhow!(
            "n8n install requires exactly one of --api-key-stdin or --bootstrap-owner"
        ));
    }
    let port = port.unwrap_or(crate::installers::n8n::DEFAULT_N8N_PORT);
    if bootstrap_owner {
        let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel();
        let cancellation_task = tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                let _ = cancel_tx.send(());
            }
        });
        let result = crate::integrations::n8n::managed_bootstrap::install_bootstrap_at(
            &crate::config::FreedomConfig::default_neoth_home(),
            port,
            &mut cancel_rx,
        )
        .await;
        cancellation_task.abort();
        return render_managed_install_job(&result?, output);
    }
    if std::io::stdin().is_terminal() {
        return Err(anyhow!("--api-key-stdin requires piped standard input"));
    }
    let api_key = read_api_key_from_stdin().await?;
    let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel();
    let cancellation_task = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = cancel_tx.send(());
        }
    });
    let home = crate::config::FreedomConfig::default_neoth_home();
    let result = if let Some(value) = reuse_uninstall {
        let job_id = JobId::parse(value.to_owned()).map_err(anyhow::Error::msg)?;
        crate::integrations::n8n::managed_runtime::install_retained_at(
            &home,
            &job_id,
            api_key,
            &mut cancel_rx,
        )
        .await
    } else {
        let request = crate::integrations::n8n::managed_runtime::ManagedN8nRequest::new(
            port,
            crate::installers::n8n::N8N_OCI_REFERENCE,
        )
        .map_err(anyhow::Error::msg)?;
        crate::integrations::n8n::managed_runtime::install_managed_at(
            &home,
            request,
            api_key,
            &mut cancel_rx,
        )
        .await
    };
    cancellation_task.abort();
    render_managed_install_job(&result?, output)
}

fn render_managed_install_job(
    job: &crate::integrations::IntegrationJob,
    output: OutputFormat,
) -> Result<()> {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "job_id": job.job_id,
                "state": job.state,
                "probe_binding": "authenticated_n8n_workflows",
                "failure_code": job.failure.as_ref().map(|failure| &failure.code),
            })
        ),
        OutputFormat::Table => {
            println!("n8n managed install job: {}", job.job_id);
            println!("state: {}", job.state);
            println!("probe binding: authenticated n8n workflows API");
            if let Some(failure) = &job.failure {
                println!("failure: {} — {}", failure.code, failure.redacted_message);
            }
        }
    }
    if let Some(failure) = &job.failure {
        return Err(anyhow!(
            "n8n managed install job {} failed: {}",
            job.job_id,
            failure.code
        ));
    }
    if job.state != crate::integrations::JobState::Ready {
        return Err(anyhow!(
            "n8n managed install job {} did not reach Ready (state: {})",
            job.job_id,
            job.state
        ));
    }
    Ok(())
}

async fn run_adopt(endpoint: &str, api_key_stdin: bool, output: OutputFormat) -> Result<()> {
    let endpoint = LoopbackHttpEndpoint::parse(endpoint).map_err(anyhow::Error::msg)?;
    let home = crate::config::FreedomConfig::default_neoth_home();
    if !api_key_stdin {
        let service = crate::integrations::n8n::open_n8n_job_service(&home)?;
        let job = crate::integrations::n8n::enqueue_required_input_failure(
            &service,
            &endpoint,
            crate::integrations::JobRequester::Cli,
        )?;
        return render_adopt_job(&job, output);
    }
    if std::io::stdin().is_terminal() {
        return Err(anyhow!("--api-key-stdin requires piped standard input"));
    }
    let api_key = read_api_key_from_stdin().await?;
    let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel();
    let cancellation_task = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = cancel_tx.send(());
        }
    });
    let result =
        crate::integrations::n8n::adopt_at_with_cancel(&home, endpoint, api_key, &mut cancel_rx)
            .await;
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

fn read_api_key_line(reader: impl BufRead) -> Result<crate::secret::SecretString> {
    let mut input = zeroize::Zeroizing::new(Vec::new());
    reader
        .take(MAX_N8N_API_KEY_BYTES + 2)
        .read_until(b'\n', &mut input)
        .context("read bounded n8n API key from standard input")?;
    if input.last() == Some(&b'\n') {
        input.pop();
        if input.last() == Some(&b'\r') {
            input.pop();
        }
    }
    if input.len() > MAX_N8N_API_KEY_BYTES as usize {
        return Err(anyhow!("n8n API key input exceeds the bounded line length"));
    }
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
        return Err(anyhow!(
            "n8n API key input must be nonempty and contain no control characters"
        ));
    }
    Ok(key)
}

fn render_adopt_job(job: &crate::integrations::IntegrationJob, output: OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "job_id": job.job_id, "state": job.state, "failure_code": job.failure.as_ref().map(|failure| &failure.code),
            })
        ),
        OutputFormat::Table => {
            println!("n8n adoption job: {}", job.job_id);
            println!("state: {}", job.state);
            if let Some(failure) = &job.failure {
                println!("failure: {} — {}", failure.code, failure.redacted_message);
            }
        }
    }
    if let Some(failure) = &job.failure {
        return Err(anyhow!(
            "n8n adoption job {} failed: {}",
            job.job_id,
            failure.code
        ));
    }
    Ok(())
}

fn run_status(selected_job: Option<&str>, output: OutputFormat) -> Result<()> {
    let selected_job = selected_job
        .map(JobId::parse)
        .transpose()
        .map_err(anyhow::Error::msg)?;
    let view = crate::integrations::n8n::status_at(
        &crate::config::FreedomConfig::default_neoth_home(),
        selected_job.as_ref(),
    )?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!("{}", serde_json::to_string(&view)?),
        OutputFormat::Table => {
            println!(
                "configured endpoint: {}",
                view.configured_endpoint
                    .as_ref()
                    .map(LoopbackHttpEndpoint::as_str)
                    .unwrap_or("unconfigured")
            );
            println!(
                "API key: {}",
                if view.api_key_present {
                    "present"
                } else {
                    "absent"
                }
            );
            match &view.job {
                Some(job) => {
                    println!("job: {} ({})", job.id, job.state);
                    println!("operation: {}", job.operation.as_str());
                    if let Some(disposition) = job.disposition {
                        println!("disposition: {disposition}");
                    }
                    if let Some(cleanup) = job.config_cleanup {
                        println!("configuration cleanup: {cleanup}");
                    }
                    if let Some(receipt) = &job.backup {
                        print_backup_receipt(receipt)?;
                    }
                    if let Some(receipt) = &job.restore {
                        println!("restore candidate: validated retained volume");
                        println!("live n8n: unchanged");
                        println!("workflows validated: {}", receipt.workflow_count);
                        println!("credentials validated: {}", receipt.credential_count);
                        println!(
                            "credential decryption proven: {}",
                            receipt.credential_decryption_proven
                        );
                    }
                    println!("progress: {}/{}", job.completed_steps, job.total_steps);
                    if let Some(step) = &job.current_step {
                        println!("current step: {step}");
                    }
                    if let Some(code) = &job.failure_code {
                        println!("failure: {code}");
                    }
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
            for workflow in &workflows {
                println!(
                    "• {}  [{}]\n    {}",
                    workflow.name, workflow.slug, workflow.description
                );
            }
            println!(
                "\n{} workflow(s). Import into n8n; they POST to {NEOTH_HTTP_BASE}.",
                workflows.len()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn n8n_backup_cli_uses_owned_archive_and_runtime_without_overrides() {
        use clap::Parser;
        let cli = crate::cli::Cli::try_parse_from(["neoth", "n8n", "backup"]).unwrap();
        assert!(matches!(
            cli.command,
            crate::cli::Commands::N8n(N8nArgs {
                action: N8nAction::Backup,
            })
        ));
        for argument in [
            "--container",
            "--image",
            "--volume",
            "--output",
            "--destination",
            "--endpoint",
            "--job",
        ] {
            assert!(
                crate::cli::Cli::try_parse_from(["neoth", "n8n", "backup", argument, "unowned",])
                    .is_err()
            );
        }
        for argument in ["--follow-links", "--live", "--api-key-stdin"] {
            assert!(crate::cli::Cli::try_parse_from(["neoth", "n8n", "backup", argument]).is_err());
        }
    }

    #[test]
    fn n8n_restore_cli_accepts_only_a_canonical_backup_uuid_without_overrides() {
        use clap::Parser;

        let backup = uuid::Uuid::now_v7().to_string();
        let cli = crate::cli::Cli::try_parse_from([
            "neoth",
            "n8n",
            "restore",
            "--backup",
            backup.as_str(),
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            crate::cli::Commands::N8n(N8nArgs {
                action: N8nAction::Restore { backup: value },
            }) if value == backup
        ));
        assert!(crate::cli::Cli::try_parse_from(["neoth", "n8n", "restore"]).is_err());
        assert!(parse_restore_backup_id("not-a-uuid").is_err());
        assert!(parse_restore_backup_id("018f8a5a-6e7b-4000-8000-000000000000").is_err());
        for argument in [
            "--container",
            "--image",
            "--volume",
            "--path",
            "--port",
            "--endpoint",
            "--api-key-stdin",
        ] {
            assert!(
                crate::cli::Cli::try_parse_from([
                    "neoth",
                    "n8n",
                    "restore",
                    "--backup",
                    backup.as_str(),
                    argument,
                    "unowned",
                ])
                .is_err()
            );
        }
    }

    #[test]
    fn n8n_repair_cli_uses_stored_managed_identity_without_overrides() {
        use clap::Parser;
        let cli = crate::cli::Cli::try_parse_from(["neoth", "n8n", "repair"]).unwrap();
        assert!(matches!(
            cli.command,
            crate::cli::Commands::N8n(N8nArgs {
                action: N8nAction::Repair,
            })
        ));
        for argument in [
            "--container",
            "--image",
            "--port",
            "--volume",
            "--endpoint",
            "--job",
            "--reuse-uninstall",
        ] {
            assert!(
                crate::cli::Cli::try_parse_from(["neoth", "n8n", "repair", argument, "unowned",])
                    .is_err()
            );
        }
        for argument in ["--api-key-stdin", "--bootstrap-owner"] {
            assert!(
                crate::cli::Cli::try_parse_from(["neoth", "n8n", "repair", argument,]).is_err()
            );
        }
    }

    use super::*;

    #[test]
    fn uninstall_cli_retains_data_and_has_no_foreign_target_override() {
        use clap::Parser;
        let cli = crate::cli::Cli::try_parse_from(["neoth", "n8n", "uninstall"]).unwrap();
        assert!(matches!(
            cli.command,
            crate::cli::Commands::N8n(N8nArgs {
                action: N8nAction::Uninstall
            })
        ));
        for args in [
            vec!["--purge"],
            vec!["--volume", "foreign"],
            vec!["--container", "foreign"],
            vec!["--endpoint", "http://127.0.0.1:7777"],
        ] {
            assert!(
                crate::cli::Cli::try_parse_from(
                    ["neoth", "n8n", "uninstall"].into_iter().chain(args)
                )
                .is_err()
            );
        }
    }

    #[test]
    fn purge_cli_selects_only_an_uninstall_job_and_preserves_exact_confirmation() {
        use clap::Parser;
        let id = uuid::Uuid::now_v7().to_string();
        let preview =
            crate::cli::Cli::try_parse_from(["neoth", "n8n", "purge", "--uninstall", id.as_str()])
                .unwrap();
        assert!(matches!(preview.command,
            crate::cli::Commands::N8n(N8nArgs {
                action: N8nAction::Purge { uninstall, confirm: None },
            }) if uninstall == id
        ));
        let phrase = format!("PURGE N8N VOLUME {id} neoth_n8n_owned");
        let confirmed = crate::cli::Cli::try_parse_from([
            "neoth",
            "n8n",
            "purge",
            "--uninstall",
            id.as_str(),
            "--confirm",
            phrase.as_str(),
        ])
        .unwrap();
        assert!(matches!(confirmed.command,
            crate::cli::Commands::N8n(N8nArgs {
                action: N8nAction::Purge { uninstall, confirm: Some(value) },
            }) if uninstall == id && value == phrase
        ));
        assert!(crate::cli::Cli::try_parse_from(["neoth", "n8n", "purge"]).is_err());
        for argument in [
            "--volume",
            "--container",
            "--endpoint",
            "--home",
            "--yes",
            "--purge-data",
        ] {
            assert!(
                crate::cli::Cli::try_parse_from([
                    "neoth",
                    "n8n",
                    "purge",
                    "--uninstall",
                    id.as_str(),
                    argument,
                    "foreign",
                ])
                .is_err()
            );
        }
    }

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

    #[test]
    fn install_cli_requires_secret_stdin_and_keeps_port_typed() {
        use clap::Parser;
        let cli = crate::cli::Cli::try_parse_from([
            "neoth",
            "n8n",
            "install",
            "--port",
            "5679",
            "--api-key-stdin",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            crate::cli::Commands::N8n(N8nArgs {
                action: N8nAction::Install {
                    port: Some(5679),
                    api_key_stdin: true,
                    bootstrap_owner: false,
                    reuse_uninstall: None,
                }
            })
        ));
        assert!(
            crate::cli::Cli::try_parse_from([
                "neoth",
                "n8n",
                "install",
                "--api-key",
                "no-secret-argv"
            ])
            .is_err()
        );
        let bootstrap = crate::cli::Cli::try_parse_from([
            "neoth",
            "n8n",
            "install",
            "--bootstrap-owner",
            "--port",
            "5679",
        ])
        .unwrap();
        assert!(matches!(
            bootstrap.command,
            crate::cli::Commands::N8n(N8nArgs {
                action: N8nAction::Install {
                    port: Some(5679),
                    api_key_stdin: false,
                    bootstrap_owner: true,
                    reuse_uninstall: None,
                }
            })
        ));
        assert!(
            crate::cli::Cli::try_parse_from([
                "neoth",
                "n8n",
                "install",
                "--bootstrap-owner",
                "--api-key-stdin",
            ])
            .is_err()
        );
    }

    #[test]
    fn retained_reinstall_cli_requires_explicit_stdin_key_and_excludes_new_owner_options() {
        use clap::Parser;
        let uninstall = uuid::Uuid::now_v7().to_string();
        let cli = crate::cli::Cli::try_parse_from([
            "neoth",
            "n8n",
            "install",
            "--reuse-uninstall",
            uninstall.as_str(),
            "--api-key-stdin",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            crate::cli::Commands::N8n(N8nArgs {
                action: N8nAction::Install {
                    port: None,
                    api_key_stdin: true,
                    bootstrap_owner: false,
                    reuse_uninstall: Some(value),
                }
            }) if value == uninstall
        ));
        for args in [
            vec![
                "--reuse-uninstall",
                uninstall.as_str(),
                "--port",
                "5679",
                "--api-key-stdin",
            ],
            vec!["--reuse-uninstall", uninstall.as_str(), "--bootstrap-owner"],
        ] {
            assert!(
                crate::cli::Cli::try_parse_from(
                    ["neoth", "n8n", "install"].into_iter().chain(args)
                )
                .is_err()
            );
        }
    }

    #[test]
    fn import_workflows_cli_has_no_hidden_execution_options() {
        use clap::Parser;
        let cli = crate::cli::Cli::try_parse_from(["neoth", "n8n", "import-workflows"]).unwrap();
        assert!(matches!(
            cli.command,
            crate::cli::Commands::N8n(N8nArgs {
                action: N8nAction::ImportWorkflows
            })
        ));
        assert!(
            crate::cli::Cli::try_parse_from([
                "neoth",
                "n8n",
                "import-workflows",
                "--endpoint",
                "http://127.0.0.1:5678"
            ])
            .is_err()
        );
    }
}
