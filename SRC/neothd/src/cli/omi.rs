//! Operator controls for the complete OMI conversation runtime.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use sha2::{Digest, Sha256};

use crate::cli::OutputFormat;
use crate::config::credentials::Credentials;
use crate::config::{FreedomConfig, OmiIngestMode, SecretsBackend};
use crate::secret::SecretString;
use crate::wal::events::{EVENT_TYPE_EXTENDED, ExtendedSubtype};
use crate::wal::writer::WalWriterHandle;

static OMI_OPERATOR_AUDIT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Args, Debug, Clone)]
pub struct OmiArgs {
    #[command(subcommand)]
    pub action: OmiAction,

    /// Override the NEOTH home containing freedom.yaml, credentials.yaml, and views.db.
    #[arg(long, global = true, value_name = "DIR")]
    pub home: Option<PathBuf>,

    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum OmiAction {
    /// Show configuration validity, credentials posture, ledger counts, and halt state.
    Status,
    /// Probe configured local OMI endpoints without contacting a public cloud API.
    Probe,
    /// Read a bounded JSON credential update from stdin. Secret values never enter argv.
    SetCredentials,
    /// Permanently delete one conversation and every local derivative (privacy deletion wins over audit failure).
    Purge {
        conversation_id: String,
        /// Confirm the privacy deletion and durable anti-reimport tombstone.
        #[arg(long)]
        yes: bool,
    },
    /// Resume an SC-18-halted stream after a durable operator intent and documented review.
    Resume {
        /// Short review evidence retained with the last sanitizer finding set.
        #[arg(long, value_name = "NOTE")]
        review_note: String,
    },
    /// Apply the configured OMI retention window immediately (privacy deletion wins over audit failure).
    EnforceRetention,
    /// Remove stale recovery state and a purge tombstone after a durable operator intent.
    AllowReimport {
        conversation_id: String,
        /// Confirm that the remote source may restore previously deleted data.
        #[arg(long)]
        yes: bool,
    },
}

struct OmiContext {
    home: PathBuf,
    config: FreedomConfig,
    credentials: Credentials,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OmiCredentialUpdate {
    #[serde(default)]
    pub(crate) developer_api_key: Option<SecretString>,
    #[serde(default)]
    pub(crate) native_ingest_token: Option<SecretString>,
}

impl OmiCredentialUpdate {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.developer_api_key.is_none() && self.native_ingest_token.is_none() {
            bail!("OMI credential update contains no fields");
        }
        if let Some(key) = self
            .developer_api_key
            .as_ref()
            .map(SecretString::expose_secret)
            && (!key.starts_with("omi_dev_") || key.len() == "omi_dev_".len() || key.trim() != key)
        {
            bail!("OMI Developer key must be a trimmed non-empty omi_dev_* value");
        }
        if let Some(token) = self
            .native_ingest_token
            .as_ref()
            .map(SecretString::expose_secret)
            && (token.len() < 32 || token.trim() != token)
        {
            bail!("OMI native token must be trimmed and contain at least 32 bytes");
        }
        Ok(())
    }

    fn updated_field_names(&self) -> Vec<&'static str> {
        let mut fields = Vec::with_capacity(2);
        if self.developer_api_key.is_some() {
            fields.push("omi_developer_api_key");
        }
        if self.native_ingest_token.is_some() {
            fields.push("omi_ingest_token");
        }
        fields
    }
}

impl OmiContext {
    fn load(home: Option<PathBuf>) -> Result<Self> {
        let home = home.unwrap_or_else(FreedomConfig::default_neoth_home);
        let config_path = home.join("freedom.yaml");
        let config = FreedomConfig::load_from_path(&config_path)
            .with_context(|| format!("load OMI config from {}", config_path.display()))?;
        let credentials_path = home.join("credentials.yaml");
        let credentials = Credentials::load_effective(&credentials_path, config.secrets_backend)
            .with_context(|| {
                format!(
                    "load effective OMI credentials from {}",
                    credentials_path.display()
                )
            })?;
        Ok(Self {
            home,
            config,
            credentials,
        })
    }

    fn db_path(&self) -> PathBuf {
        self.home.join("views.db")
    }
}

#[derive(Clone, Copy)]
enum OperatorAuditContract {
    /// Safety boundaries may not be lowered until the intent frame is durable.
    FailClosedBeforeMutation,
    /// Privacy deletion proceeds even when audit storage is unavailable. The
    /// command then returns an explicit "committed without complete audit"
    /// error rather than silently extending data retention.
    PrivacyDeletionWins,
}

impl OperatorAuditContract {
    const fn as_str(self) -> &'static str {
        match self {
            Self::FailClosedBeforeMutation => "fail_closed_before_mutation",
            Self::PrivacyDeletionWins => "privacy_deletion_wins",
        }
    }
}

struct OperatorAudit {
    writer: WalWriterHandle,
    join: tokio::task::JoinHandle<()>,
}

impl OperatorAudit {
    fn start(home: &Path) -> Result<Self> {
        let wal_dir = home.join("wal");
        std::fs::create_dir_all(&wal_dir)
            .with_context(|| format!("create OMI operator WAL dir {}", wal_dir.display()))?;
        let sequence = OMI_OPERATOR_AUDIT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let segment = wal_dir.join(format!(
            "omi-operator-{}-{}-{sequence}.wal",
            crate::time::now_unix_ns(),
            std::process::id(),
        ));
        let (writer, join) = crate::wal::writer::spawn(segment)
            .context("spawn dedicated OMI operator WAL writer")?;
        Ok(Self { writer, join })
    }

    async fn emit(
        &self,
        phase: &'static str,
        operation: &'static str,
        contract: OperatorAuditContract,
        conversation_id: Option<&str>,
        review_note: Option<&str>,
        result: Option<serde_json::Value>,
    ) -> Result<()> {
        let payload = operator_audit_payload(
            phase,
            operation,
            contract,
            conversation_id,
            review_note,
            result,
        )?;
        let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
            .event_subtype(ExtendedSubtype::OmiLifecycleAudit as u8)
            .build();
        self.writer
            .append(header, payload)
            .await
            .context("durably append OMI operator audit frame")?;
        Ok(())
    }

    async fn finish(self) -> Result<()> {
        drop(self.writer);
        self.join.await.context("join OMI operator WAL writer")?;
        Ok(())
    }
}

fn operator_audit_payload(
    phase: &'static str,
    operation: &'static str,
    contract: OperatorAuditContract,
    conversation_id: Option<&str>,
    review_note: Option<&str>,
    result: Option<serde_json::Value>,
) -> Result<Vec<u8>> {
    let hash = |value: &str| hex::encode(Sha256::digest(value.as_bytes()));
    serde_json::to_vec(&serde_json::json!({
        "phase": phase,
        "operation": operation,
        "source": "omi_cli",
        "scope": "omi_operator",
        "audit_contract": contract.as_str(),
        "conversation_hash": conversation_id.map(hash),
        "review_note_hash": review_note.map(hash),
        "result": result,
        "ts_unix": crate::time::now_unix_secs(),
    }))
    .context("encode OMI operator audit frame")
}

struct PrivacyDeletionAudit {
    audit: Option<OperatorAudit>,
    failure: Option<String>,
}

impl PrivacyDeletionAudit {
    async fn begin(home: &Path, operation: &'static str, conversation_id: Option<&str>) -> Self {
        match OperatorAudit::start(home) {
            Ok(audit) => match audit
                .emit(
                    "operator_intent",
                    operation,
                    OperatorAuditContract::PrivacyDeletionWins,
                    conversation_id,
                    None,
                    None,
                )
                .await
            {
                Ok(()) => Self {
                    audit: Some(audit),
                    failure: None,
                },
                Err(error) => {
                    let _ = audit.finish().await;
                    Self {
                        audit: None,
                        failure: Some(error.to_string()),
                    }
                }
            },
            Err(error) => Self {
                audit: None,
                failure: Some(error.to_string()),
            },
        }
    }

    async fn complete(
        mut self,
        operation: &'static str,
        conversation_id: Option<&str>,
        result: serde_json::Value,
    ) -> Result<()> {
        if let Some(audit) = self.audit.take() {
            if let Err(error) = audit
                .emit(
                    "operator_result",
                    operation,
                    OperatorAuditContract::PrivacyDeletionWins,
                    conversation_id,
                    None,
                    Some(result),
                )
                .await
            {
                self.failure = Some(error.to_string());
            }
            if let Err(error) = audit.finish().await {
                self.failure.get_or_insert_with(|| error.to_string());
            }
        }
        if let Some(error) = self.failure {
            bail!(
                "OMI {operation} committed under privacy_deletion_wins, but its operator audit is incomplete: {error}"
            );
        }
        Ok(())
    }

    async fn record_failed_attempt(
        mut self,
        operation: &'static str,
        conversation_id: Option<&str>,
    ) {
        if let Some(audit) = self.audit.take() {
            let _ = audit
                .emit(
                    "operator_result",
                    operation,
                    OperatorAuditContract::PrivacyDeletionWins,
                    conversation_id,
                    None,
                    Some(serde_json::json!({ "success": false, "committed": false })),
                )
                .await;
            let _ = audit.finish().await;
        }
    }
}

fn native_daemon_pidfile(home: &Path) -> PathBuf {
    home.join("neothd.pid")
}

pub(crate) fn effective_omi_runtime_state(
    enabled: bool,
    status: &crate::memory::omi::OmiStatus,
    live_daemon_pid: Option<u32>,
) -> String {
    if !enabled {
        return "disabled".to_string();
    }
    let Some(live_pid) = live_daemon_pid else {
        return "inactive".to_string();
    };
    if status.runtime_pid != Some(live_pid) {
        return "unknown".to_string();
    }
    status
        .runtime_state
        .clone()
        .unwrap_or_else(|| "unknown".to_string())
}

fn native_mutation_requires_stopped_daemon(home: &Path, conversation_id: &str) -> Result<()> {
    if conversation_id.starts_with("native:") {
        let live = crate::daemon::pidfile::live_daemon_pid(&native_daemon_pidfile(home))
            .context("verify that the daemon is stopped before native OMI mutation")?;
        if live.is_some() {
            bail!(
                "native OMI mutation requires the daemon to be stopped so in-memory call data cannot recreate a removed receipt"
            );
        }
    }
    Ok(())
}

fn mode_name(mode: OmiIngestMode) -> &'static str {
    match mode {
        OmiIngestMode::DeveloperApi => "developer_api",
        OmiIngestMode::NativeIngest => "native_ingest",
        OmiIngestMode::Both => "both",
        OmiIngestMode::LegacyMemories => "legacy_memories",
    }
}

fn open_views(path: &Path) -> Result<rusqlite::Connection> {
    crate::memory::store::open(path)
        .with_context(|| format!("open OMI ledger at {}", path.display()))
}

fn read_status(path: &Path) -> Result<Option<crate::memory::omi::OmiStatus>> {
    if !path.exists() {
        return Ok(None);
    }
    let flags =
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = rusqlite::Connection::open_with_flags(path, flags)
        .with_context(|| format!("open OMI ledger read-only at {}", path.display()))?;
    crate::memory::omi::status(&conn)
        .map(Some)
        .context("read OMI ledger status; run `neoth migrate` or start the daemon")
}

fn read_omi_credential_update() -> Result<OmiCredentialUpdate> {
    const MAX_STDIN_BYTES: u64 = 8 * 1024;
    let mut body = zeroize::Zeroizing::new(Vec::new());
    std::io::stdin()
        .lock()
        .take(MAX_STDIN_BYTES + 1)
        .read_to_end(&mut body)
        .context("read OMI credential update from stdin")?;
    if body.len() as u64 > MAX_STDIN_BYTES {
        bail!("OMI credential update exceeds {MAX_STDIN_BYTES} bytes");
    }
    let update: OmiCredentialUpdate =
        serde_json::from_slice(&body).context("parse OMI credential update JSON from stdin")?;
    update.validate()?;
    Ok(update)
}

fn rollback_omi_keychain_updates(
    store: &dyn crate::config::keychain::SecretStore,
    applied: &[(&'static str, Option<SecretString>)],
) -> Vec<String> {
    let mut failures = Vec::new();
    for (key, previous) in applied.iter().rev() {
        let result = match previous {
            Some(previous) => store.set(key, previous),
            None => store.delete(key),
        };
        if let Err(error) = result {
            failures.push(format!("{key}: {error:#}"));
        }
    }
    failures
}

fn persist_omi_keychain_update(
    credentials_path: &Path,
    store: &dyn crate::config::keychain::SecretStore,
    update: &OmiCredentialUpdate,
) -> Result<()> {
    let mut requested = Vec::with_capacity(2);
    if let Some(value) = update.developer_api_key.as_ref() {
        requested.push(("omi_developer_api_key", value.clone()));
    }
    if let Some(value) = update.native_ingest_token.as_ref() {
        requested.push(("omi_ingest_token", value.clone()));
    }

    let mut applied = Vec::with_capacity(requested.len());
    for (key, value) in &requested {
        let previous = store
            .get(key)
            .with_context(|| format!("read existing {key} from {}", store.backend_name()))?;
        if let Err(error) = store.set(key, value) {
            let rollback = rollback_omi_keychain_updates(store, &applied);
            if rollback.is_empty() {
                return Err(error).with_context(|| {
                    format!(
                        "write {key} to {}; prior updates rolled back",
                        store.backend_name()
                    )
                });
            }
            bail!(
                "write {key} to {} failed ({error:#}); rollback also failed: {}",
                store.backend_name(),
                rollback.join("; ")
            );
        }
        applied.push((*key, previous));
    }

    // File values intentionally override keychain values. Clear only the two
    // updated OMI fields after the store writes succeed, otherwise an old
    // emergency-file value would silently mask the newly stored credential.
    if let Err(error) = Credentials::update_at(credentials_path, |credentials| {
        if update.developer_api_key.is_some() {
            credentials.omi_developer_api_key = None;
        }
        if update.native_ingest_token.is_some() {
            credentials.omi_ingest_token = None;
        }
        Ok(())
    }) {
        let rollback = rollback_omi_keychain_updates(store, &applied);
        if rollback.is_empty() {
            return Err(error).context(
                "clear OMI emergency-file overrides after keychain update; keychain rolled back",
            );
        }
        bail!(
            "clear OMI emergency-file overrides failed ({error:#}); keychain rollback also failed: {}",
            rollback.join("; ")
        );
    }
    Ok(())
}

pub(crate) fn persist_omi_credential_update(
    home: &Path,
    backend: SecretsBackend,
    update: &OmiCredentialUpdate,
) -> Result<()> {
    let path = home.join("credentials.yaml");
    match backend {
        SecretsBackend::File => Credentials::update_at(&path, |credentials| {
            if let Some(value) = update.developer_api_key.as_ref() {
                credentials.omi_developer_api_key = Some(value.clone());
            }
            if let Some(value) = update.native_ingest_token.as_ref() {
                credentials.omi_ingest_token = Some(value.clone());
            }
            Ok(())
        })
        .context("merge OMI credentials into the encrypted/private credential file"),
        SecretsBackend::Keychain => {
            let store = crate::config::keychain::open_store()
                .context("open configured OS keychain for OMI credential update")?;
            persist_omi_keychain_update(&path, store.as_ref(), update)
        }
    }
}

fn print_credential_update(
    output: OutputFormat,
    backend: SecretsBackend,
    updated_fields: &[&str],
) -> Result<()> {
    let backend = match backend {
        SecretsBackend::File => "file",
        SecretsBackend::Keychain => "keychain",
    };
    match output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "updated_fields": updated_fields,
                "backend": backend,
            }))?
        ),
        OutputFormat::Jsonl => println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "updated_fields": updated_fields,
                "backend": backend,
            }))?
        ),
        OutputFormat::Table => println!(
            "Updated OMI credential field(s) in {backend}: {} (values hidden)",
            updated_fields.join(", ")
        ),
    }
    Ok(())
}

fn require_confirmation(confirmed: bool, operation: &str) -> Result<()> {
    if !confirmed {
        bail!("{operation} requires --yes");
    }
    Ok(())
}

fn print_outcome(
    output: OutputFormat,
    operation: &str,
    source_id: Option<&str>,
    outcome: crate::memory::omi::OmiPurgeOutcome,
) -> Result<()> {
    let value = serde_json::json!({
        "operation": operation,
        "conversation_id": source_id,
        "conversations": outcome.conversations,
        "segments": outcome.segments,
        "media": outcome.media,
        "actions": outcome.actions,
        "tasks": outcome.tasks,
        "groundtruth": outcome.groundtruth,
    });
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&value)?),
        OutputFormat::Jsonl => println!("{}", serde_json::to_string(&value)?),
        OutputFormat::Table => {
            if let Some(source_id) = source_id {
                println!("OMI {operation}: {source_id}");
            } else {
                println!("OMI {operation}");
            }
            println!(
                "conversations={} segments={} media={} actions={} tasks={} groundtruth={}",
                outcome.conversations,
                outcome.segments,
                outcome.media,
                outcome.actions,
                outcome.tasks,
                outcome.groundtruth,
            );
        }
    }
    Ok(())
}

fn print_status(context: &OmiContext, output: OutputFormat) -> Result<()> {
    let validation_error = context
        .config
        .omi
        .validate_with_credentials(&context.credentials)
        .err();
    let status = read_status(&context.db_path())?;
    let ledger_initialized = status.is_some();
    let status = status.unwrap_or_default();
    let daemon_pid = crate::daemon::pidfile::live_daemon_pid(&native_daemon_pidfile(&context.home))
        .context("read OMI daemon PID state")?;
    let effective_runtime_state =
        effective_omi_runtime_state(context.config.omi.enabled, &status, daemon_pid);
    let value = serde_json::json!({
        "enabled": context.config.omi.enabled,
        "mode": mode_name(context.config.omi.mode),
        "configuration_valid": validation_error.is_none(),
        "configuration_error": validation_error.as_deref(),
        "developer_api_credential_present": context.credentials.omi_developer_api_key.is_some(),
        "native_ingest_credential_present": context.credentials.omi_ingest_token.is_some(),
        "endpoint": context.config.omi.endpoint.as_str(),
        "listen_addr": context.config.omi.listen_addr.as_str(),
        "retention_days": context.config.omi.retention_days,
        "poll_interval_secs": context.config.omi.poll_interval_secs,
        "retain_transcripts": context.config.omi.retain_transcripts,
        "audio_enabled": context.config.omi.audio_enabled,
        "visual_enabled": context.config.omi.visual_enabled,
        "video_enabled": context.config.omi.video_enabled,
        "allow_cloud_api": context.config.omi.allow_cloud_api,
        "allow_cloud_summary": context.config.omi.allow_cloud_summary,
        "create_actions": context.config.omi.create_actions,
        "seed_groundtruth": context.config.omi.seed_groundtruth,
        "summary_enabled": context.config.omi.summary_enabled,
        "ledger_initialized": ledger_initialized,
        "conversations": status.conversations,
        "segments": status.segments,
        "media": status.media,
        "actions": status.actions,
        "tombstones": status.tombstones,
        "pending_audits": status.pending_audits,
        "runtime_state": effective_runtime_state,
        "runtime_persisted_state": status.runtime_state.as_deref(),
        "runtime_detail": status.runtime_detail.as_deref(),
        "runtime_pid": status.runtime_pid,
        "runtime_updated_ns": status.runtime_updated_ts,
        "daemon_pid": daemon_pid,
        "sanitizer_halted": status.sanitizer_halted,
        "last_success_ns": status.last_success_ts,
        "last_error": status.last_error.as_deref(),
        "last_retention_purge_ns": status.last_retention_purge_ts,
        "last_retention_error": status.last_retention_error.as_deref(),
    });

    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&value)?),
        OutputFormat::Jsonl => println!("{}", serde_json::to_string(&value)?),
        OutputFormat::Table => {
            println!(
                "OMI: {} / {} / config {}",
                if context.config.omi.enabled {
                    "enabled"
                } else {
                    "disabled"
                },
                mode_name(context.config.omi.mode),
                if validation_error.is_none() {
                    "valid"
                } else {
                    "INVALID"
                }
            );
            if let Some(error) = validation_error {
                println!("configuration error: {error}");
            }
            if ledger_initialized {
                println!(
                    "ledger: conversations={} segments={} media={} actions={} tombstones={} pending_audits={}",
                    status.conversations,
                    status.segments,
                    status.media,
                    status.actions,
                    status.tombstones,
                    status.pending_audits,
                );
            } else {
                println!("ledger: not initialized (start neoth serve)");
            }
            println!(
                "privacy: retention={}d retain_transcripts={} audio={} images={} video={}",
                context.config.omi.retention_days,
                context.config.omi.retain_transcripts,
                context.config.omi.audio_enabled,
                context.config.omi.visual_enabled,
                context.config.omi.video_enabled,
            );
            println!(
                "sanitizer: {}",
                if !ledger_initialized {
                    "not initialized"
                } else if status.sanitizer_halted {
                    "HALTED"
                } else {
                    "ready"
                }
            );
            println!(
                "runtime: {}{}",
                effective_runtime_state,
                status
                    .runtime_detail
                    .as_deref()
                    .map(|detail| format!(" ({detail})"))
                    .unwrap_or_default()
            );
            if let Some(error) = status.last_error {
                println!("last error: {error}");
            }
            if let Some(error) = status.last_retention_error {
                println!("retention error: {error}");
            }
        }
    }
    Ok(())
}

async fn print_probe(context: &OmiContext, output: OutputFormat) -> Result<()> {
    let local_endpoint = if context.config.omi.mode.polls()
        && crate::installers::omi::is_local_endpoint(&context.config.omi.endpoint).is_ok()
    {
        Some(
            crate::installers::omi::probe_endpoint(&context.config.omi.endpoint)
                .await
                .as_str(),
        )
    } else {
        None
    };
    let native_listener = if context.config.omi.mode.listens() {
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::net::TcpStream::connect(&context.config.omi.listen_addr),
        )
        .await;
        Some(match outcome {
            Ok(Ok(_)) => "reachable",
            Ok(Err(_)) => "port_closed",
            Err(_) => "timeout",
        })
    } else {
        None
    };
    let public_api_probe = if context.config.omi.mode.polls()
        && crate::installers::omi::is_local_endpoint(&context.config.omi.endpoint).is_err()
    {
        Some("not_probed_auth_required")
    } else {
        None
    };
    let value = serde_json::json!({
        "mode": mode_name(context.config.omi.mode),
        "local_endpoint": local_endpoint,
        "native_listener": native_listener,
        "public_api": public_api_probe,
    });
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&value)?),
        OutputFormat::Jsonl => println!("{}", serde_json::to_string(&value)?),
        OutputFormat::Table => {
            println!("OMI probe ({})", mode_name(context.config.omi.mode));
            if let Some(outcome) = local_endpoint {
                println!("local endpoint: {outcome}");
            }
            if let Some(outcome) = native_listener {
                println!("native listener: {outcome}");
            }
            if let Some(outcome) = public_api_probe {
                println!("public Developer API: {outcome}");
            }
        }
    }
    Ok(())
}

pub async fn run_omi(args: OmiArgs) -> Result<()> {
    if matches!(&args.action, OmiAction::SetCredentials) {
        let home = args
            .home
            .clone()
            .unwrap_or_else(FreedomConfig::default_neoth_home);
        let config_path = home.join("freedom.yaml");
        let backend = if config_path.exists() {
            FreedomConfig::load_from_path(&config_path)
                .with_context(|| format!("load OMI config from {}", config_path.display()))?
                .secrets_backend
        } else {
            SecretsBackend::File
        };
        let update = read_omi_credential_update()?;
        let updated_fields = update.updated_field_names();
        persist_omi_credential_update(&home, backend, &update)?;
        return print_credential_update(args.output, backend, &updated_fields);
    }
    let context = OmiContext::load(args.home)?;
    match args.action {
        OmiAction::Status => print_status(&context, args.output),
        OmiAction::Probe => print_probe(&context, args.output).await,
        OmiAction::SetCredentials => unreachable!("handled before OMI context load"),
        OmiAction::Purge {
            conversation_id,
            yes,
        } => {
            require_confirmation(yes, "OMI purge")?;
            native_mutation_requires_stopped_daemon(&context.home, &conversation_id)?;
            let audit =
                PrivacyDeletionAudit::begin(&context.home, "purge", Some(&conversation_id)).await;
            let mut conn = match open_views(&context.db_path()) {
                Ok(conn) => conn,
                Err(error) => {
                    audit
                        .record_failed_attempt("purge", Some(&conversation_id))
                        .await;
                    return Err(error);
                }
            };
            let outcome = match crate::memory::omi::purge_conversation(
                &mut conn,
                &conversation_id,
                crate::time::now_unix_ns(),
            ) {
                Ok(outcome) => outcome,
                Err(error) => {
                    audit
                        .record_failed_attempt("purge", Some(&conversation_id))
                        .await;
                    return Err(error);
                }
            };
            let journal_cleanup = crate::daemon::omi_native_ingest::purge_native_journal_for_source(
                &context.home,
                &conversation_id,
            );
            let audit_result = audit
                .complete(
                    "purge",
                    Some(&conversation_id),
                    serde_json::json!({
                        "success": journal_cleanup.is_ok(),
                        "committed": true,
                        "journal_removed": journal_cleanup.as_ref().copied().ok(),
                        "conversations": outcome.conversations,
                        "segments": outcome.segments,
                        "media": outcome.media,
                        "actions": outcome.actions,
                        "tasks": outcome.tasks,
                        "groundtruth": outcome.groundtruth,
                    }),
                )
                .await;
            if let Err(error) = journal_cleanup {
                if let Err(audit_error) = audit_result {
                    bail!(
                        "OMI purge database deletion committed, but native receipt cleanup failed: {error:#}; {audit_error:#}"
                    );
                }
                return Err(error).context(
                    "OMI purge database deletion committed, but native receipt cleanup failed",
                );
            }
            audit_result?;
            print_outcome(args.output, "purge", Some(&conversation_id), outcome)
        }
        OmiAction::Resume { review_note } => {
            let audit = OperatorAudit::start(&context.home)?;
            audit
                .emit(
                    "operator_intent",
                    "resume",
                    OperatorAuditContract::FailClosedBeforeMutation,
                    None,
                    Some(&review_note),
                    None,
                )
                .await?;
            let resumed = match crate::daemon::omi_ingest_task::resume_sanitizer(
                &context.db_path(),
                &review_note,
            )
            .await
            {
                Ok(resumed) => resumed,
                Err(error) => {
                    let _ = audit
                        .emit(
                            "operator_result",
                            "resume",
                            OperatorAuditContract::FailClosedBeforeMutation,
                            None,
                            Some(&review_note),
                            Some(serde_json::json!({ "success": false, "committed": false })),
                        )
                        .await;
                    let _ = audit.finish().await;
                    return Err(error);
                }
            };
            if let Err(error) = audit
                .emit(
                    "operator_result",
                    "resume",
                    OperatorAuditContract::FailClosedBeforeMutation,
                    None,
                    Some(&review_note),
                    Some(serde_json::json!({ "success": true, "resumed": resumed })),
                )
                .await
            {
                let _ = audit.finish().await;
                bail!("OMI resume committed, but its result audit failed: {error:#}");
            }
            audit.finish().await?;
            let value = serde_json::json!({
                "operation": "resume",
                "resumed": resumed,
                "review_evidence_retained": resumed,
            });
            match args.output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&value)?),
                OutputFormat::Jsonl => println!("{}", serde_json::to_string(&value)?),
                OutputFormat::Table => println!(
                    "OMI sanitizer: {}",
                    if resumed { "resumed" } else { "not halted" }
                ),
            }
            Ok(())
        }
        OmiAction::EnforceRetention => {
            let audit = PrivacyDeletionAudit::begin(&context.home, "enforce_retention", None).await;
            let outcome = match crate::daemon::omi_ingest_task::enforce_retention_once(
                &context.db_path(),
                context.config.omi.retention_days,
            )
            .await
            {
                Ok(outcome) => outcome,
                Err(error) => {
                    // `enforce_retention_once` commits its SQLite deletion before
                    // removing filesystem receipts. Report that partial boundary
                    // explicitly; never imply that a retry can restore data.
                    let audit_result = audit
                        .complete(
                            "enforce_retention",
                            None,
                            serde_json::json!({
                                "success": false,
                                "database_deletion_may_be_committed": true,
                            }),
                        )
                        .await;
                    if let Err(audit_error) = audit_result {
                        bail!(
                            "OMI retention may have committed its database deletion before failing: {error:#}; {audit_error:#}"
                        );
                    }
                    return Err(error).context(
                        "OMI retention may have committed its database deletion before receipt cleanup failed",
                    );
                }
            };
            audit
                .complete(
                    "enforce_retention",
                    None,
                    serde_json::json!({
                        "success": true,
                        "committed": true,
                        "conversations": outcome.conversations,
                        "segments": outcome.segments,
                        "media": outcome.media,
                        "actions": outcome.actions,
                        "tasks": outcome.tasks,
                        "groundtruth": outcome.groundtruth,
                    }),
                )
                .await?;
            print_outcome(args.output, "retention", None, outcome)
        }
        OmiAction::AllowReimport {
            conversation_id,
            yes,
        } => {
            require_confirmation(yes, "OMI allow-reimport")?;
            native_mutation_requires_stopped_daemon(&context.home, &conversation_id)?;
            let audit = OperatorAudit::start(&context.home)?;
            audit
                .emit(
                    "operator_intent",
                    "allow_reimport",
                    OperatorAuditContract::FailClosedBeforeMutation,
                    Some(&conversation_id),
                    None,
                    None,
                )
                .await?;
            let journal_removed =
                match crate::daemon::omi_native_ingest::purge_native_journal_for_source(
                    &context.home,
                    &conversation_id,
                ) {
                    Ok(removed) => removed,
                    Err(error) => {
                        let _ = audit
                            .emit(
                                "operator_result",
                                "allow_reimport",
                                OperatorAuditContract::FailClosedBeforeMutation,
                                Some(&conversation_id),
                                None,
                                Some(serde_json::json!({ "success": false, "committed": false })),
                            )
                            .await;
                        let _ = audit.finish().await;
                        return Err(error).context(
                            "remove stale native OMI receipt before clearing the tombstone",
                        );
                    }
                };
            let conn = match open_views(&context.db_path()) {
                Ok(conn) => conn,
                Err(error) => {
                    let _ = audit
                        .emit(
                            "operator_result",
                            "allow_reimport",
                            OperatorAuditContract::FailClosedBeforeMutation,
                            Some(&conversation_id),
                            None,
                            Some(serde_json::json!({
                                "success": false,
                                "stale_native_receipt_removed": journal_removed,
                                "tombstone_cleared": false,
                            })),
                        )
                        .await;
                    let _ = audit.finish().await;
                    return Err(error);
                }
            };
            let cleared = match crate::memory::omi::clear_tombstone(&conn, &conversation_id) {
                Ok(cleared) => cleared,
                Err(error) => {
                    let _ = audit
                        .emit(
                            "operator_result",
                            "allow_reimport",
                            OperatorAuditContract::FailClosedBeforeMutation,
                            Some(&conversation_id),
                            None,
                            Some(serde_json::json!({
                                "success": false,
                                "stale_native_receipt_removed": journal_removed,
                                "tombstone_cleared": false,
                            })),
                        )
                        .await;
                    let _ = audit.finish().await;
                    return Err(error);
                }
            };
            if let Err(error) = audit
                .emit(
                    "operator_result",
                    "allow_reimport",
                    OperatorAuditContract::FailClosedBeforeMutation,
                    Some(&conversation_id),
                    None,
                    Some(serde_json::json!({
                        "success": true,
                        "tombstone_cleared": cleared,
                        "stale_native_receipt_removed": journal_removed,
                        "reconciliation_state_cleared": true,
                    })),
                )
                .await
            {
                let _ = audit.finish().await;
                bail!("OMI allow-reimport committed, but its result audit failed: {error:#}");
            }
            audit.finish().await?;
            let value = serde_json::json!({
                "operation": "allow_reimport",
                "conversation_id": conversation_id.as_str(),
                "tombstone_cleared": cleared,
                "stale_native_receipt_removed": journal_removed,
                "reconciliation_state_cleared": true,
            });
            match args.output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&value)?),
                OutputFormat::Jsonl => println!("{}", serde_json::to_string(&value)?),
                OutputFormat::Table => println!(
                    "OMI allow-reimport: {} ({})",
                    conversation_id,
                    if cleared {
                        "tombstone cleared"
                    } else {
                        "no tombstone"
                    }
                ),
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::keychain::SecretStore as _;

    fn credential_update(developer: Option<&str>, native: Option<&str>) -> OmiCredentialUpdate {
        OmiCredentialUpdate {
            developer_api_key: developer.map(SecretString::from),
            native_ingest_token: native.map(SecretString::from),
        }
    }

    #[test]
    fn credential_update_validation_is_strict_and_names_only() {
        assert!(credential_update(None, None).validate().is_err());
        assert!(
            credential_update(Some("omi_dev_"), None)
                .validate()
                .is_err()
        );
        assert!(credential_update(None, Some("short")).validate().is_err());
        let valid = credential_update(
            Some("omi_dev_replacement"),
            Some("0123456789abcdef0123456789abcdef"),
        );
        valid.validate().unwrap();
        assert_eq!(
            valid.updated_field_names(),
            vec!["omi_developer_api_key", "omi_ingest_token"]
        );
    }

    #[test]
    fn file_credential_update_preserves_every_unrelated_secret() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("credentials.yaml");
        let existing = Credentials {
            provider_key: Some(SecretString::from("provider-stays")),
            telegram_token: Some(SecretString::from("telegram-stays")),
            omi_developer_api_key: Some(SecretString::from("omi_dev_old")),
            ..Default::default()
        };
        existing.write(&path).unwrap();
        let update = credential_update(
            Some("omi_dev_replacement"),
            Some("0123456789abcdef0123456789abcdef"),
        );
        persist_omi_credential_update(home.path(), SecretsBackend::File, &update).unwrap();

        let loaded = Credentials::load_or_default(&path).unwrap();
        assert_eq!(
            loaded.provider_key.as_ref().unwrap().expose(),
            "provider-stays"
        );
        assert_eq!(
            loaded.telegram_token.as_ref().unwrap().expose(),
            "telegram-stays"
        );
        assert_eq!(
            loaded.omi_developer_api_key.as_ref().unwrap().expose(),
            "omi_dev_replacement"
        );
        assert_eq!(
            loaded.omi_ingest_token.as_ref().unwrap().expose(),
            "0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn keychain_update_clears_masking_file_values_and_preserves_other_fields() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("credentials.yaml");
        let existing = Credentials {
            provider_key: Some(SecretString::from("provider-stays")),
            omi_developer_api_key: Some(SecretString::from("omi_dev_file_override")),
            omi_ingest_token: Some(SecretString::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")),
            ..Default::default()
        };
        existing.write(&path).unwrap();
        let store = crate::config::keychain::InMemorySecretStore::default();
        store
            .set(
                "omi_developer_api_key",
                &SecretString::from("omi_dev_old_store"),
            )
            .unwrap();
        let update = credential_update(
            Some("omi_dev_new_store"),
            Some("0123456789abcdef0123456789abcdef"),
        );

        persist_omi_keychain_update(&path, &store, &update).unwrap();

        let file = Credentials::load_or_default(&path).unwrap();
        assert_eq!(
            file.provider_key.as_ref().unwrap().expose(),
            "provider-stays"
        );
        assert!(file.omi_developer_api_key.is_none());
        assert!(file.omi_ingest_token.is_none());
        assert_eq!(
            store
                .get("omi_developer_api_key")
                .unwrap()
                .unwrap()
                .expose(),
            "omi_dev_new_store"
        );
        assert_eq!(
            store.get("omi_ingest_token").unwrap().unwrap().expose(),
            "0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn confirmation_is_fail_closed() {
        assert!(require_confirmation(false, "OMI purge").is_err());
        assert!(require_confirmation(true, "OMI purge").is_ok());
    }

    #[test]
    fn every_ingest_mode_has_a_stable_operator_name() {
        assert_eq!(mode_name(OmiIngestMode::DeveloperApi), "developer_api");
        assert_eq!(mode_name(OmiIngestMode::NativeIngest), "native_ingest");
        assert_eq!(mode_name(OmiIngestMode::Both), "both");
        assert_eq!(mode_name(OmiIngestMode::LegacyMemories), "legacy_memories");
    }

    #[test]
    fn status_does_not_create_a_missing_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("views.db");

        assert_eq!(read_status(&path).unwrap(), None);
        assert!(!path.exists());
    }

    #[test]
    fn effective_runtime_health_rejects_stale_or_missing_daemon_state() {
        let mut status = crate::memory::omi::OmiStatus {
            runtime_state: Some("healthy".to_string()),
            runtime_pid: Some(42),
            ..Default::default()
        };
        assert_eq!(
            effective_omi_runtime_state(false, &status, None),
            "disabled"
        );
        assert_eq!(effective_omi_runtime_state(true, &status, None), "inactive");
        assert_eq!(
            effective_omi_runtime_state(true, &status, Some(41)),
            "unknown"
        );
        assert_eq!(
            effective_omi_runtime_state(true, &status, Some(42)),
            "healthy"
        );
        status.runtime_state = Some("failed".to_string());
        assert_eq!(
            effective_omi_runtime_state(true, &status, Some(42)),
            "failed"
        );
    }

    #[test]
    fn native_mutation_uses_the_explicit_home_pidfile() {
        let custom_home = tempfile::tempdir().unwrap();
        let custom_pidfile = native_daemon_pidfile(custom_home.path());
        assert_eq!(custom_pidfile, custom_home.path().join("neothd.pid"));
        assert_ne!(
            custom_pidfile,
            crate::daemon::pidfile::default_pidfile(),
            "--home must never fall back to the default daemon lock"
        );

        std::fs::write(&custom_pidfile, std::process::id().to_string()).unwrap();
        assert!(
            native_mutation_requires_stopped_daemon(custom_home.path(), "native:call-1").is_err(),
            "the live PID in the custom home must block native mutation"
        );
        assert!(
            native_mutation_requires_stopped_daemon(custom_home.path(), "developer-call-1").is_ok(),
            "non-native sources do not own a local recovery receipt"
        );
    }

    #[test]
    fn operator_audit_hashes_external_identifiers_and_documents_contract() {
        let payload = operator_audit_payload(
            "operator_intent",
            "allow_reimport",
            OperatorAuditContract::FailClosedBeforeMutation,
            Some("native:private-call"),
            Some("review contains private details"),
            None,
        )
        .unwrap();
        let payload = String::from_utf8(payload).unwrap();
        assert!(payload.contains("fail_closed_before_mutation"));
        assert!(payload.contains("conversation_hash"));
        assert!(payload.contains("review_note_hash"));
        assert!(!payload.contains("private-call"));
        assert!(!payload.contains("review contains private details"));
    }

    #[tokio::test]
    async fn operator_audit_uses_a_dedicated_durable_wal_segment() {
        let home = tempfile::tempdir().unwrap();
        let audit = OperatorAudit::start(home.path()).unwrap();
        audit
            .emit(
                "operator_intent",
                "resume",
                OperatorAuditContract::FailClosedBeforeMutation,
                None,
                Some("reviewed"),
                None,
            )
            .await
            .unwrap();
        audit.finish().await.unwrap();

        let segments: Vec<_> = std::fs::read_dir(home.path().join("wal"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(segments.len(), 1);
        assert!(
            segments[0]
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("omi-operator-")
        );
        assert!(std::fs::metadata(&segments[0]).unwrap().len() > 0);
    }
}
