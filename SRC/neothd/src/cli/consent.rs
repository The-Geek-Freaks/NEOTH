//! `neoth consent` — manage first-run outbound-LLM consent (V03-08).
//!
//! Subcommands: `list`, `grant <provider>`, `revoke <provider>`. The chat +
//! serve paths gate cloud-bound provider calls behind a recorded consent
//! marker so the operator's text never reaches a third-party until they
//! explicitly opt in.
//!
//! Consent state lives under `~/.neoth/consent/<provider_kind>.granted`.
//! Fixed-vendor markers are provider-wide. Configurable OpenAI,
//! OpenAI-compatible, Azure, and remote Ollama routes record canonical origins
//! in their marker. Operators can audit via this CLI.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::Serialize;
use serde_json::json;

use crate::cli::OutputFormat;
use crate::cli::consent_challenge::{
    ChatConsentDecision, ConsentCommandSource, verify_gui_mutation_binding,
};
use crate::cli::consent_outbox::ConsentMutationAction;
pub(crate) use crate::cli::consent_outbox::ConsentMutationSource;
use crate::cli::init::ProviderKind;
use crate::config::FreedomConfig;
use crate::consent;
use crate::wal::events::EVENT_TYPE_CONSENT_DECISION;

const CONSENT_PROVIDER_KINDS: [ProviderKind; 11] = [
    ProviderKind::ClaudeCli,
    ProviderKind::OpenaiApi,
    ProviderKind::AnthropicApi,
    ProviderKind::GeminiApi,
    ProviderKind::Cohere,
    ProviderKind::OpenaiCompat,
    ProviderKind::LocalOllama,
    ProviderKind::AwsBedrock,
    ProviderKind::AzureOpenAi,
    ProviderKind::GitHubCopilot,
    ProviderKind::RecursiveMas,
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ConsentStatusRow {
    pub(crate) provider: &'static str,
    pub(crate) consent_required: bool,
    pub(crate) current_route_granted: bool,
    pub(crate) configured_endpoint_origins: Vec<String>,
    pub(crate) granted_endpoint_origins: Vec<String>,
    pub(crate) endpoint_origins: Vec<String>,
    pub(crate) stale_endpoint_origins: Vec<String>,
    pub(crate) granted_unix_ts: Option<String>,
    pub(crate) grantable: bool,
    pub(crate) revokable: bool,
    pub(crate) granted: bool,
    pub(crate) status: &'static str,
    pub(crate) audit_pending: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConsentChangeReceipt {
    pub(crate) provider: ProviderKind,
    pub(crate) was_granted: bool,
    pub(crate) changed: bool,
    pub(crate) status: ConsentMutationStatus,
    pub(crate) configured_endpoint_origins: Vec<String>,
    pub(crate) endpoint_origins: Vec<String>,
    pub(crate) added_endpoint_origins: Vec<String>,
    pub(crate) removed_endpoint_origins: Vec<String>,
    pub(crate) endpoint_delta_known: bool,
    pub(crate) marker_source_malformed: bool,
    pub(crate) audit_pending: bool,
    pub(crate) operation_id: Option<String>,
    pub(crate) authority_persisted: bool,
    pub(crate) failure: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConsentMutationStatus {
    Applied,
    CommittedButBindingStale,
}

impl ConsentMutationStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::CommittedButBindingStale => "committed_but_binding_stale",
        }
    }
}

#[derive(Args, Debug, Clone)]
pub struct ConsentArgs {
    #[command(subcommand)]
    pub action: ConsentAction,

    /// Output format (inherited from global --output flag).
    #[clap(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ConsentAction {
    /// List recorded consent grants under `~/.neoth/consent/`.
    List,
    /// Show consent state for a single provider.
    Show {
        #[arg(value_enum)]
        provider: ProviderKind,
    },
    /// Record consent for the provider's configured remote egress routes.
    Grant {
        #[arg(value_enum)]
        provider: ProviderKind,
        /// Private caller provenance for the desktop GUI bridge.
        #[arg(long, hide = true, value_enum, default_value = "cli")]
        source: ConsentCommandSource,
        /// Exact freedom.yaml generation observed by GUI preflight.
        #[arg(long, hide = true)]
        expected_config_sha256: Option<String>,
        /// Exact canonical required-route generation observed by GUI preflight.
        #[arg(long, hide = true)]
        expected_route_set_sha256: Option<String>,
    },
    /// Remove a previously recorded consent grant.
    Revoke {
        #[arg(value_enum)]
        provider: ProviderKind,
        /// Private caller provenance for the desktop GUI bridge.
        #[arg(long, hide = true, value_enum, default_value = "cli")]
        source: ConsentCommandSource,
        /// Exact freedom.yaml generation observed by GUI preflight.
        #[arg(long, hide = true)]
        expected_config_sha256: Option<String>,
        /// Exact canonical required-route generation observed by GUI preflight.
        #[arg(long, hide = true)]
        expected_route_set_sha256: Option<String>,
    },
    /// Private GUI preflight for a config- and route-bound chat challenge.
    #[command(name = "preflight-chat", hide = true)]
    PreflightChat {
        #[arg(long, value_enum)]
        source: ConsentCommandSource,
    },
    /// Private read-only config/route binding for GUI grant and revoke.
    #[command(name = "mutation-binding", hide = true)]
    MutationBinding {
        #[arg(long, value_enum)]
        source: ConsentCommandSource,
    },
    /// Private GUI decision endpoint. The challenge secret is read from stdin.
    #[command(name = "decide-chat", hide = true)]
    DecideChat {
        #[arg(long)]
        challenge_id: String,
        #[arg(long, value_enum)]
        decision: ChatConsentDecision,
        #[arg(long, value_enum)]
        source: ConsentCommandSource,
    },
}

pub async fn run_consent(args: ConsentArgs) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    match args.action {
        ConsentAction::List => render_list(&home, args.output),
        ConsentAction::Show { provider } => render_show(&home, provider, args.output),
        ConsentAction::Grant {
            provider,
            source,
            expected_config_sha256,
            expected_route_set_sha256,
        } => {
            render_grant(
                &home,
                provider,
                args.output,
                source,
                expected_config_sha256.as_deref(),
                expected_route_set_sha256.as_deref(),
            )
            .await
        }
        ConsentAction::Revoke {
            provider,
            source,
            expected_config_sha256,
            expected_route_set_sha256,
        } => {
            render_revoke(
                &home,
                provider,
                args.output,
                source,
                expected_config_sha256.as_deref(),
                expected_route_set_sha256.as_deref(),
            )
            .await
        }
        ConsentAction::PreflightChat { source } => {
            crate::cli::consent_challenge::render_preflight_chat(&home, source, args.output).await
        }
        ConsentAction::MutationBinding { source } => {
            crate::cli::consent_challenge::render_mutation_binding(&home, source, args.output)
        }
        ConsentAction::DecideChat {
            challenge_id,
            decision,
            source,
        } => {
            crate::cli::consent_challenge::render_decide_chat(
                &home,
                &challenge_id,
                decision,
                source,
                args.output,
            )
            .await
        }
    }
}

fn daemon_is_live(home: &std::path::Path) -> bool {
    let pidfile = home.join("neothd.pid");
    matches!(
        crate::daemon::pidfile::live_daemon_pid(&pidfile),
        Ok(Some(_))
    )
}

pub(crate) async fn emit_consent_decision(
    home: &std::path::Path,
    route: &consent::ConsentRoute,
    decision: consent::ConsentDecision,
    source: ConsentMutationSource,
) -> Result<()> {
    let payload = consent::consent_decision_payload(
        route,
        decision,
        source.as_str(),
        crate::time::now_unix_i64(),
    )?;

    if daemon_is_live(home) {
        crate::daemon::audit_rpc::try_post_audit_frame(home, EVENT_TYPE_CONSENT_DECISION, &payload)
            .await
            .context("daemon audit-RPC did not acknowledge consent decision")?;
        return Ok(());
    }

    let wal_dir = home.join("wal");
    std::fs::create_dir_all(&wal_dir).with_context(|| {
        format!(
            "create consent-decision WAL directory {}",
            wal_dir.display()
        )
    })?;
    let segment = crate::wal::writer::unique_standalone_segment_path(&wal_dir, "consent-decision");
    let (writer, join) = crate::wal::writer::spawn_for_home(segment.clone(), home.to_path_buf())
        .with_context(|| {
            format!(
                "spawn standalone consent-decision WAL {}",
                segment.display()
            )
        })?;
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_CONSENT_DECISION, &payload).build();
    let append_result = writer.append(header, payload).await;
    drop(writer);
    let join_result = join.await;
    append_result.with_context(|| {
        format!(
            "standalone consent-decision WAL append was not acknowledged in {}",
            segment.display()
        )
    })?;
    join_result.with_context(|| {
        format!(
            "standalone consent-decision WAL writer task failed for {}",
            segment.display()
        )
    })?;
    Ok(())
}

pub(crate) fn consent_status_rows(
    home: &std::path::Path,
    config: Option<&FreedomConfig>,
) -> Result<Vec<ConsentStatusRow>> {
    use std::collections::BTreeSet;

    let configured_routes = config
        .map(consent::required_consent_routes)
        .unwrap_or_default();
    let mut rows = Vec::new();

    for provider in CONSENT_PROVIDER_KINDS {
        let provider_routes: Vec<_> = configured_routes
            .iter()
            .filter(|route| route.kind == provider)
            .collect();
        let configured_endpoint_origins: Vec<String> = provider_routes
            .iter()
            .map(|route| consent::route_endpoint_origin(route))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();
        let marker_exists = consent::marker_path(home, provider).exists();
        let inventory = consent::list_route_grants_for_kind(home, provider);
        if inventory.is_err() && !marker_exists && provider_routes.is_empty() {
            continue;
        }
        let (grants, mut error) = match inventory {
            Ok(grants) => (grants, None),
            Err(error) => (
                Vec::new(),
                Some(crate::security::redact::redact_text(&format!("{error:#}"))),
            ),
        };
        let audit_pending = match crate::cli::consent_outbox::has_pending_audit(home, provider) {
            Ok(pending) => pending,
            Err(audit_error) => {
                let audit_error = crate::security::redact::redact_text(&format!("{audit_error:#}"));
                error = Some(match error {
                    Some(existing) => format!("{existing}; {audit_error}"),
                    None => audit_error,
                });
                true
            }
        };
        if grants.is_empty() && !marker_exists && provider_routes.is_empty() {
            continue;
        }

        let granted_endpoint_origins: Vec<String> = grants
            .iter()
            .filter_map(|grant| grant.endpoint_origin.clone())
            .collect();
        let configured_set: BTreeSet<_> = configured_endpoint_origins.iter().cloned().collect();
        let stale_endpoint_origins = granted_endpoint_origins
            .iter()
            .filter(|origin| !configured_set.contains(*origin))
            .cloned()
            .collect();
        let consent_required = !provider_routes.is_empty();
        let current_route_granted = error.is_none()
            && consent_required
            && provider_routes
                .iter()
                .all(|route| consent::is_route_granted(home, route));
        let revokable = marker_exists;
        let status = if error.is_some() {
            "invalid"
        } else if current_route_granted {
            "granted"
        } else if consent_required {
            "pending"
        } else if revokable {
            "stale"
        } else {
            "not_required"
        };
        rows.push(ConsentStatusRow {
            provider: consent::slug(provider),
            consent_required,
            current_route_granted,
            configured_endpoint_origins,
            endpoint_origins: granted_endpoint_origins.clone(),
            granted_endpoint_origins,
            stale_endpoint_origins,
            granted_unix_ts: grants
                .iter()
                .map(|grant| grant.granted_unix_ts.clone())
                .max(),
            grantable: consent_required && !current_route_granted && error.is_none(),
            revokable,
            granted: current_route_granted,
            status,
            audit_pending,
            error,
        });
    }
    Ok(rows)
}

fn render_list(home: &std::path::Path, output: OutputFormat) -> Result<()> {
    let config_path = home.join("freedom.yaml");
    let config = if config_path.exists() {
        Some(
            FreedomConfig::load_from_path(&config_path)
                .context("load freedom.yaml for current consent-route status")?,
        )
    } else {
        None
    };
    let rows = consent_status_rows(home, config.as_ref())?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
        OutputFormat::Table => {
            if rows.is_empty() {
                println!("No consent grants recorded.");
                println!();
                println!("Cloud providers require one-time consent before NEOTH routes");
                println!("any text to them. Run `neoth consent grant <provider>` to grant.");
                return Ok(());
            }
            println!("{:<18}  {:<12}  routes", "provider", "status");
            println!("{}  {}  {}", "-".repeat(18), "-".repeat(12), "-".repeat(60));
            for row in rows {
                let mut details = Vec::new();
                if !row.configured_endpoint_origins.is_empty() {
                    details.push(format!(
                        "configured={}",
                        row.configured_endpoint_origins.join(",")
                    ));
                }
                if !row.granted_endpoint_origins.is_empty() {
                    details.push(format!(
                        "granted={}",
                        row.granted_endpoint_origins.join(",")
                    ));
                }
                if !row.stale_endpoint_origins.is_empty() {
                    details.push(format!("stale={}", row.stale_endpoint_origins.join(",")));
                }
                if row.audit_pending {
                    details.push("audit=pending".to_string());
                }
                if let Some(error) = row.error {
                    details.push(format!("error={error}"));
                }
                println!(
                    "{:<18}  {:<12}  {}",
                    row.provider,
                    row.status,
                    details.join(" ")
                );
            }
        }
    }
    Ok(())
}

fn render_show(home: &std::path::Path, provider: ProviderKind, output: OutputFormat) -> Result<()> {
    let slug_s = consent::slug(provider);
    let grants = consent::list_route_grants_for_kind(home, provider)?;
    let config_path = home.join("freedom.yaml");
    let configured_routes = if config_path.exists() {
        consent::required_consent_routes(
            &FreedomConfig::load_from_path(&config_path)
                .context("load freedom.yaml for current consent-route status")?,
        )
        .into_iter()
        .filter(|route| route.kind == provider)
        .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let configured_endpoint_origins = configured_routes
        .iter()
        .map(consent::route_endpoint_origin)
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let current_route_granted = !configured_routes.is_empty()
        && configured_routes
            .iter()
            .all(|route| consent::is_route_granted(home, route));
    let stale_endpoint_origins = grants
        .iter()
        .filter_map(|grant| grant.endpoint_origin.clone())
        .filter(|origin| !configured_endpoint_origins.contains(origin))
        .collect::<Vec<_>>();
    let recorded = !grants.is_empty();
    let is_cloud = consent::is_cloud(provider);
    let is_endpoint_conditional = provider == ProviderKind::LocalOllama;
    let is_endpoint_bound = consent::uses_endpoint_bound_consent(provider);
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let routes: Vec<_> = grants
                .iter()
                .map(|grant| {
                    json!({
                        "endpoint_origin": grant.endpoint_origin,
                        "granted_unix_ts": grant.granted_unix_ts,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "provider": slug_s,
                    "is_cloud": is_cloud,
                    "is_endpoint_conditional": is_endpoint_conditional,
                    "is_endpoint_bound": is_endpoint_bound,
                    "consent_required": !configured_routes.is_empty(),
                    "current_route_granted": current_route_granted,
                    "granted": current_route_granted,
                    "configured_endpoint_origins": configured_endpoint_origins,
                    "stale_endpoint_origins": stale_endpoint_origins,
                    "marker_path": consent::marker_path(home, provider).display().to_string(),
                    "routes": routes,
                }))?
            );
        }
        OutputFormat::Table => {
            if is_endpoint_bound {
                if is_endpoint_conditional {
                    println!(
                        "{slug_s}: endpoint-dependent — loopback needs no consent; LAN/DNS/public endpoints do."
                    );
                } else {
                    println!(
                        "{slug_s}: exact-origin consent required for every configured endpoint."
                    );
                }
                if recorded {
                    println!(
                        "current configured route: {}",
                        if current_route_granted {
                            "GRANTED"
                        } else {
                            "NOT GRANTED"
                        }
                    );
                    println!("recorded endpoint grants:");
                    for grant in grants {
                        println!(
                            "  {}  granted_unix_ts={}",
                            grant.endpoint_origin.as_deref().unwrap_or("<invalid>"),
                            grant.granted_unix_ts
                        );
                    }
                    println!("marker: {}", consent::marker_path(home, provider).display());
                } else {
                    println!("endpoint consent: NOT GRANTED");
                    println!("configure the route, then run `neoth consent grant {slug_s}`.");
                }
                return Ok(());
            }
            if !is_cloud {
                println!("{slug_s}: not a cloud provider — no consent required.");
                return Ok(());
            }
            if recorded {
                println!(
                    "{slug_s}: {}",
                    if current_route_granted || configured_routes.is_empty() {
                        "GRANTED"
                    } else {
                        "STALE (not granted for the current configuration)"
                    }
                );
                println!("marker: {}", consent::marker_path(home, provider).display());
            } else {
                println!("{slug_s}: NOT GRANTED");
                println!("run `neoth consent grant {slug_s}` to record consent.");
            }
        }
    }
    Ok(())
}

async fn render_grant(
    home: &std::path::Path,
    provider: ProviderKind,
    output: OutputFormat,
    source: ConsentCommandSource,
    expected_config_sha256: Option<&str>,
    expected_route_set_sha256: Option<&str>,
) -> Result<()> {
    let receipt = change_consent_for_command(
        home,
        provider,
        true,
        source,
        expected_config_sha256,
        expected_route_set_sha256,
    )
    .await?;
    let slug_s = consent::slug(receipt.provider);
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let routes: Vec<_> = receipt
                .endpoint_origins
                .iter()
                .map(|origin| {
                    json!({
                        "endpoint_origin": origin,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "provider": slug_s,
                    "action": if receipt.changed { "granted" } else { "noop" },
                    "status": receipt.status.as_str(),
                    "marker_path": consent::marker_path(home, provider).display().to_string(),
                    "configured_endpoint_origins": receipt.configured_endpoint_origins,
                    "endpoint_origins": receipt.endpoint_origins,
                    "added_endpoint_origins": receipt.added_endpoint_origins,
                    "removed_endpoint_origins": receipt.removed_endpoint_origins,
                    "endpoint_delta_known": receipt.endpoint_delta_known,
                    "marker_source_malformed": receipt.marker_source_malformed,
                    "audit_pending": receipt.audit_pending,
                    "operation_id": receipt.operation_id,
                    "authority_persisted": receipt.authority_persisted,
                    "failure": receipt.failure,
                    "config_sha256": expected_config_sha256,
                    "route_set_sha256": expected_route_set_sha256,
                    "routes": routes,
                }))?
            );
        }
        OutputFormat::Table => {
            if receipt.changed {
                println!("✓ consent granted for `{slug_s}`.");
            } else {
                println!("`{slug_s}` already had consent for every configured route.");
            }
            for origin in receipt.endpoint_origins {
                println!("endpoint: {origin}");
            }
            if receipt.audit_pending {
                println!("audit: queued for durable retry");
            }
            if receipt.status == ConsentMutationStatus::CommittedButBindingStale {
                println!("binding: changed after commit; refresh consent state before continuing");
            }
            println!("marker: {}", consent::marker_path(home, provider).display());
        }
    }
    Ok(())
}

async fn render_revoke(
    home: &std::path::Path,
    provider: ProviderKind,
    output: OutputFormat,
    source: ConsentCommandSource,
    expected_config_sha256: Option<&str>,
    expected_route_set_sha256: Option<&str>,
) -> Result<()> {
    let receipt = change_consent_for_command(
        home,
        provider,
        false,
        source,
        expected_config_sha256,
        expected_route_set_sha256,
    )
    .await?;
    let slug_s = consent::slug(receipt.provider);
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "provider": slug_s,
                    "action": if receipt.changed { "revoked" } else { "noop" },
                    "status": receipt.status.as_str(),
                    "configured_endpoint_origins": receipt.configured_endpoint_origins,
                    "endpoint_origins": receipt.endpoint_origins,
                    "added_endpoint_origins": receipt.added_endpoint_origins,
                    "removed_endpoint_origins": receipt.removed_endpoint_origins,
                    "endpoint_delta_known": receipt.endpoint_delta_known,
                    "marker_source_malformed": receipt.marker_source_malformed,
                    "audit_pending": receipt.audit_pending,
                    "operation_id": receipt.operation_id,
                    "authority_persisted": receipt.authority_persisted,
                    "failure": receipt.failure,
                    "config_sha256": expected_config_sha256,
                    "route_set_sha256": expected_route_set_sha256,
                }))?
            );
        }
        OutputFormat::Table => {
            if receipt.changed {
                println!("✓ consent revoked for `{slug_s}`.");
                println!(
                    "next chat against `{slug_s}` will re-prompt (or bail in non-interactive contexts)."
                );
            } else {
                println!("`{slug_s}` had no consent grant — nothing to revoke.");
            }
            if receipt.audit_pending {
                println!("audit: queued for durable retry");
            }
            if receipt.status == ConsentMutationStatus::CommittedButBindingStale {
                println!("binding: changed after commit; refresh consent state before continuing");
            }
        }
    }
    Ok(())
}

async fn change_consent_for_command(
    home: &std::path::Path,
    provider: ProviderKind,
    grant: bool,
    source: ConsentCommandSource,
    expected_config_sha256: Option<&str>,
    expected_route_set_sha256: Option<&str>,
) -> Result<ConsentChangeReceipt> {
    match source {
        ConsentCommandSource::Cli => {
            anyhow::ensure!(
                expected_config_sha256.is_none() && expected_route_set_sha256.is_none(),
                "expected GUI consent bindings require `--source gui`"
            );
            change_consent_at(home, provider, grant).await
        }
        ConsentCommandSource::Gui => {
            if !grant {
                // Revocation only removes authority. Keep it available from
                // the GUI even when freedom.yaml is missing/corrupt and a
                // config-bound mutation preflight therefore cannot exist.
                anyhow::ensure!(
                    expected_config_sha256.is_none() && expected_route_set_sha256.is_none(),
                    "GUI consent revoke is deliberately unbound; omit expected config hashes"
                );
                return change_consent_at_with_source(
                    home,
                    provider,
                    false,
                    source.mutation_source(),
                )
                .await;
            }
            let expected_config_sha256 = expected_config_sha256
                .context("GUI consent mutation requires --expected-config-sha256")?;
            let expected_route_set_sha256 = expected_route_set_sha256
                .context("GUI consent mutation requires --expected-route-set-sha256")?;
            let config = verify_gui_mutation_binding(
                home,
                expected_config_sha256,
                expected_route_set_sha256,
            )?;
            change_consent_with_config_at_inner(
                home,
                provider,
                grant,
                &config,
                source.mutation_source(),
                Some(GuiMutationBinding {
                    home,
                    config_sha256: expected_config_sha256,
                    route_set_sha256: expected_route_set_sha256,
                }),
            )
            .await
        }
    }
}

#[derive(Clone, Copy)]
struct GuiMutationBinding<'a> {
    home: &'a std::path::Path,
    config_sha256: &'a str,
    route_set_sha256: &'a str,
}

impl GuiMutationBinding<'_> {
    fn verify(self) -> Result<()> {
        verify_gui_mutation_binding(self.home, self.config_sha256, self.route_set_sha256)
            .map(|_| ())
    }
}

/// Canonical consent mutation for CLI, slash, and GUI surfaces. Required-audit
/// posture is enforced before touching the marker; a real mutation receives
/// the same WAL event regardless of caller.
pub(crate) async fn change_consent_at(
    home: &std::path::Path,
    provider: ProviderKind,
    grant: bool,
) -> Result<ConsentChangeReceipt> {
    change_consent_at_with_source(home, provider, grant, ConsentMutationSource::Cli).await
}

async fn change_consent_at_with_source(
    home: &std::path::Path,
    provider: ProviderKind,
    grant: bool,
    source: ConsentMutationSource,
) -> Result<ConsentChangeReceipt> {
    let config_path = home.join("freedom.yaml");
    let config = match FreedomConfig::load_from_path(&config_path) {
        Ok(config) => config,
        Err(error) if grant => {
            return Err(error).context("load freedom.yaml before consent grant");
        }
        Err(error) => {
            // Revocation is an emergency fail-safe and must remain available
            // when configuration is missing or corrupt. Preserve the stricter
            // audit posture because the unavailable file cannot prove that
            // optional audit was intended.
            tracing::warn!(
                path = %config_path.display(),
                error = %crate::security::redact::redact_text(&format!("{error:#}")),
                "freedom.yaml unavailable during consent revoke; using required audit and no configured routes"
            );
            let mut fallback = FreedomConfig::default();
            fallback.audit_rpc.required_for_oneshot_permission_events = true;
            fallback
        }
    };
    change_consent_with_config_at(home, provider, grant, &config, source).await
}

pub(crate) async fn change_consent_with_config_at(
    home: &std::path::Path,
    provider: ProviderKind,
    grant: bool,
    config: &FreedomConfig,
    source: ConsentMutationSource,
) -> Result<ConsentChangeReceipt> {
    change_consent_with_config_at_inner(home, provider, grant, config, source, None).await
}

async fn change_consent_with_config_at_inner(
    home: &std::path::Path,
    provider: ProviderKind,
    grant: bool,
    config: &FreedomConfig,
    source: ConsentMutationSource,
    gui_binding: Option<GuiMutationBinding<'_>>,
) -> Result<ConsentChangeReceipt> {
    if grant {
        recover_pending_before_grant(home).await?;
    }
    if grant && !consent::is_consent_managed_kind(provider) {
        anyhow::bail!(
            "provider `{}` has no remote-egress consent marker",
            consent::slug(provider)
        );
    }
    let configured_routes: Vec<_> = consent::required_consent_routes(config)
        .into_iter()
        .filter(|route| route.kind == provider)
        .collect();
    let configured_endpoint_origins = configured_routes
        .iter()
        .map(consent::route_endpoint_origin)
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let routes = if grant {
        if provider == ProviderKind::LocalOllama && configured_routes.is_empty() {
            anyhow::bail!(
                "no configured remote Ollama endpoint requires consent; loopback Ollama is already local and marker-free"
            );
        }
        if matches!(
            provider,
            ProviderKind::OpenaiCompat | ProviderKind::AzureOpenAi
        ) && configured_routes.is_empty()
        {
            anyhow::bail!(
                "no configured `{}` endpoint exists; configure the exact route before granting consent",
                consent::slug(provider)
            );
        }
        if configured_routes.is_empty() {
            vec![consent::ConsentRoute::new(provider, None)]
        } else {
            configured_routes
        }
    } else {
        Vec::new()
    };
    let update = if grant {
        consent::prepare_grant_routes(home, &routes)?
    } else {
        consent::prepare_revoke_kind(home, provider)?
    };
    apply_prepared_consent_update(
        home,
        provider,
        grant,
        config,
        source,
        configured_endpoint_origins,
        update,
        gui_binding,
    )
    .await
}

async fn recover_pending_before_grant(home: &std::path::Path) -> Result<()> {
    if let crate::cli::consent_outbox::RecoveryOutcome::Recovered {
        operation_id,
        delivery,
        ..
    } = crate::cli::consent_outbox::recover_pending(home)
        .await
        .context("recover pending consent mutation before granting more authority")?
        && delivery.is_pending()
        && crate::cli::consent_outbox::blocks_new_grant(home)?
    {
        anyhow::bail!(
            "pending consent audit operation {operation_id} could not be delivered; \
             retry after the audit path is available"
        );
    }
    Ok(())
}

/// Grant only the exact routes covered by one already-audited decision.
///
/// Unlike the provider-wide CLI grant, this never widens to other configured
/// routes of the same provider. GUI challenge batches use it so a concurrent
/// revoke cannot be silently restored by a decision that covered a different
/// missing endpoint.
pub(crate) async fn grant_exact_routes_with_config_at(
    home: &std::path::Path,
    provider: ProviderKind,
    routes: &[consent::ConsentRoute],
    config: &FreedomConfig,
    source: ConsentMutationSource,
) -> Result<ConsentChangeReceipt> {
    anyhow::ensure!(
        consent::is_consent_managed_kind(provider),
        "provider `{}` has no remote-egress consent marker",
        consent::slug(provider)
    );
    anyhow::ensure!(
        !routes.is_empty()
            && routes.iter().all(|route| {
                route.kind == provider
                    && consent::route_requires_consent(route.kind, route.endpoint.as_deref())
            }),
        "exact consent grant for `{}` requires at least one matching remote route",
        consent::slug(provider)
    );
    recover_pending_before_grant(home).await?;
    let configured_endpoint_origins = routes
        .iter()
        .map(consent::route_endpoint_origin)
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();
    let update = consent::prepare_grant_routes(home, routes)?;
    apply_prepared_consent_update(
        home,
        provider,
        true,
        config,
        source,
        configured_endpoint_origins,
        update,
        None,
    )
    .await
}

async fn apply_prepared_consent_update(
    home: &std::path::Path,
    provider: ProviderKind,
    grant: bool,
    config: &FreedomConfig,
    source: ConsentMutationSource,
    configured_endpoint_origins: Vec<String>,
    update: consent::ConsentMarkerUpdate,
    gui_binding: Option<GuiMutationBinding<'_>>,
) -> Result<ConsentChangeReceipt> {
    let was_granted = update.source_exists();
    let prior_origins = update
        .prior_grants()
        .iter()
        .filter_map(|entry| entry.endpoint_origin.clone())
        .collect::<Vec<_>>();
    let target_origins = update
        .target_grants()
        .iter()
        .filter_map(|entry| entry.endpoint_origin.clone())
        .collect::<Vec<_>>();
    let endpoint_origins = if grant { target_origins } else { prior_origins };
    let added_endpoint_origins = update.added_endpoint_origins().to_vec();
    let removed_endpoint_origins = update.removed_endpoint_origins().to_vec();
    let endpoint_delta_known = update.endpoint_delta_known();
    let marker_source_malformed = update.malformed_source();
    if !update.changed() {
        if let Some(binding) = gui_binding {
            binding.verify()?;
        }
        return Ok(ConsentChangeReceipt {
            provider,
            was_granted,
            changed: false,
            status: ConsentMutationStatus::Applied,
            configured_endpoint_origins,
            endpoint_origins,
            added_endpoint_origins,
            removed_endpoint_origins,
            endpoint_delta_known,
            marker_source_malformed,
            audit_pending: false,
            operation_id: None,
            authority_persisted: was_granted,
            failure: None,
        });
    }

    let action = if grant {
        ConsentMutationAction::Grant
    } else {
        ConsentMutationAction::Revoke
    };
    let audit_origins = if grant {
        added_endpoint_origins.clone()
    } else {
        removed_endpoint_origins.clone()
    };
    let required_audit = config.audit_rpc.required_for_oneshot_permission_events;
    let mut transaction = crate::cli::consent_outbox::begin(
        home,
        &update,
        action,
        source,
        audit_origins,
        required_audit,
    )
    .await?;
    let operation_id = transaction.record().operation_id().to_owned();
    let mut audit_pending = transaction.deliver_phase().await?.is_pending();

    update
        .commit()
        .context("commit consent marker after durable mutation intent")?;
    transaction.mark_committed()?;
    let mut status = ConsentMutationStatus::Applied;
    let mut failure = None;
    if let Some(binding) = gui_binding
        && let Err(binding_error) = binding.verify()
    {
        let binding_error = crate::security::redact::redact_text(&format!("{binding_error:#}"));
        match update.rollback() {
            Ok(true) => {
                transaction.mark_rolled_back_after_commit()?;
                transaction
                    .deliver_phase()
                    .await
                    .context("deliver aborted consent mutation after GUI binding rollback")?;
                anyhow::bail!(
                    "GUI consent binding changed during mutation; committed marker was rolled back: {binding_error}"
                );
            }
            Ok(false) => {
                status = ConsentMutationStatus::CommittedButBindingStale;
                failure = Some(format!(
                    "{binding_error}; exact rollback lost a concurrent marker race"
                ));
            }
            Err(rollback_error) => {
                status = ConsentMutationStatus::CommittedButBindingStale;
                failure = Some(format!(
                    "{binding_error}; rollback failed: {}",
                    crate::security::redact::redact_text(&format!("{rollback_error:#}"))
                ));
            }
        }
    }
    match transaction.deliver_phase().await {
        Ok(delivery) => {
            audit_pending |= delivery.is_pending();
        }
        Err(commit_audit_error) => {
            let audit_error = format!("{commit_audit_error:#}");
            let rolled_back = update
                .rollback()
                .context("rollback consent marker after required commit-audit failure")?;
            anyhow::ensure!(
                rolled_back,
                "required consent commit audit failed and exact marker rollback lost a concurrent mutation race; journal remains fail-closed: {audit_error}"
            );
            transaction.mark_rolled_back_after_commit()?;
            transaction
                .deliver_phase()
                .await
                .context("deliver aborted consent mutation after rollback")?;
            anyhow::bail!(
                "required consent commit audit failed; marker was rolled back: {audit_error}"
            );
        }
    }
    let authority_persisted = if status == ConsentMutationStatus::CommittedButBindingStale {
        if added_endpoint_origins.is_empty() {
            consent::is_granted(home, provider)
        } else {
            added_endpoint_origins.iter().any(|origin| {
                consent::is_route_granted(home, &consent::ConsentRoute::new(provider, Some(origin)))
            })
        }
    } else {
        grant
    };

    Ok(ConsentChangeReceipt {
        provider,
        was_granted,
        changed: true,
        status,
        configured_endpoint_origins,
        endpoint_origins,
        added_endpoint_origins,
        removed_endpoint_origins,
        endpoint_delta_known,
        marker_source_malformed,
        audit_pending,
        operation_id: Some(operation_id),
        authority_persisted,
        failure,
    })
}

pub(crate) async fn ensure_route_granted_or_prompt_at(
    home: &std::path::Path,
    route: &consent::ConsentRoute,
    config: &FreedomConfig,
    source: ConsentMutationSource,
) -> Result<consent::EphemeralConsent> {
    let Some(decision) = consent::prompt_route_decision(home, route)? else {
        return Ok(consent::EphemeralConsent::default());
    };
    emit_consent_decision(home, route, decision, source)
        .await
        .context("durably audit outbound-LLM consent decision")?;

    match decision {
        consent::ConsentDecision::AllowOnce => {
            let mut ephemeral = consent::EphemeralConsent::default();
            ephemeral.allow_route(route)?;
            Ok(ephemeral)
        }
        consent::ConsentDecision::Deny => {
            anyhow::bail!("consent declined — exiting without sending any text")
        }
        consent::ConsentDecision::AllowAlways => {
            recover_pending_before_grant(home).await?;
            let configured_endpoint_origins =
                consent::route_endpoint_origin(route)?.into_iter().collect();
            let update = consent::prepare_grant_routes(home, std::slice::from_ref(route))?;
            let receipt = apply_prepared_consent_update(
                home,
                route.kind,
                true,
                config,
                source,
                configured_endpoint_origins,
                update,
                None,
            )
            .await?;
            if receipt.changed {
                eprintln!(
                    "✓ consent recorded for `{}` ({})",
                    consent::slug(route.kind),
                    consent::route_label(route)
                );
            }
            Ok(consent::EphemeralConsent::default())
        }
    }
}

pub(crate) async fn ensure_all_granted_or_prompt_at(
    home: &std::path::Path,
    config: &FreedomConfig,
    source: ConsentMutationSource,
) -> Result<consent::EphemeralConsent> {
    let mut ephemeral = consent::EphemeralConsent::default();
    for route in consent::required_consent_routes(config) {
        ephemeral.extend(ensure_route_granted_or_prompt_at(home, &route, config, source).await?)?;
    }
    Ok(ephemeral)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::events::{EVENT_TYPE_CONSENT_GRANTED, EVENT_TYPE_CONSENT_REVOKED};
    use tempfile::TempDir;

    #[test]
    fn grant_then_show_then_revoke_round_trip_via_render_helpers() {
        let tmp = TempDir::new().unwrap();
        // Direct module calls — render_* uses default_neoth_home() which we
        // can't override per call without env shimming. These tests pin the
        // underlying consent module behaviour the CLI dispatches to.
        assert!(!consent::is_granted(tmp.path(), ProviderKind::OpenaiApi));
        consent::grant(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        assert!(consent::is_granted(tmp.path(), ProviderKind::OpenaiApi));
        consent::revoke(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        assert!(!consent::is_granted(tmp.path(), ProviderKind::OpenaiApi));
    }

    #[tokio::test]
    async fn revoke_remains_available_without_freedom_config() {
        let tmp = TempDir::new().unwrap();
        consent::grant(tmp.path(), ProviderKind::OpenaiApi).unwrap();

        let receipt = change_consent_at(tmp.path(), ProviderKind::OpenaiApi, false)
            .await
            .unwrap();

        assert!(receipt.changed);
        assert!(!consent::is_granted(tmp.path(), ProviderKind::OpenaiApi));
        assert!(!crate::cli::consent_outbox::journal_path(tmp.path()).exists());
        assert!(
            std::fs::read_dir(tmp.path().join("wal"))
                .unwrap()
                .filter_map(Result::ok)
                .any(|entry| entry.file_name().to_string_lossy().ends_with(".wal"))
        );
    }

    #[test]
    fn status_synthesizes_configured_remote_ollama_without_marker() {
        let tmp = TempDir::new().unwrap();
        let config = FreedomConfig {
            provider_kind: Some(ProviderKind::LocalOllama),
            provider_endpoint: Some("http://ollama-b.example:11434/api".into()),
            ..FreedomConfig::default()
        };

        let rows = consent_status_rows(tmp.path(), Some(&config)).unwrap();
        let row = rows
            .iter()
            .find(|row| row.provider == "local_ollama")
            .unwrap();
        assert_eq!(
            row.configured_endpoint_origins,
            vec!["http://ollama-b.example:11434"]
        );
        assert!(row.granted_endpoint_origins.is_empty());
        assert!(!row.current_route_granted);
        assert!(row.consent_required);
        assert!(row.grantable);
        assert_eq!(row.status, "pending");
    }

    #[test]
    fn recursive_mas_status_is_visible_grantable_and_revokable() {
        let tmp = TempDir::new().unwrap();
        let config = FreedomConfig {
            provider_kind: Some(ProviderKind::RecursiveMas),
            ..FreedomConfig::default()
        };

        let rows = consent_status_rows(tmp.path(), Some(&config)).unwrap();
        let pending = rows
            .iter()
            .find(|row| row.provider == "recursive_mas")
            .unwrap();
        assert!(pending.consent_required);
        assert!(pending.grantable);
        assert!(!pending.revokable);
        assert_eq!(pending.status, "pending");

        consent::grant(tmp.path(), ProviderKind::RecursiveMas).unwrap();
        let rows = consent_status_rows(tmp.path(), Some(&config)).unwrap();
        let granted = rows
            .iter()
            .find(|row| row.provider == "recursive_mas")
            .unwrap();
        assert!(granted.current_route_granted);
        assert!(!granted.grantable);
        assert!(granted.revokable);
        assert_eq!(granted.status, "granted");
    }

    #[test]
    fn status_marks_old_ollama_origin_stale_after_reconfigure() {
        let tmp = TempDir::new().unwrap();
        consent::grant_route(
            tmp.path(),
            &consent::ConsentRoute::new(
                ProviderKind::LocalOllama,
                Some("http://ollama-a.example:11434"),
            ),
        )
        .unwrap();
        let config = FreedomConfig {
            provider_kind: Some(ProviderKind::LocalOllama),
            provider_endpoint: Some("http://ollama-b.example:11434".into()),
            ..FreedomConfig::default()
        };

        let rows = consent_status_rows(tmp.path(), Some(&config)).unwrap();
        let row = rows
            .iter()
            .find(|row| row.provider == "local_ollama")
            .unwrap();
        assert_eq!(
            row.configured_endpoint_origins,
            vec!["http://ollama-b.example:11434"]
        );
        assert_eq!(
            row.granted_endpoint_origins,
            vec!["http://ollama-a.example:11434"]
        );
        assert_eq!(
            row.stale_endpoint_origins,
            vec!["http://ollama-a.example:11434"]
        );
        assert!(!row.current_route_granted);
        assert!(row.grantable);
        assert!(row.revokable);
        assert_eq!(row.status, "pending");
    }

    #[test]
    fn status_does_not_call_stale_remote_grant_current_for_loopback() {
        let tmp = TempDir::new().unwrap();
        consent::grant_route(
            tmp.path(),
            &consent::ConsentRoute::new(
                ProviderKind::LocalOllama,
                Some("http://ollama-a.example:11434"),
            ),
        )
        .unwrap();
        let config = FreedomConfig {
            provider_kind: Some(ProviderKind::LocalOllama),
            provider_endpoint: Some("http://127.0.0.1:11434".into()),
            ..FreedomConfig::default()
        };

        let rows = consent_status_rows(tmp.path(), Some(&config)).unwrap();
        let row = rows
            .iter()
            .find(|row| row.provider == "local_ollama")
            .unwrap();
        assert!(!row.consent_required);
        assert!(!row.current_route_granted);
        assert!(!row.grantable);
        assert!(row.revokable);
        assert_eq!(row.status, "stale");
    }

    #[tokio::test]
    async fn cli_local_ollama_grant_binds_configured_origins_and_revoke_clears_all() {
        let tmp = TempDir::new().unwrap();
        let mut config = FreedomConfig {
            provider_kind: Some(ProviderKind::LocalOllama),
            provider_endpoint: Some("http://ollama-a.example:11434/api".into()),
            ..FreedomConfig::default()
        };
        std::fs::write(
            tmp.path().join("freedom.yaml"),
            serde_yaml::to_string(&config).unwrap(),
        )
        .unwrap();
        let route_a = consent::ConsentRoute::new(
            ProviderKind::LocalOllama,
            Some("http://ollama-a.example:11434"),
        );
        let route_b = consent::ConsentRoute::new(
            ProviderKind::LocalOllama,
            Some("http://ollama-b.example:11434"),
        );

        change_consent_at(tmp.path(), ProviderKind::LocalOllama, true)
            .await
            .unwrap();
        assert!(consent::is_route_granted(tmp.path(), &route_a));
        assert!(!consent::is_route_granted(tmp.path(), &route_b));
        let mut audited_origin = false;
        for segment in wal_segments(tmp.path()) {
            let wal = std::fs::read(segment).unwrap();
            crate::wal::scan::for_each_frame(&wal, |_, frame| {
                if frame.header.event_type == EVENT_TYPE_CONSENT_GRANTED {
                    let payload: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
                    audited_origin |=
                        payload["endpoint_origins"]
                            .as_array()
                            .is_some_and(|origins| {
                                origins
                                    .iter()
                                    .any(|origin| origin == "http://ollama-a.example:11434")
                            });
                }
                Ok(())
            })
            .unwrap();
        }
        assert!(
            audited_origin,
            "WAL grant must bind the safe canonical origin"
        );

        config.provider_endpoint = Some("http://ollama-b.example:11434".into());
        std::fs::write(
            tmp.path().join("freedom.yaml"),
            serde_yaml::to_string(&config).unwrap(),
        )
        .unwrap();
        assert!(
            !consent::is_route_granted(tmp.path(), &route_b),
            "changing the configured endpoint must re-arm consent"
        );
        change_consent_at(tmp.path(), ProviderKind::LocalOllama, true)
            .await
            .unwrap();
        assert!(consent::is_route_granted(tmp.path(), &route_a));
        assert!(consent::is_route_granted(tmp.path(), &route_b));

        assert!(
            change_consent_at(tmp.path(), ProviderKind::LocalOllama, false)
                .await
                .unwrap()
                .changed
        );
        assert!(!consent::is_route_granted(tmp.path(), &route_a));
        assert!(!consent::is_route_granted(tmp.path(), &route_b));
    }

    #[tokio::test]
    async fn active_config_not_stale_disk_config_selects_the_granted_ollama_origin() {
        let tmp = TempDir::new().unwrap();
        let disk_config = FreedomConfig {
            provider_kind: Some(ProviderKind::LocalOllama),
            provider_endpoint: Some("http://ollama-b.example:11434".into()),
            ..FreedomConfig::default()
        };
        std::fs::write(
            tmp.path().join("freedom.yaml"),
            serde_yaml::to_string(&disk_config).unwrap(),
        )
        .unwrap();
        let active_config = FreedomConfig {
            provider_kind: Some(ProviderKind::LocalOllama),
            provider_endpoint: Some("http://ollama-a.example:11434".into()),
            ..FreedomConfig::default()
        };

        change_consent_with_config_at(
            tmp.path(),
            ProviderKind::LocalOllama,
            true,
            &active_config,
            ConsentMutationSource::Slash,
        )
        .await
        .unwrap();

        assert!(consent::is_route_granted(
            tmp.path(),
            &consent::ConsentRoute::new(
                ProviderKind::LocalOllama,
                Some("http://ollama-a.example:11434"),
            ),
        ));
        assert!(!consent::is_route_granted(
            tmp.path(),
            &consent::ConsentRoute::new(
                ProviderKind::LocalOllama,
                Some("http://ollama-b.example:11434"),
            ),
        ));
    }

    #[tokio::test]
    async fn required_prepared_audit_failure_leaves_permission_marker_unchanged() {
        let tmp = TempDir::new().unwrap();
        let config = FreedomConfig {
            provider_kind: Some(ProviderKind::OpenaiApi),
            audit_rpc: crate::config::AuditRpcConfig {
                required_for_oneshot_permission_events: true,
                ..crate::config::AuditRpcConfig::default()
            },
            ..FreedomConfig::default()
        };
        std::fs::write(
            tmp.path().join("freedom.yaml"),
            serde_yaml::to_string(&config).unwrap(),
        )
        .unwrap();
        let _daemon_owner =
            crate::daemon::pidfile::acquire(&tmp.path().join("neothd.pid")).unwrap();

        let error = change_consent_at(tmp.path(), ProviderKind::OpenaiApi, true)
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("required consent audit delivery failed"),
            "{error:#}"
        );
        assert!(
            !consent::is_granted(tmp.path(), ProviderKind::OpenaiApi),
            "required prepared-audit failure must not expose a permission marker"
        );
        assert!(
            crate::cli::consent_outbox::journal_path(tmp.path()).exists(),
            "the prepared journal must remain for explicit recovery"
        );
    }

    #[tokio::test]
    async fn malformed_local_ollama_marker_is_revokable_without_blocking_other_providers() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("consent")).unwrap();
        let local_marker = consent::marker_path(tmp.path(), ProviderKind::LocalOllama);
        std::fs::write(&local_marker, b"{not valid consent json").unwrap();
        consent::grant(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        let config = FreedomConfig {
            provider_kind: Some(ProviderKind::LocalOllama),
            provider_endpoint: Some("http://ollama.example:11434".into()),
            ..FreedomConfig::default()
        };

        let receipt = change_consent_with_config_at(
            tmp.path(),
            ProviderKind::LocalOllama,
            false,
            &config,
            ConsentMutationSource::Cli,
        )
        .await
        .unwrap();
        assert!(receipt.changed);
        assert!(receipt.marker_source_malformed);
        assert!(!receipt.endpoint_delta_known);
        assert!(!local_marker.exists());
        assert!(
            consent::is_granted(tmp.path(), ProviderKind::OpenaiApi),
            "provider-scoped malformed state must not poison an unrelated cloud grant"
        );
    }

    #[tokio::test]
    async fn gui_grant_binding_drift_rolls_back_committed_marker() {
        let tmp = TempDir::new().unwrap();
        let config = FreedomConfig {
            provider_kind: Some(ProviderKind::OpenaiApi),
            ..FreedomConfig::default()
        };
        std::fs::write(
            tmp.path().join("freedom.yaml"),
            serde_yaml::to_string(&config).unwrap(),
        )
        .unwrap();
        let route =
            consent::ConsentRoute::new(ProviderKind::OpenaiApi, Some("https://api.openai.com"));
        let update =
            consent::prepare_grant_routes(tmp.path(), std::slice::from_ref(&route)).unwrap();
        let stale_config_hash = "0".repeat(64);
        let stale_route_hash = "1".repeat(64);
        let error = apply_prepared_consent_update(
            tmp.path(),
            ProviderKind::OpenaiApi,
            true,
            &config,
            ConsentMutationSource::Gui,
            vec!["https://api.openai.com".to_string()],
            update,
            Some(GuiMutationBinding {
                home: tmp.path(),
                config_sha256: &stale_config_hash,
                route_set_sha256: &stale_route_hash,
            }),
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("marker was rolled back"));
        assert!(
            !consent::is_route_granted(tmp.path(), &route),
            "a stale GUI binding must not leave newly granted authority behind"
        );
    }

    #[tokio::test]
    async fn unbound_gui_revoke_survives_corrupt_config() {
        let tmp = TempDir::new().unwrap();
        consent::grant(tmp.path(), ProviderKind::AnthropicApi).unwrap();
        std::fs::write(tmp.path().join("freedom.yaml"), b"not: [valid").unwrap();

        let receipt = change_consent_for_command(
            tmp.path(),
            ProviderKind::AnthropicApi,
            false,
            ConsentCommandSource::Gui,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(receipt.status, ConsentMutationStatus::Applied);
        assert!(!receipt.authority_persisted);
        assert!(!consent::is_granted(tmp.path(), ProviderKind::AnthropicApi));
    }

    #[tokio::test]
    async fn exact_gui_batch_grant_does_not_restore_concurrently_revoked_route() {
        let tmp = TempDir::new().unwrap();
        let route_a = consent::ConsentRoute::new(
            ProviderKind::LocalOllama,
            Some("http://ollama-a.example:11434"),
        );
        let route_b = consent::ConsentRoute::new(
            ProviderKind::LocalOllama,
            Some("http://ollama-b.example:11434"),
        );
        consent::grant_route(tmp.path(), &route_a).unwrap();
        consent::revoke(tmp.path(), ProviderKind::LocalOllama).unwrap();

        let receipt = grant_exact_routes_with_config_at(
            tmp.path(),
            ProviderKind::LocalOllama,
            std::slice::from_ref(&route_b),
            &FreedomConfig::default(),
            ConsentMutationSource::Gui,
        )
        .await
        .unwrap();
        assert_eq!(
            receipt.configured_endpoint_origins,
            vec!["http://ollama-b.example:11434"]
        );
        assert!(!consent::is_route_granted(tmp.path(), &route_a));
        assert!(consent::is_route_granted(tmp.path(), &route_b));
    }

    fn wal_segments(home: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut segments = std::fs::read_dir(home.join("wal"))
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("wal"))
            .collect::<Vec<_>>();
        segments.sort();
        segments
    }

    /// Count frames of a given event type across unique one-shot WAL segments.
    fn count_event_frames(home: &std::path::Path, want: u8) -> usize {
        let mut n = 0usize;
        for segment in wal_segments(home) {
            let bytes = std::fs::read(segment).unwrap_or_default();
            let _ = crate::wal::scan::for_each_frame(&bytes, |_, dec| {
                if dec.header.event_type == want {
                    n += 1;
                }
                Ok(())
            });
        }
        n
    }

    /// SR-017 / GOLD-SEC-30: a one-shot consent grant must leave a
    /// `0xDB CONSENT_GRANTED` frame in the WAL (discoverable via
    /// `neoth wal show --type consent_granted`); a real revoke leaves a
    /// `0xDC CONSENT_REVOKED` frame.
    #[tokio::test]
    async fn grant_and_revoke_emit_consent_audit_frames_via_oneshot() {
        let tmp = TempDir::new().unwrap();
        let config = FreedomConfig {
            provider_kind: Some(ProviderKind::OpenaiApi),
            ..FreedomConfig::default()
        };
        std::fs::write(
            tmp.path().join("freedom.yaml"),
            serde_yaml::to_string(&config).unwrap(),
        )
        .unwrap();

        let grant = change_consent_at(tmp.path(), ProviderKind::OpenaiApi, true)
            .await
            .unwrap();
        assert!(grant.changed);
        assert!(grant.operation_id.is_some());
        assert_eq!(
            count_event_frames(tmp.path(), EVENT_TYPE_CONSENT_GRANTED),
            2,
            "grant must write prepared and committed CONSENT_GRANTED frames"
        );
        assert_eq!(
            count_event_frames(tmp.path(), EVENT_TYPE_CONSENT_REVOKED),
            0
        );

        let revoke = change_consent_at(tmp.path(), ProviderKind::OpenaiApi, false)
            .await
            .unwrap();
        assert!(revoke.changed);
        assert_eq!(
            count_event_frames(tmp.path(), EVENT_TYPE_CONSENT_REVOKED),
            2,
            "revoke must write prepared and committed CONSENT_REVOKED frames"
        );
        assert_eq!(
            count_event_frames(tmp.path(), EVENT_TYPE_CONSENT_GRANTED),
            2
        );
    }

    /// The event-name registry resolves the new codes both ways (the 5-site
    /// registration is complete).
    #[test]
    fn consent_event_codes_resolve_in_the_registry() {
        use crate::wal::events::{event_code_from_filter, event_name_from_code};
        assert_eq!(
            event_code_from_filter("consent_granted"),
            Some(EVENT_TYPE_CONSENT_GRANTED)
        );
        assert_eq!(
            event_code_from_filter("consent_revoked"),
            Some(EVENT_TYPE_CONSENT_REVOKED)
        );
        assert_eq!(
            event_name_from_code(EVENT_TYPE_CONSENT_GRANTED),
            Some("consent_granted")
        );
        assert_eq!(
            event_name_from_code(EVENT_TYPE_CONSENT_REVOKED),
            Some("consent_revoked")
        );
    }

    #[tokio::test]
    async fn consent_audit_required_posture_is_bound_into_both_phases() {
        let dir = TempDir::new().unwrap();
        let config = FreedomConfig {
            provider_kind: Some(ProviderKind::OpenaiApi),
            audit_rpc: crate::config::AuditRpcConfig {
                required_for_oneshot_permission_events: true,
                ..crate::config::AuditRpcConfig::default()
            },
            ..FreedomConfig::default()
        };
        std::fs::write(
            dir.path().join("freedom.yaml"),
            serde_yaml::to_string(&config).unwrap(),
        )
        .unwrap();
        change_consent_at(dir.path(), ProviderKind::OpenaiApi, true)
            .await
            .unwrap();

        let mut required_phases = Vec::new();
        for segment in wal_segments(dir.path()) {
            let bytes = std::fs::read(segment).unwrap();
            crate::wal::scan::for_each_frame(&bytes, |_, frame| {
                if frame.header.event_type == EVENT_TYPE_CONSENT_GRANTED {
                    let payload: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
                    if payload["required_audit"] == true {
                        required_phases.push(payload["phase"].as_str().unwrap().to_owned());
                    }
                }
                Ok(())
            })
            .unwrap();
        }
        required_phases.sort();
        assert_eq!(required_phases, vec!["committed", "prepared"]);
    }
}
