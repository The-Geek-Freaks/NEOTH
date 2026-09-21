//! `neoth citation lookup` — bounded DOI lookup bound to an explicit claim.

use anyhow::{Result, anyhow, ensure};
use clap::{Args, Subcommand, ValueEnum};
use serde::Serialize;
use std::future::Future;
use std::io::Read as _;

use zeroize::Zeroizing;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::tools::citation_http;
use crate::tools::citation_lookup::{
    CitationCache, CitationDisplay, CitationLookupResult, CitationProvider, CitationQuery,
    LookupSource, validate_claim,
};
use crate::tools::external_http::ExternalHttpAuthorizer;

#[derive(Args, Debug, Clone)]
pub struct CitationArgs {
    #[command(subcommand)]
    pub action: CitationAction,
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CitationAction {
    /// Look up one DOI and bind the selected canonical record to an explicit claim.
    Lookup {
        #[arg(long)]
        claim: String,
        #[arg(long)]
        doi: String,
        /// One provider. Omitted: Crossref, OpenAlex, then Semantic Scholar.
        #[arg(long)]
        provider: Option<String>,
        /// Read only private cache entries; never construct an authorizer or HTTP request.
        #[arg(long)]
        offline: bool,
        /// Immutable opaque GUI request identifier; private desktop bridge only.
        #[arg(long, hide = true)]
        request_id: Option<String>,
        /// Read the one-time GUI citation proof only from bounded private stdin.
        #[arg(long, hide = true)]
        gui_approval_stdin: bool,
    },
    /// Private desktop-GUI policy preflight for one explicit citation provider.
    #[command(name = "gui-preflight", hide = true)]
    GuiPreflight {
        #[arg(long)]
        claim: String,
        #[arg(long)]
        doi: String,
        #[arg(long)]
        provider: String,
        #[arg(long)]
        request_id: String,
        /// Return a typed cache-only result and never mint GUI consent.
        #[arg(long)]
        offline: bool,
    },
    /// Private desktop-GUI challenge decision; its challenge token is stdin-only.
    #[command(name = "gui-decide", hide = true)]
    GuiDecide {
        #[arg(long)]
        claim: String,
        #[arg(long)]
        doi: String,
        #[arg(long)]
        provider: String,
        #[arg(long)]
        request_id: String,
        #[arg(long, value_enum)]
        decision: GuiCitationDecision,
        #[arg(long, hide = true)]
        approval_stdin: bool,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum GuiCitationDecision {
    Approve,
    Deny,
}

impl GuiCitationDecision {
    fn core(self) -> crate::tools::citation_consent::CitationConsentDecision {
        match self {
            Self::Approve => crate::tools::citation_consent::CitationConsentDecision::Approve,
            Self::Deny => crate::tools::citation_consent::CitationConsentDecision::Deny,
        }
    }
}

const MAX_GUI_TOKEN_STDIN_BYTES: u64 = 256;

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct GuiCitationPreflightReceipt {
    kind: &'static str,
    status: &'static str,
    request_key_sha256: String,
    cache_read: citation_http::CitationCacheReadState,
    result: Option<CitationLookupResult>,
    expires_unix: Option<u64>,
    challenge_token: Option<String>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct GuiCitationDecisionReceipt {
    kind: &'static str,
    status: &'static str,
    proof_token: Option<String>,
}

fn gui_query(provider: &str, doi: &str) -> Result<CitationQuery> {
    let provider = selected_providers(Some(provider))?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("GUI citation lookup requires one explicit provider"))?;
    CitationQuery::new(provider, doi).map_err(Into::into)
}

fn read_gui_token_from_stdin(label: &str) -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new(Vec::new());
    std::io::stdin()
        .take(MAX_GUI_TOKEN_STDIN_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(anyhow::Error::from)?;
    ensure!(
        bytes.len() <= MAX_GUI_TOKEN_STDIN_BYTES as usize,
        "{label} on stdin exceeds the private size limit"
    );
    let token = std::str::from_utf8(&bytes)
        .map_err(anyhow::Error::from)
        .map(|value| Zeroizing::new(value.trim().to_owned()))?;
    ensure!(
        !token.is_empty(),
        "{label} is required on stdin and must not be passed in argv"
    );
    Ok(token)
}

fn print_gui_receipt<T: Serialize>(receipt: &T, output: OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(receipt)?),
        OutputFormat::Jsonl => println!("{}", serde_json::to_string(receipt)?),
        OutputFormat::Table => anyhow::bail!("private GUI citation commands require --output json"),
    }
    Ok(())
}

async fn run_gui_preflight(
    claim: &str,
    doi: &str,
    provider: &str,
    request_id: &str,
    offline: bool,
    output: OutputFormat,
) -> Result<()> {
    let claim = validate_claim(claim)?;
    let query = gui_query(provider, doi)?;
    let home = FreedomConfig::default_neoth_home();
    let cache = CitationCache::at_default()?;
    let now_secs = crate::time::now_unix_secs();
    let result = citation_http::gui_citation_preflight_cache_first(
        &query,
        &claim,
        Some(&cache),
        now_secs,
        offline,
        |live_miss| {
            crate::tools::citation_consent::create_gui_citation_lookup_preflight(
                &home, &query, &claim, request_id, now_secs, live_miss,
            )
        },
    )?;
    let receipt = match result {
        citation_http::GuiCitationPreflightCacheFirst::Consent {
            cache_read,
            preflight: crate::tools::citation_consent::CitationConsentPreflight::Ready,
        } => GuiCitationPreflightReceipt {
            kind: "citation_gui_preflight",
            status: "ready",
            request_key_sha256: query.request_key_sha256(),
            cache_read,
            result: None,
            expires_unix: None,
            challenge_token: None,
        },
        citation_http::GuiCitationPreflightCacheFirst::Consent {
            cache_read,
            preflight: crate::tools::citation_consent::CitationConsentPreflight::Denied,
        } => GuiCitationPreflightReceipt {
            kind: "citation_gui_preflight",
            status: "denied",
            request_key_sha256: query.request_key_sha256(),
            cache_read,
            result: None,
            expires_unix: None,
            challenge_token: None,
        },
        citation_http::GuiCitationPreflightCacheFirst::Consent {
            cache_read,
            preflight:
                crate::tools::citation_consent::CitationConsentPreflight::ConfirmationRequired {
                    challenge_token,
                    expires_unix,
                    request_key_sha256,
                },
        } => GuiCitationPreflightReceipt {
            kind: "citation_gui_preflight",
            status: "confirmation_required",
            request_key_sha256,
            cache_read,
            result: None,
            expires_unix: Some(expires_unix),
            challenge_token: Some(challenge_token.to_string()),
        },
        citation_http::GuiCitationPreflightCacheFirst::Terminal(report) => {
            let report = *report;
            GuiCitationPreflightReceipt {
                kind: "citation_gui_preflight",
                status: if matches!(
                    report.cache_read,
                    citation_http::CitationCacheReadState::Hit
                ) {
                    "cache_hit"
                } else {
                    "offline"
                },
                request_key_sha256: query.request_key_sha256(),
                cache_read: report.cache_read,
                result: Some(report.lookup),
                expires_unix: None,
                challenge_token: None,
            }
        }
    };
    print_gui_receipt(&receipt, output)
}
fn run_gui_decide(
    claim: &str,
    doi: &str,
    provider: &str,
    request_id: &str,
    decision: GuiCitationDecision,
    approval_stdin: bool,
    output: OutputFormat,
) -> Result<()> {
    ensure!(
        approval_stdin,
        "private GUI citation decisions require --approval-stdin"
    );
    let query = gui_query(provider, doi)?;
    let token = read_gui_token_from_stdin("GUI citation challenge token")?;
    let home = FreedomConfig::default_neoth_home();
    let proof_token = crate::tools::citation_consent::decide_gui_citation_lookup(
        &home,
        &token,
        &query,
        claim,
        request_id,
        decision.core(),
        crate::time::now_unix_secs(),
    )?;
    let receipt = GuiCitationDecisionReceipt {
        kind: "citation_gui_decision",
        status: if proof_token.is_some() {
            "approved"
        } else {
            "denied"
        },
        proof_token: proof_token.map(|token| token.to_string()),
    };
    print_gui_receipt(&receipt, output)
}
const DEFAULT_PROVIDER_ORDER: [CitationProvider; 3] = [
    CitationProvider::Crossref,
    CitationProvider::OpenAlex,
    CitationProvider::SemanticScholar,
];

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct CitationCliReceipt {
    claim: String,
    providers: Vec<CitationProvider>,
    result: CitationLookupResult,
    cache_read: citation_http::CitationCacheReadState,
    cache_write: citation_http::CitationCacheWriteState,
    attempts: Vec<CitationAttempt>,
    display: Option<CitationDisplay>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct CitationAttempt {
    provider: CitationProvider,
    doi: String,
    result: CitationLookupResult,
    cache_read: citation_http::CitationCacheReadState,
    cache_write: citation_http::CitationCacheWriteState,
}

pub async fn run_citation(args: CitationArgs) -> Result<()> {
    match args.action {
        CitationAction::Lookup {
            claim,
            doi,
            provider,
            offline,
            request_id,
            gui_approval_stdin,
        } => {
            ensure!(
                !gui_approval_stdin || request_id.is_some(),
                "--gui-approval-stdin requires the immutable GUI --request-id"
            );
            match request_id {
                Some(request_id) => {
                    run_gui_lookup(
                        &claim,
                        &doi,
                        provider.as_deref(),
                        offline,
                        &request_id,
                        gui_approval_stdin,
                        args.output,
                    )
                    .await
                }
                None => run_lookup(&claim, &doi, provider.as_deref(), offline, args.output).await,
            }
        }
        CitationAction::GuiPreflight {
            claim,
            doi,
            provider,
            request_id,
            offline,
        } => run_gui_preflight(&claim, &doi, &provider, &request_id, offline, args.output).await,
        CitationAction::GuiDecide {
            claim,
            doi,
            provider,
            request_id,
            decision,
            approval_stdin,
        } => run_gui_decide(
            &claim,
            &doi,
            &provider,
            &request_id,
            decision,
            approval_stdin,
            args.output,
        ),
    }
}

async fn run_gui_lookup(
    claim: &str,
    doi: &str,
    provider: Option<&str>,
    offline: bool,
    request_id: &str,
    gui_approval_stdin: bool,
    output: OutputFormat,
) -> Result<()> {
    let claim = validate_claim(claim)?;
    let provider =
        provider.ok_or_else(|| anyhow!("GUI citation lookup requires one explicit provider"))?;
    let query = gui_query(provider, doi)?;
    let cache = CitationCache::at_default()?;
    let home = FreedomConfig::default_neoth_home();
    let now_secs = crate::time::now_unix_secs();
    let report = if gui_approval_stdin {
        citation_http::lookup_cache_first_with_gui_citation_approval(
            &query,
            &claim,
            Some(&cache),
            now_secs,
            offline,
            &home,
            request_id,
            || {
                let proof = read_gui_token_from_stdin("GUI citation approval proof")?;
                crate::tools::citation_consent::consume_gui_citation_lookup_approval(
                    &home, &proof, &query, &claim, request_id, now_secs,
                )
            },
        )
        .await
    } else {
        citation_http::lookup_cache_first_with_gui_citation_ready(
            &query,
            &claim,
            Some(&cache),
            now_secs,
            offline,
            &home,
            request_id,
        )
        .await
    };
    ensure!(
        report.lookup.validate_for_claim(&query, &claim),
        "citation lookup returned a result that is not bound to its current query and claim"
    );
    let display = report.lookup.display_for_claim(&query, &claim);
    let receipt = CitationCliReceipt {
        claim,
        providers: vec![query.provider],
        result: report.lookup.clone(),
        cache_read: report.cache_read,
        cache_write: report.cache_write,
        attempts: vec![CitationAttempt {
            provider: query.provider,
            doi: query.doi.clone(),
            result: report.lookup,
            cache_read: report.cache_read,
            cache_write: report.cache_write,
        }],
        display,
    };
    emit_lookup(receipt, output)
}
async fn run_lookup(
    claim: &str,
    doi: &str,
    provider: Option<&str>,
    offline: bool,
    output: OutputFormat,
) -> Result<()> {
    let cache = CitationCache::at_default()?;
    let cache_ref = &cache;
    let now_secs = crate::time::now_unix_secs();
    let receipt = run_lookup_with(
        claim,
        doi,
        provider,
        offline,
        now_secs,
        move |query, claim, offline, now_secs| async move {
            citation_http::lookup_cache_first(
                &query,
                &claim,
                Some(cache_ref),
                now_secs,
                offline,
                || {
                    let config = FreedomConfig::load_from_default_path_or_default()?;
                    ExternalHttpAuthorizer::interactive(config.autonomy_policy())
                },
            )
            .await
        },
    )
    .await?;
    emit_lookup(receipt, output)
}

async fn run_lookup_with<F, Fut>(
    claim: &str,
    doi: &str,
    provider: Option<&str>,
    offline: bool,
    _now_secs: u64,
    mut lookup: F,
) -> Result<CitationCliReceipt>
where
    F: FnMut(CitationQuery, String, bool, u64) -> Fut,
    Fut: Future<Output = citation_http::CitationCacheFirstReport>,
{
    let claim = validate_claim(claim)?;
    let providers = selected_providers(provider)?;
    let queries = providers
        .iter()
        .map(|provider| CitationQuery::new(*provider, doi))
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let mut attempts = Vec::with_capacity(queries.len());
    for query in queries {
        let report = lookup(query.clone(), claim.clone(), offline, _now_secs).await;
        ensure!(
            report.lookup.validate_for_claim(&query, &claim),
            "citation lookup returned a result that is not bound to its current query and claim"
        );
        let display = report.lookup.display_for_claim(&query, &claim);
        let terminal = matches!(
            &report.lookup,
            CitationLookupResult::Unavailable {
                state: crate::tools::citation_lookup::CitationLookupState::PermissionDenied
                    | crate::tools::citation_lookup::CitationLookupState::InvalidQuery,
                ..
            }
        );
        let found = display.is_some();
        attempts.push(CitationAttempt {
            provider: query.provider,
            doi: query.doi.clone(),
            result: report.lookup.clone(),
            cache_read: report.cache_read,
            cache_write: report.cache_write,
        });
        if found || terminal {
            return Ok(CitationCliReceipt {
                claim,
                providers,
                result: report.lookup,
                cache_read: report.cache_read,
                cache_write: report.cache_write,
                attempts,
                display,
            });
        }
    }

    let last = attempts
        .last()
        .ok_or_else(|| anyhow!("citation lookup selected no provider"))?;
    let result = last.result.clone();
    let cache_read = last.cache_read;
    let cache_write = last.cache_write;
    Ok(CitationCliReceipt {
        claim,
        providers,
        result,
        cache_read,
        cache_write,
        attempts,
        display: None,
    })
}

fn selected_providers(provider: Option<&str>) -> Result<Vec<CitationProvider>> {
    match provider {
        None => Ok(DEFAULT_PROVIDER_ORDER.to_vec()),
        Some("crossref") => Ok(vec![CitationProvider::Crossref]),
        Some("openalex") => Ok(vec![CitationProvider::OpenAlex]),
        Some("semantic-scholar") => Ok(vec![CitationProvider::SemanticScholar]),
        Some(_) => Err(anyhow!(
            "invalid citation provider; expected crossref, openalex, or semantic-scholar"
        )),
    }
}

fn emit_lookup(receipt: CitationCliReceipt, output: OutputFormat) -> Result<()> {
    let unavailable = matches!(&receipt.result, CitationLookupResult::Unavailable { .. });
    print_receipt(&receipt, output)?;
    if unavailable {
        return Err(anyhow!("citation lookup produced no citation"));
    }
    Ok(())
}

fn print_receipt(receipt: &CitationCliReceipt, output: OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(receipt)?),
        OutputFormat::Jsonl => println!("{}", serde_json::to_string(receipt)?),
        OutputFormat::Table => match &receipt.display {
            Some(display) => {
                println!("# citation found");
                println!("  claim        : {}", display.claim);
                println!("  provider     : {}", display.provider.wire_name());
                println!("  source       : {}", lookup_source_label(display.source));
                println!("  record       : {}", display.provider_record_id);
                if let Some(doi) = &display.canonical_doi {
                    println!("  doi          : {doi}");
                }
                println!("  title        : {}", display.title);
                if !display.authors.is_empty() {
                    println!("  authors      : {}", display.authors.join(", "));
                }
                if let Some(year) = display.year {
                    println!("  year         : {year}");
                }
                if let Some(venue) = &display.venue {
                    println!("  venue        : {venue}");
                }
                println!("  binding      : {}", display.binding_sha256);
                println!("  permalink    : {}", display.provider_permalink);
            }
            None => {
                let CitationLookupResult::Unavailable { provider, state } = &receipt.result else {
                    return Err(anyhow!("citation receipt lacks a display-safe projection"));
                };
                println!("# citation unavailable");
                println!("  provider     : {}", provider.wire_name());
                println!("  state        : {}", serde_json::to_string(state)?);
            }
        },
    }
    Ok(())
}

fn lookup_source_label(source: LookupSource) -> &'static str {
    match source {
        LookupSource::Live => "live",
        LookupSource::Cache => "cache",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::citation_lookup::{CitationLookupState, CitationRecord};
    use clap::Parser;
    use std::sync::{Arc, Mutex};

    fn unavailable_report(
        provider: CitationProvider,
        state: CitationLookupState,
    ) -> citation_http::CitationCacheFirstReport {
        citation_http::CitationCacheFirstReport {
            lookup: CitationLookupResult::unavailable(provider, state),
            cache_read: citation_http::CitationCacheReadState::NotConfigured,
            cache_write: citation_http::CitationCacheWriteState::NotAttempted,
        }
    }

    #[test]
    fn provider_omission_order_and_explicit_limit_are_pinned() {
        assert_eq!(selected_providers(None).unwrap(), DEFAULT_PROVIDER_ORDER);
        assert_eq!(
            selected_providers(Some("openalex")).unwrap(),
            vec![CitationProvider::OpenAlex]
        );
        assert!(selected_providers(Some("other")).is_err());
    }

    #[test]
    fn invalid_claim_and_query_reject_before_lookup() {
        assert!(validate_claim("\n").is_err());
        assert!(CitationQuery::new(CitationProvider::Crossref, "not-a-doi").is_err());
    }

    #[test]
    fn clap_binds_explicit_provider_and_offline_without_a_network_path() {
        let parsed = crate::cli::Cli::try_parse_from([
            "neoth",
            "citation",
            "lookup",
            "--claim",
            "bound claim",
            "--doi",
            "10.1000/example",
            "--provider",
            "openalex",
            "--offline",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            crate::cli::Commands::Citation(CitationArgs {
                action: CitationAction::Lookup { offline: true, provider: Some(ref provider), .. },
                ..
            }) if provider == "openalex"
        ));
    }

    #[test]
    fn injected_empty_cache_offline_is_a_typed_miss_without_live_lookup() {
        let root = tempfile::tempdir().unwrap();
        let cache = CitationCache::new(root.path().join("citations"), 60, 8, 4096).unwrap();
        let query = CitationQuery::new(CitationProvider::Crossref, "10.1000/example").unwrap();
        let result = cache.lookup_offline(&query, "bound claim", 1).unwrap();
        assert!(matches!(
            result,
            CitationLookupResult::Unavailable {
                state: CitationLookupState::OfflineCacheMiss,
                ..
            }
        ));
    }

    #[test]
    fn unavailable_receipt_has_no_display_projection() {
        let result = CitationLookupResult::unavailable(
            CitationProvider::Crossref,
            CitationLookupState::OfflineCacheMiss,
        );
        let query = CitationQuery::new(CitationProvider::Crossref, "10.1000/example").unwrap();
        assert!(result.validate_for_claim(&query, "a valid explicit claim"));
        assert!(
            result
                .display_for_claim(&query, "a valid explicit claim")
                .is_none()
        );
    }

    #[test]
    fn altered_claim_cannot_render_a_found_display() {
        let query = CitationQuery::new(CitationProvider::Crossref, "10.1000/example").unwrap();
        let record = CitationRecord::new(
            &query,
            "10.1000/example",
            Some("10.1000/example"),
            "Bounded title",
            &["Author".to_string()],
            Some(2026),
            None,
            1,
            None,
        )
        .unwrap();
        let result = CitationLookupResult::from_live(&query, "first claim", record).unwrap();
        assert!(result.display_for_claim(&query, "second claim").is_none());
    }

    #[tokio::test]
    async fn runner_preserves_order_and_all_prior_typed_outcomes() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_lookup = Arc::clone(&seen);
        let receipt = run_lookup_with(
            "bound claim",
            "10.1000/example",
            None,
            false,
            7,
            move |query, _claim, _offline, _now| {
                seen_lookup.lock().unwrap().push(query.provider);
                async move {
                    let state = match query.provider {
                        CitationProvider::Crossref => CitationLookupState::NotFound,
                        CitationProvider::OpenAlex => CitationLookupState::ProviderUnavailable,
                        CitationProvider::SemanticScholar => CitationLookupState::RateLimited {
                            retry_after_secs: Some(12),
                        },
                    };
                    unavailable_report(query.provider, state)
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(*seen.lock().unwrap(), DEFAULT_PROVIDER_ORDER);
        assert_eq!(receipt.attempts.len(), 3);
        assert!(matches!(
            &receipt.attempts[0].result,
            CitationLookupResult::Unavailable {
                state: CitationLookupState::NotFound,
                ..
            }
        ));
        assert!(matches!(
            &receipt.attempts[1].result,
            CitationLookupResult::Unavailable {
                state: CitationLookupState::ProviderUnavailable,
                ..
            }
        ));
        assert!(matches!(
            &receipt.attempts[2].result,
            CitationLookupResult::Unavailable {
                state: CitationLookupState::RateLimited {
                    retry_after_secs: Some(12)
                },
                ..
            }
        ));
    }

    #[tokio::test]
    async fn runner_offline_and_invalid_inputs_construct_zero_authorizers() {
        let authorizers = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&authorizers);
        let receipt =
            run_lookup_with(
                "bound claim",
                "10.1000/example",
                Some("crossref"),
                true,
                7,
                move |query, _claim, offline, _now| {
                    if !offline {
                        observed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    async move {
                        unavailable_report(query.provider, CitationLookupState::OfflineCacheMiss)
                    }
                },
            )
            .await
            .unwrap();
        assert_eq!(authorizers.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(receipt.attempts.len(), 1);

        let invalid_authorizers = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let invalid_seen = Arc::clone(&invalid_authorizers);
        let invalid = run_lookup_with(
            "\n",
            "10.1000/example",
            None,
            false,
            7,
            move |query, _claim, _offline, _now| {
                invalid_seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                async move { unavailable_report(query.provider, CitationLookupState::NotFound) }
            },
        )
        .await;
        assert!(invalid.is_err());
        assert_eq!(
            invalid_authorizers.load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn permission_denied_stops_fallback_and_query_drift_is_rejected() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let call_counter = Arc::clone(&calls);
        let denied =
            run_lookup_with(
                "bound claim",
                "10.1000/example",
                None,
                false,
                7,
                move |query, _claim, _offline, _now| {
                    call_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    async move {
                        unavailable_report(query.provider, CitationLookupState::PermissionDenied)
                    }
                },
            )
            .await
            .unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(denied.attempts.len(), 1);

        let drift = run_lookup_with(
            "bound claim",
            "10.1000/example",
            Some("crossref"),
            false,
            7,
            |_query, claim, _offline, _now| async move {
                let wrong =
                    CitationQuery::new(CitationProvider::Crossref, "10.1000/other").unwrap();
                let record = CitationRecord::new(
                    &wrong,
                    "10.1000/other",
                    Some("10.1000/other"),
                    "Bounded title",
                    &["Author".to_string()],
                    Some(2026),
                    None,
                    1,
                    None,
                )
                .unwrap();
                citation_http::CitationCacheFirstReport {
                    lookup: CitationLookupResult::from_live(&wrong, &claim, record).unwrap(),
                    cache_read: citation_http::CitationCacheReadState::NotConfigured,
                    cache_write: citation_http::CitationCacheWriteState::NotAttempted,
                }
            },
        )
        .await;
        assert!(drift.is_err());
    }
}
