//! `neoth fetch <url>` — operator-facing web_fetch surface.
//!
//! Wraps `tools::web_fetch::fetch` so operators can pull a URL into
//! their terminal (or pipe to recall via `neoth ingest --url`,
//! deferred to Phase 2). Honours the Hysteria SOCKS5 proxy via
//! `providers::http_client::build_client`.

use anyhow::{Context, Result};
use clap::Args;

use crate::cli::OutputFormat;

#[derive(Args, Debug, Clone)]
pub struct FetchArgs {
    /// URL to fetch. Only http(s) schemes accepted.
    pub url: String,

    /// GOLD-ADOPT-26 — fetch via the Jina Reader proxy (https://r.jina.ai),
    /// which renders JS-heavy / bot-blocked pages to clean Markdown. The
    /// last-resort path when the plain fetch returns thin or empty content.
    #[arg(long)]
    pub jina: bool,

    /// GOLD-ADOPT-04 — extract the text of elements matching this CSS selector
    /// from the fetched page (e.g. `--selector "h1.title"`). The selector is
    /// cached per host; if the site later changes and the selector breaks, an
    /// adaptive fingerprint re-find heals it. Mutually exclusive with `--jina`.
    #[arg(long)]
    pub selector: Option<String>,

    /// GOLD-ADAPT-ODY-23 — extract only the goal-relevant
    /// `{rational, evidence, summary}` from the fetched page via the configured
    /// utility provider (an LLM pass reads the page and pulls what bears on this
    /// goal). Mutually exclusive with `--selector` / `--jina`.
    #[arg(long)]
    pub goal: Option<String>,

    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_fetch(args: FetchArgs) -> Result<()> {
    if args.jina && args.selector.is_some() {
        anyhow::bail!("--jina and --selector are mutually exclusive");
    }
    if args.goal.is_some() && (args.jina || args.selector.is_some()) {
        anyhow::bail!("--goal cannot be combined with --jina or --selector");
    }
    // GOLD-ADAPT-SKILL-03 — opt this fetch process into the conditional-GET doc
    // cache so a re-fetch of the same documentation URL is revalidated (304),
    // not re-downloaded. Applies to plain, --selector, and --jina fetches.
    crate::tools::web_doc_cache::init(&crate::config::FreedomConfig::default_neoth_home());
    // GOLD-ADOPT-04 — CSS-selector extraction path.
    if let Some(selector) = args.selector.clone() {
        if selector.trim().is_empty() {
            anyhow::bail!("--selector must not be empty");
        }
        let home = crate::config::FreedomConfig::default_neoth_home();
        crate::tools::web_selector_cache::init(&home).await;
        // Cache key scopes the selector to the exact PAGE (host + path), so two
        // different pages on the same host don't share a (possibly wrong) cached
        // selector. (review F: host-only collided across pages.)
        let (host, path) = url::Url::parse(&args.url)
            .ok()
            .map(|u| {
                (
                    u.host_str().unwrap_or("unknown").to_string(),
                    u.path().to_string(),
                )
            })
            .unwrap_or_else(|| ("unknown".to_string(), String::new()));
        let cache_key = format!("{host}{path}:{selector}");
        let result = crate::tools::web_selector_cache::extract_with_cache(
            &args.url, &cache_key, &selector, None,
        )
        .await?;
        match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "url": args.url,
                        "selector": selector,
                        "selector_used": result.selector_used,
                        "stale_recovered": result.stale_recovered,
                        "hits": result.hits,
                    }))?
                );
            }
            OutputFormat::Table => {
                println!("url:       {}", args.url);
                println!("selector:  {selector}");
                if result.stale_recovered {
                    println!(
                        "recovered: yes (selector healed to `{}`)",
                        result.selector_used
                    );
                }
                println!("matches:   {}", result.hits.len());
                println!();
                for h in &result.hits {
                    println!("{h}");
                }
            }
        }
        return Ok(());
    }
    if args.jina {
        // SSRF-guard the ORIGINAL URL (scheme + private-IP) before handing it
        // to the proxy; r.jina.ai itself is a fixed public host.
        crate::tools::web_fetch::validate_url(&args.url).await?;
        let markdown = crate::tools::jina_reader::fetch_via_jina(&args.url).await?;
        match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "url": args.url,
                        "source": "jina_reader",
                        "text": markdown,
                    }))?
                );
            }
            OutputFormat::Table => {
                println!("url:    {}", args.url);
                println!("source: jina_reader (r.jina.ai)");
                println!();
                println!("{markdown}");
            }
        }
        return Ok(());
    }
    // GOLD-ADAPT-ODY-23b — goal-focused extraction path. Fetches the page plain
    // (SSRF-guarded, cached) then runs one utility-provider LLM pass that pulls
    // only the goal-relevant {rational, evidence, summary}. This is the real
    // caller for tools::web_fetch::fetch_with_goal (the ODY-23 extractor was
    // engine-only until now).
    if let Some(goal) = args.goal.clone() {
        if goal.trim().is_empty() {
            anyhow::bail!("--goal must not be empty");
        }
        let home = crate::config::FreedomConfig::default_neoth_home();
        let config = crate::config::FreedomConfig::load_from_default_path_or_default()?;
        let provider = crate::providers::from_config_for_utility_at(&config, &home)
            .await
            .context("build utility provider for goal extraction")?;
        let default_model = crate::providers::provider_default_wire_model(provider.as_ref());
        let provider_audit =
            crate::providers::cost_authorization::ProviderCallAuthorizer::interactive_one_shot(
                config.autonomy_policy(),
                config.tokens.max_per_request,
            )
            .await?;
        let provider = crate::providers::cost_authorization::AuthorizedProvider::from_box(
            provider,
            provider_audit.authorizer(),
            default_model,
            "fetch.goal_extract",
        );
        let extraction =
            crate::tools::web_fetch::fetch_with_goal(&args.url, &goal, &provider).await;
        provider_audit
            .finish(provider)
            .await
            .context("finalize goal-extraction provider-call audit WAL")?;
        let extraction = extraction?;
        match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "url": args.url,
                        "goal": goal,
                        "rational": extraction.rational,
                        "evidence": extraction.evidence,
                        "summary": extraction.summary,
                    }))?
                );
            }
            OutputFormat::Table => {
                println!("url:      {}", args.url);
                println!("goal:     {goal}");
                println!();
                println!("rational: {}", extraction.rational);
                println!();
                println!("evidence ({}):", extraction.evidence.len());
                for e in &extraction.evidence {
                    println!("  - {e}");
                }
                println!();
                println!("summary:  {}", extraction.summary);
            }
        }
        return Ok(());
    }
    let result = crate::tools::web_fetch::fetch(&args.url).await?;
    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        OutputFormat::Table => {
            println!("url:          {}", result.url);
            println!("status:       {}", result.status);
            println!("content-type: {}", result.content_type);
            println!("bytes:        {}", result.bytes);
            if result.truncated {
                println!("truncated:    yes (extracted text > ceiling)");
            }
            println!();
            println!("{}", result.text);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_fetch_rejects_non_http() {
        let args = FetchArgs {
            url: "file:///etc/passwd".to_string(),
            jina: false,
            selector: None,
            goal: None,
            output: OutputFormat::Json,
        };
        let err = run_fetch(args).await.unwrap_err();
        assert!(err.to_string().contains("http(s)"));
    }

    #[tokio::test]
    async fn run_fetch_jina_rejects_non_http() {
        // The --jina path must still run the SSRF/scheme guard first.
        let args = FetchArgs {
            url: "file:///etc/passwd".to_string(),
            jina: true,
            selector: None,
            goal: None,
            output: OutputFormat::Json,
        };
        let err = run_fetch(args).await.unwrap_err();
        assert!(err.to_string().contains("http(s)"));
    }

    #[tokio::test]
    async fn selector_and_jina_are_mutually_exclusive() {
        let args = FetchArgs {
            url: "https://example.com".to_string(),
            jina: true,
            selector: Some("h1".to_string()),
            goal: None,
            output: OutputFormat::Json,
        };
        let err = run_fetch(args).await.unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"), "{err}");
    }

    #[tokio::test]
    async fn goal_cannot_combine_with_jina_or_selector() {
        // GOLD-ADAPT-ODY-23b — --goal is its own (plain-fetch + extract) path.
        let with_jina = FetchArgs {
            url: "https://example.com".to_string(),
            jina: true,
            selector: None,
            goal: Some("find the pricing".to_string()),
            output: OutputFormat::Json,
        };
        let err = run_fetch(with_jina).await.unwrap_err();
        assert!(
            err.to_string().contains("--goal cannot be combined"),
            "{err}"
        );

        let with_selector = FetchArgs {
            url: "https://example.com".to_string(),
            jina: false,
            selector: Some("h1".to_string()),
            goal: Some("find the pricing".to_string()),
            output: OutputFormat::Json,
        };
        let err = run_fetch(with_selector).await.unwrap_err();
        assert!(
            err.to_string().contains("--goal cannot be combined"),
            "{err}"
        );
    }

    #[test]
    fn goal_flag_parses() {
        use clap::Parser;
        #[derive(Parser)]
        struct Wrap {
            #[command(flatten)]
            args: FetchArgs,
        }
        let w = Wrap::parse_from(["x", "https://e.com", "--goal", "summarise the API"]);
        assert_eq!(w.args.goal.as_deref(), Some("summarise the API"));
        assert!(!w.args.jina);
        assert!(w.args.selector.is_none());
    }

    #[test]
    fn selector_flag_parses() {
        use clap::Parser;
        #[derive(Parser)]
        struct Wrap {
            #[command(flatten)]
            args: FetchArgs,
        }
        let w = Wrap::parse_from(["x", "https://e.com", "--selector", "span.price"]);
        assert_eq!(w.args.selector.as_deref(), Some("span.price"));
        assert!(!w.args.jina);
    }
}
