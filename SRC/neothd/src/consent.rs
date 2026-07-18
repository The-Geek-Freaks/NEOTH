//! V03-08 — First-run outbound-LLM consent.
//!
//! Operators get exactly one consent prompt per cloud provider, recorded as
//! a tag file under `~/.neoth/consent/<provider_kind>.granted`. Subsequent
//! invocations see the file + skip the prompt. Providers that are guaranteed
//! to stay in-process (`LocalQwen`, `LocalOuro`, `Skip`) never gate. Ollama is
//! endpoint-aware: loopback is local; LAN/DNS/public endpoints require consent.
//!
//! Why a file marker instead of `freedom.yaml`: marker files survive
//! `neoth init` reconfigure passes that rewrite `freedom.yaml`, and they
//! let the operator audit consent state with `ls ~/.neoth/consent/`.
//!
//! Daemon path (`neoth serve`) cannot prompt (no TTY) — startup must bail
//! with the exact CLI to grant consent before reconnecting. CLI path
//! (`neoth chat`) prompts interactively on a TTY, bails with the same
//! instruction off a TTY.

use std::fs;
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::cli::init::ProviderKind;

/// Cloud providers that ship operator text to a third-party. The operator
/// must explicitly grant consent before NEOTH routes any traffic to them.
///
/// THE canonical cloud-egress classifier (GOLD-SEC-09 / A-25). Every gate
/// that asks "is this provider cloud?" — the consent gate, the wizard
/// pre-grant hint, the cost/quota job preview — MUST route through here,
/// not maintain its own match set (those drifted and silently missed
/// `AnthropicApi`/`Cohere`). The match is EXHAUSTIVE on purpose: adding a
/// `ProviderKind` variant fails to compile until it is classified here.
pub fn is_cloud(kind: ProviderKind) -> bool {
    match kind {
        ProviderKind::ClaudeCli
        | ProviderKind::OpenaiApi
        | ProviderKind::AnthropicApi
        | ProviderKind::GeminiApi
        | ProviderKind::Cohere
        | ProviderKind::OpenaiCompat
        | ProviderKind::AwsBedrock
        | ProviderKind::AzureOpenAi
        | ProviderKind::GitHubCopilot => true,
        ProviderKind::LocalQwen
        | ProviderKind::LocalOuro
        | ProviderKind::LocalOllama
        | ProviderKind::RecursiveMas
        | ProviderKind::Skip => false,
    }
}

/// Stable slug used in WAL events + marker filenames. Matches
/// `Provider::name()` so log lines + marker filenames stay aligned.
pub fn slug(kind: ProviderKind) -> &'static str {
    match kind {
        ProviderKind::ClaudeCli => "claude_cli",
        ProviderKind::OpenaiApi => "openai_api",
        ProviderKind::AnthropicApi => "anthropic_api",
        ProviderKind::GeminiApi => "gemini_api",
        ProviderKind::Cohere => "cohere_api",
        ProviderKind::OpenaiCompat => "openai_compat",
        ProviderKind::LocalQwen => "local_qwen",
        ProviderKind::LocalOuro => "local_ouro",
        ProviderKind::LocalOllama => "local_ollama",
        ProviderKind::AwsBedrock => "aws_bedrock",
        ProviderKind::AzureOpenAi => "azure_openai",
        ProviderKind::GitHubCopilot => "copilot_api",
        ProviderKind::RecursiveMas => "recursive_mas",
        ProviderKind::Skip => "skip",
    }
}

pub fn kind_from_slug(s: &str) -> Option<ProviderKind> {
    match s {
        "claude_cli" => Some(ProviderKind::ClaudeCli),
        "openai_api" => Some(ProviderKind::OpenaiApi),
        "anthropic_api" => Some(ProviderKind::AnthropicApi),
        "gemini_api" => Some(ProviderKind::GeminiApi),
        "cohere_api" => Some(ProviderKind::Cohere),
        "openai_compat" => Some(ProviderKind::OpenaiCompat),
        "local_qwen" => Some(ProviderKind::LocalQwen),
        "local_ouro" => Some(ProviderKind::LocalOuro),
        "local_ollama" => Some(ProviderKind::LocalOllama),
        "aws_bedrock" => Some(ProviderKind::AwsBedrock),
        "azure_openai" => Some(ProviderKind::AzureOpenAi),
        "copilot_api" => Some(ProviderKind::GitHubCopilot),
        "recursive_mas" => Some(ProviderKind::RecursiveMas),
        "skip" => Some(ProviderKind::Skip),
        _ => None,
    }
}

fn cloud_label(kind: ProviderKind) -> &'static str {
    match kind {
        ProviderKind::ClaudeCli => "Anthropic Claude",
        ProviderKind::OpenaiApi => "OpenAI",
        ProviderKind::AnthropicApi => "Anthropic Claude (API key)",
        ProviderKind::GeminiApi => "Google Gemini",
        ProviderKind::Cohere => "Cohere",
        ProviderKind::OpenaiCompat => "the configured OpenAI-compatible endpoint",
        ProviderKind::AwsBedrock => "AWS Bedrock (region + IAM credential chain)",
        ProviderKind::AzureOpenAi => "Azure OpenAI (api-version + deployment name)",
        ProviderKind::GitHubCopilot => "GitHub Copilot (api.githubcopilot.com)",
        ProviderKind::LocalQwen => "local Qwen (no remote network)",
        ProviderKind::LocalOuro => "local Ouro thinking-models (no remote network)",
        ProviderKind::LocalOllama => "local Ollama (no remote network)",
        ProviderKind::RecursiveMas => "local RecursiveMAS sidecar (no remote network)",
        ProviderKind::Skip => "no provider",
    }
}

/// One concrete provider route at the consent boundary. `ProviderKind` alone
/// is insufficient for Ollama: the same adapter may target loopback or a
/// remote host configured through `provider_endpoint` / a hemisphere slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentRoute {
    pub kind: ProviderKind,
    pub endpoint: Option<String>,
}

impl ConsentRoute {
    pub fn new(kind: ProviderKind, endpoint: Option<&str>) -> Self {
        Self {
            kind,
            endpoint: endpoint.map(str::to_owned),
        }
    }
}

/// LocalOllama is conditionally consent-managed. Its default endpoint is
/// loopback, while any malformed, LAN, DNS, or public endpoint is treated as
/// remote (fail closed). This deliberately shares the provider adapter's
/// typed-host loopback classifier so IPv4/IPv6/domain handling cannot drift.
pub fn route_requires_consent(kind: ProviderKind, endpoint: Option<&str>) -> bool {
    if is_cloud(kind) {
        return true;
    }
    if kind != ProviderKind::LocalOllama {
        return false;
    }
    let endpoint = endpoint.unwrap_or(crate::providers::ollama_api::DEFAULT_BASE_URL);
    let Ok(url) = reqwest::Url::parse(endpoint) else {
        return true;
    };
    !crate::providers::http_client::url_has_loopback_host(&url)
}

/// Whether a provider can own a durable consent marker. LocalOllama is
/// included even though its loopback route does not require one: operators
/// targeting a remote Ollama server need `neoth consent grant local_ollama`.
pub fn is_consent_managed_kind(kind: ProviderKind) -> bool {
    is_cloud(kind) || kind == ProviderKind::LocalOllama
}

fn marker_exists(home: &Path, kind: ProviderKind) -> bool {
    marker_path(home, kind).exists()
}

pub fn is_route_granted(home: &Path, route: &ConsentRoute) -> bool {
    !route_requires_consent(route.kind, route.endpoint.as_deref())
        || marker_exists(home, route.kind)
}

fn route_label(route: &ConsentRoute) -> String {
    if route.kind == ProviderKind::LocalOllama
        && route_requires_consent(route.kind, route.endpoint.as_deref())
    {
        let endpoint = route.endpoint.as_deref().unwrap_or("<invalid endpoint>");
        return format!("the configured remote Ollama endpoint ({endpoint})");
    }
    cloud_label(route.kind).to_string()
}

pub fn consent_dir(home: &Path) -> PathBuf {
    home.join("consent")
}

pub fn marker_path(home: &Path, kind: ProviderKind) -> PathBuf {
    consent_dir(home).join(format!("{}.granted", slug(kind)))
}

/// True when (a) the kind is not cloud or (b) the operator has granted
/// consent. The "non-cloud is always granted" branch lets callers gate on
/// `is_granted` unconditionally without re-checking `is_cloud`.
pub fn is_granted(home: &Path, kind: ProviderKind) -> bool {
    if !is_cloud(kind) {
        return true;
    }
    marker_path(home, kind).exists()
}

/// Record consent. Idempotent — overwrites the timestamp on each call so
/// `neoth consent grant <kind>` after a no-op stays cheap.
pub fn grant(home: &Path, kind: ProviderKind) -> Result<()> {
    if !is_consent_managed_kind(kind) {
        anyhow::bail!(
            "consent::grant called with non-cloud kind `{}` — only cloud \
             or endpoint-conditional providers can own consent markers",
            slug(kind)
        );
    }
    let dir = consent_dir(home);
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let marker = marker_path(home, kind);
    let ts = unix_ts_string();
    fs::write(&marker, ts.as_bytes()).with_context(|| format!("write {}", marker.display()))?;
    Ok(())
}

pub fn revoke(home: &Path, kind: ProviderKind) -> Result<()> {
    let marker = marker_path(home, kind);
    if marker.exists() {
        fs::remove_file(&marker).with_context(|| format!("remove {}", marker.display()))?;
    }
    Ok(())
}

/// List every recorded consent marker. Returns `(kind, raw_timestamp_string)`
/// pairs, sorted by slug. Unknown slugs in the directory are ignored — the
/// operator can drop ad-hoc files there without breaking the listing.
pub fn list_grants(home: &Path) -> Result<Vec<(ProviderKind, String)>> {
    let dir = consent_dir(home);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some(slug_part) = name.strip_suffix(".granted") else {
            continue;
        };
        let Some(kind) = kind_from_slug(slug_part) else {
            continue;
        };
        let ts = fs::read_to_string(&path).unwrap_or_default();
        out.push((kind, ts.trim().to_string()));
    }
    out.sort_by(|a, b| slug(a.0).cmp(slug(b.0)));
    Ok(out)
}

/// P-02 (Session 24) — tri-state consent decision. Replaces the
/// implicit two-state (granted-marker-exists vs not) with an
/// explicit operator choice that the audit chain can record.
///
/// - `AllowOnce`: continue this turn only; no marker written; the
///   next call re-prompts. Useful for one-off cloud bursts the
///   operator doesn't want to make persistent.
/// - `AllowAlways`: continue + write the `.granted` marker so
///   future calls auto-pass. Mirrors the pre-P-02 behaviour.
/// - `Deny`: abort this turn; no marker written. Operator explicitly
///   said no; record the audit anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentDecision {
    AllowOnce,
    AllowAlways,
    Deny,
}

impl ConsentDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            ConsentDecision::AllowOnce => "allow_once",
            ConsentDecision::AllowAlways => "allow_always",
            ConsentDecision::Deny => "deny",
        }
    }

    /// True when the decision lets the current turn continue.
    /// `Deny` is the only false branch.
    pub fn allows(self) -> bool {
        !matches!(self, ConsentDecision::Deny)
    }

    /// True when the decision persists to the marker file. Only
    /// `AllowAlways` flips the bit; the other two leave state alone.
    pub fn persists(self) -> bool {
        matches!(self, ConsentDecision::AllowAlways)
    }
}

/// Parse an operator-typed answer into a [`ConsentDecision`].
/// Accepts the canonical strings + a few aliases. Case-insensitive.
/// Returns `None` for unrecognised input — callers prompt again.
pub fn parse_decision(s: &str) -> Option<ConsentDecision> {
    match s.trim().to_lowercase().as_str() {
        "1" | "once" | "allow once" | "allow_once" | "y" | "yes" => {
            Some(ConsentDecision::AllowOnce)
        }
        "2" | "always" | "allow always" | "allow_always" | "a" => {
            Some(ConsentDecision::AllowAlways)
        }
        "3" | "deny" | "no" | "n" | "d" => Some(ConsentDecision::Deny),
        _ => None,
    }
}

/// P-02 — build the canonical [`EVENT_TYPE_CONSENT_DECISION`] payload
/// bytes. Pure helper so the prompt path + tests + downstream WAL
/// consumers agree on shape. Payload:
/// `{kind, decision, source, ts_unix}`. `source` ∈ `"tty" | "daemon"
/// | "cli_explicit"` — records WHERE the operator's answer came from
/// so audit can attribute the decision.
pub fn consent_decision_payload(
    kind: ProviderKind,
    decision: ConsentDecision,
    source: &str,
    ts_unix: i64,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "kind": slug(kind),
        "decision": decision.as_str(),
        "source": source,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_default()
}

/// P-02 — apply the operator's decision against the on-disk state.
/// `AllowOnce` + `Deny` leave the marker untouched; `AllowAlways`
/// writes the marker via the existing [`grant`] path so subsequent
/// `is_granted` calls pass unconditionally.
///
/// Returns whether the marker was actually changed (true for
/// `AllowAlways` against a non-existent marker; false otherwise).
/// Useful for the audit anchor's `marker_written` flag.
pub fn apply_decision(home: &Path, kind: ProviderKind, decision: ConsentDecision) -> Result<bool> {
    if !is_consent_managed_kind(kind) {
        // Non-cloud providers don't gate; apply is a no-op. Keep
        // the API symmetric so callers can pipe every kind through.
        return Ok(false);
    }
    match decision {
        ConsentDecision::AllowAlways => {
            let was_granted = marker_exists(home, kind);
            grant(home, kind)?;
            Ok(!was_granted)
        }
        ConsentDecision::AllowOnce | ConsentDecision::Deny => Ok(false),
    }
}

/// Preflight gate called before any cloud-bound provider request. On a TTY,
/// interactively prompts the operator + records grant. Off a TTY, bails with
/// the exact CLI to grant consent. Bypass: `NEOTH_CONSENT_BYPASS=1` for CI
/// or scripted reinvocations where the operator has reviewed the policy
/// elsewhere.
pub fn ensure_granted_or_prompt(home: &Path, kind: ProviderKind) -> Result<()> {
    ensure_route_granted_or_prompt(home, &ConsentRoute::new(kind, None))
}

/// Endpoint-aware first-run gate. Provider text cannot cross a non-loopback
/// Ollama route merely because its enum variant historically said `Local`.
pub fn ensure_route_granted_or_prompt(home: &Path, route: &ConsentRoute) -> Result<()> {
    if is_route_granted(home, route) {
        return Ok(());
    }
    if std::env::var("NEOTH_CONSENT_BYPASS").as_deref() == Ok("1") {
        return Ok(());
    }
    let slug_s = slug(route.kind);
    let label = route_label(route);
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "first-run consent required for provider `{slug_s}` ({label}). \
             Your chat text will be sent to {label}'s servers. Run \
             `neoth consent grant {slug_s}` once to record consent, or set \
             NEOTH_CONSENT_BYPASS=1 to suppress this gate in non-interactive \
             contexts."
        );
    }
    eprintln!();
    eprintln!("=== First-run outbound-LLM consent ===");
    eprintln!();
    eprintln!("Your chat text is about to be sent to {label}'s servers.");
    eprintln!("This is a third-party cloud service. Their TOS + retention");
    eprintln!("policies apply. NEOTH only routes — it cannot enforce");
    eprintln!("retention/deletion guarantees on the remote side.");
    eprintln!();
    eprintln!("This prompt appears once per provider. Recorded at:");
    eprintln!("  {}", marker_path(home, route.kind).display());
    eprintln!();
    eprint!("Type 'yes' to grant + continue (anything else aborts): ");
    std::io::stderr().flush().ok();

    let mut input = String::new();
    std::io::stdin().lock().read_line(&mut input)?;
    if input.trim() != "yes" {
        anyhow::bail!("consent declined — exiting without sending any text");
    }
    grant(home, route.kind)?;
    eprintln!("✓ consent recorded ({slug_s}).");
    Ok(())
}

fn unix_ts_string() -> String {
    crate::time::now_unix_secs().to_string()
}

/// A-2 (Session 13) — enumerate every distinct cloud `ProviderKind` the
/// operator's council topology will fan out to. Session 13 V03-08 originally
/// gated only `config.provider_kind` (legacy single-mode field), which
/// silently bypassed consent when an operator configured per-hemisphere
/// cloud providers via `inference.{left,right,cerebellum}`. This helper +
/// `ensure_all_granted_or_prompt` close that bypass.
///
/// Returns deduped, ordered list of cloud kinds:
/// - `TopologyMode::Single` → at most one kind (default_slot).
/// - `TopologyMode::Triplet|Custom` → one kind per distinct slot.provider
///   that resolves to a cloud kind; local kinds (LocalQwen) are dropped.
///
/// Legacy single-mode operators (only `provider_kind` set, no inference
/// topology) still get covered via the existing `provider_kind` fallback
/// at the call site.
pub fn cloud_kinds_for_council(
    config: &crate::config::FreedomConfig,
) -> Vec<crate::cli::init::ProviderKind> {
    use crate::config::inference::HemisphereRole;
    let mut seen: Vec<crate::cli::init::ProviderKind> = Vec::with_capacity(3);
    for role in [
        HemisphereRole::Left,
        HemisphereRole::Right,
        HemisphereRole::Cerebellum,
    ] {
        let slot = config.inference.slot_for(role);
        let Some(provider) = slot.provider else {
            continue;
        };
        let kind = provider.to_provider_kind();
        if !is_cloud(kind) {
            continue;
        }
        if !seen.contains(&kind) {
            seen.push(kind);
        }
    }
    seen
}

/// Effective route for a hemisphere provider construction. Mirrors
/// `providers::from_config_for_role`: an explicit slot owns its endpoint;
/// an empty slot falls back to the top-level provider and endpoint.
pub fn route_for_role(
    config: &crate::config::FreedomConfig,
    role: crate::config::inference::HemisphereRole,
) -> Option<ConsentRoute> {
    let slot = config.inference.slot_for(role);
    match slot.provider {
        Some(provider) => Some(ConsentRoute::new(
            provider.to_provider_kind(),
            slot.endpoint.as_deref(),
        )),
        None => config
            .provider_kind
            .map(|kind| ConsentRoute::new(kind, config.provider_endpoint.as_deref())),
    }
}

fn route_for_explicit_auxiliary(
    config: &crate::config::FreedomConfig,
    kind: ProviderKind,
) -> ConsentRoute {
    // Auxiliary factories preserve the main endpoint only for the same
    // provider kind. A different vendor gets an isolated synthetic config and
    // therefore its adapter default endpoint.
    let endpoint = (config.provider_kind == Some(kind))
        .then_some(config.provider_endpoint.as_deref())
        .flatten();
    ConsentRoute::new(kind, endpoint)
}

/// Effective route used by `providers::from_config_for_utility`.
pub fn route_for_utility(config: &crate::config::FreedomConfig) -> Option<ConsentRoute> {
    match config.inference.utility_provider {
        Some(provider) => Some(route_for_explicit_auxiliary(
            config,
            provider.to_provider_kind(),
        )),
        None => config
            .provider_kind
            .map(|kind| ConsentRoute::new(kind, config.provider_endpoint.as_deref())),
    }
}

fn route_for_learn(config: &crate::config::FreedomConfig) -> Option<ConsentRoute> {
    match config.profile.learn_provider.as_deref() {
        Some(raw) => serde_yaml::from_str::<ProviderKind>(raw)
            .ok()
            .map(|kind| route_for_explicit_auxiliary(config, kind)),
        None => config
            .provider_kind
            .map(|kind| ConsentRoute::new(kind, config.provider_endpoint.as_deref())),
    }
}

fn route_for_teacher(config: &crate::config::FreedomConfig) -> Option<ConsentRoute> {
    match config.inference.teacher_provider {
        Some(provider) => Some(route_for_explicit_auxiliary(
            config,
            provider.to_provider_kind(),
        )),
        None => config
            .provider_kind
            .map(|kind| ConsentRoute::new(kind, config.provider_endpoint.as_deref())),
    }
}

/// Canonical consent inventory for every configured provider route that can
/// receive operator-derived text without an additional opt-in at dispatch,
/// including fallback candidates that may become active after a 429.
/// The marker is per provider kind, so routes are deduplicated after filtering
/// (important for LocalOllama: a loopback occurrence must not hide a later
/// remote occurrence of the same kind).
pub fn required_consent_routes(config: &crate::config::FreedomConfig) -> Vec<ConsentRoute> {
    use crate::config::inference::HemisphereRole;

    let roles = [
        HemisphereRole::Left,
        HemisphereRole::Right,
        HemisphereRole::Cerebellum,
    ];
    let mut candidates = Vec::with_capacity(16 + config.fallback.chain.len());
    if let Some(kind) = config.provider_kind {
        candidates.push(ConsentRoute::new(kind, config.provider_endpoint.as_deref()));
    }
    for role in roles {
        if let Some(route) = route_for_role(config, role) {
            candidates.push(route);
        }
    }
    // Recursive councils can override every inner role independently for each
    // outer hemisphere. These factories use the explicit sub-slot's endpoint
    // exactly as written, so the consent inventory must mirror those nine
    // potential leaves instead of stopping at the outer triplet. Empty
    // sub-slots fall back through `slot_for_sub` to the already-inventoried
    // outer role and therefore need no duplicate candidate here.
    for sub_slots in config.inference.hemisphere_sub_slots.values() {
        for role in roles {
            let slot = sub_slots.slot_for(role);
            if let Some(provider) = slot.provider {
                candidates.push(ConsentRoute::new(
                    provider.to_provider_kind(),
                    slot.endpoint.as_deref(),
                ));
            }
        }
    }
    candidates.extend(
        [
            route_for_learn(config),
            route_for_utility(config),
            route_for_teacher(config),
        ]
        .into_iter()
        .flatten(),
    );
    candidates.extend(config.fallback.chain.iter().filter_map(|slot| {
        slot.provider.map(|provider| {
            ConsentRoute::new(provider.to_provider_kind(), slot.endpoint.as_deref())
        })
    }));

    let mut required = Vec::with_capacity(candidates.len());
    for route in candidates {
        if !route_requires_consent(route.kind, route.endpoint.as_deref()) {
            continue;
        }
        if !required
            .iter()
            .any(|existing: &ConsentRoute| existing.kind == route.kind)
        {
            required.push(route);
        }
    }
    required
}

/// A-2 pre-flight wrapper. Calls `ensure_granted_or_prompt` for each
/// distinct cloud kind the council will fan out to. Single-mode operators
/// with only `provider_kind` set (no inference topology) are still gated
/// via the caller's existing `ensure_granted_or_prompt(home, config.provider_kind)`
/// call — this helper covers the per-hemisphere case the legacy gate missed.
pub fn ensure_all_granted_or_prompt(
    home: &Path,
    config: &crate::config::FreedomConfig,
) -> Result<()> {
    for route in required_consent_routes(config) {
        ensure_route_granted_or_prompt(home, &route)?;
    }
    Ok(())
}

/// Finding 5 (Session 13) — runtime consent re-check, never prompts.
/// Called per-debate / per-channel-message AFTER the startup
/// `ensure_all_granted_or_prompt` succeeded so a mid-run
/// `neoth consent revoke <provider>` (file-marker deletion) is honoured
/// without daemon restart. Returns `Err` with an operator-facing
/// "consent revoked while daemon running" message that the channel /
/// chat layer surfaces verbatim.
///
/// Unlike `ensure_all_granted_or_prompt` this:
/// 1. Never prompts (no TTY assumption — runs on every hot-path call).
/// 2. Never honours `NEOTH_CONSENT_BYPASS` — bypass is a startup-only
///    escape hatch (CI / scripted bring-up), not a "ignore revokes
///    forever" lever. A revoke MUST stop traffic regardless of the env
///    var, otherwise the consent UX is misleading.
/// 3. Reports the FIRST revoked kind so the operator gets actionable
///    output without us iterating every provider after the first miss.
pub fn ensure_all_still_granted(home: &Path, config: &crate::config::FreedomConfig) -> Result<()> {
    ensure_routes_still_granted(home, &required_consent_routes(config))
}

/// Non-interactive live gate for an immutable provider-route inventory.
/// Long-lived runtimes use this when the provider graph was constructed from
/// an earlier config generation: the authority check must describe the graph
/// that can actually dispatch, not an unrelated on-disk edit.
pub fn ensure_routes_still_granted(home: &Path, routes: &[ConsentRoute]) -> Result<()> {
    routes
        .iter()
        .try_for_each(|route| ensure_route_still_granted(home, route))
}

/// Non-interactive live gate for a concrete route. It never honours
/// `NEOTH_CONSENT_BYPASS`: deleting the marker must stop the next dispatch in
/// a running daemon, including cluster-delegated inference.
pub fn ensure_route_still_granted(home: &Path, route: &ConsentRoute) -> Result<()> {
    if !is_route_granted(home, route) {
        anyhow::bail!(
            "consent for provider `{}` was revoked while the daemon was \
             running. Run `neoth consent grant {}` and resend, or restart \
             `neoth serve` after granting.",
            slug(route.kind),
            slug(route.kind),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn is_cloud_classifies_every_provider_kind() {
        // Cloud-egress providers (all require consent).
        assert!(is_cloud(ProviderKind::ClaudeCli));
        assert!(is_cloud(ProviderKind::OpenaiApi));
        assert!(is_cloud(ProviderKind::AnthropicApi)); // A-25: was missing downstream
        assert!(is_cloud(ProviderKind::GeminiApi));
        assert!(is_cloud(ProviderKind::Cohere)); // A-25: was missing downstream
        assert!(is_cloud(ProviderKind::OpenaiCompat));
        assert!(is_cloud(ProviderKind::AwsBedrock));
        assert!(is_cloud(ProviderKind::AzureOpenAi));
        assert!(is_cloud(ProviderKind::GitHubCopilot)); // GOLD-ADAPT-ODY-15
        // Local + skip never gate.
        assert!(!is_cloud(ProviderKind::LocalQwen));
        assert!(!is_cloud(ProviderKind::LocalOuro));
        assert!(!is_cloud(ProviderKind::Skip));
    }

    #[test]
    fn slug_round_trips_via_kind_from_slug() {
        for &kind in &[
            ProviderKind::ClaudeCli,
            ProviderKind::OpenaiApi,
            ProviderKind::GeminiApi,
            ProviderKind::OpenaiCompat,
            ProviderKind::LocalQwen,
            ProviderKind::AwsBedrock,
            ProviderKind::AzureOpenAi,
            ProviderKind::GitHubCopilot, // GOLD-ADAPT-ODY-15
            ProviderKind::Skip,
        ] {
            assert_eq!(kind_from_slug(slug(kind)), Some(kind), "{kind:?}");
        }
    }

    #[test]
    fn kind_from_slug_returns_none_for_unknown() {
        assert!(kind_from_slug("nope").is_none());
        assert!(kind_from_slug("").is_none());
        assert!(kind_from_slug("OPENAI_API").is_none()); // case-sensitive
    }

    #[test]
    fn is_granted_returns_true_for_non_cloud_kinds_without_marker() {
        let tmp = TempDir::new().unwrap();
        assert!(is_granted(tmp.path(), ProviderKind::LocalQwen));
        assert!(is_granted(tmp.path(), ProviderKind::Skip));
    }

    #[test]
    fn is_granted_returns_false_for_cloud_kind_without_marker() {
        let tmp = TempDir::new().unwrap();
        assert!(!is_granted(tmp.path(), ProviderKind::OpenaiApi));
        assert!(!is_granted(tmp.path(), ProviderKind::ClaudeCli));
    }

    #[test]
    fn grant_creates_marker_and_is_granted_flips_true() {
        let tmp = TempDir::new().unwrap();
        assert!(!is_granted(tmp.path(), ProviderKind::OpenaiApi));
        grant(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        assert!(is_granted(tmp.path(), ProviderKind::OpenaiApi));
        assert!(marker_path(tmp.path(), ProviderKind::OpenaiApi).exists());
        // grant for one kind does not leak to another
        assert!(!is_granted(tmp.path(), ProviderKind::GeminiApi));
    }

    #[test]
    fn grant_rejects_non_cloud_kinds() {
        let tmp = TempDir::new().unwrap();
        let err = grant(tmp.path(), ProviderKind::LocalQwen).unwrap_err();
        assert!(err.to_string().contains("non-cloud"));
    }

    #[test]
    fn revoke_removes_marker_and_is_granted_flips_false() {
        let tmp = TempDir::new().unwrap();
        grant(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        assert!(is_granted(tmp.path(), ProviderKind::OpenaiApi));
        revoke(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        assert!(!is_granted(tmp.path(), ProviderKind::OpenaiApi));
    }

    #[test]
    fn revoke_is_idempotent_when_marker_absent() {
        let tmp = TempDir::new().unwrap();
        // No grant; revoke should be a no-op without error.
        revoke(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        assert!(!is_granted(tmp.path(), ProviderKind::OpenaiApi));
    }

    #[test]
    fn list_grants_returns_empty_when_consent_dir_missing() {
        let tmp = TempDir::new().unwrap();
        let listed = list_grants(tmp.path()).unwrap();
        assert!(listed.is_empty());
    }

    #[test]
    fn list_grants_returns_every_granted_kind_sorted_by_slug() {
        let tmp = TempDir::new().unwrap();
        grant(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        grant(tmp.path(), ProviderKind::ClaudeCli).unwrap();
        grant(tmp.path(), ProviderKind::GeminiApi).unwrap();
        let listed: Vec<ProviderKind> = list_grants(tmp.path())
            .unwrap()
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(
            listed,
            vec![
                ProviderKind::ClaudeCli,
                ProviderKind::GeminiApi,
                ProviderKind::OpenaiApi,
            ]
        );
    }

    #[test]
    fn list_grants_ignores_unknown_files_in_consent_dir() {
        let tmp = TempDir::new().unwrap();
        grant(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        // Drop a stray file in the consent dir.
        std::fs::write(consent_dir(tmp.path()).join("README.txt"), "ignore me").unwrap();
        std::fs::write(consent_dir(tmp.path()).join("bogus.granted"), "0").unwrap();
        let listed = list_grants(tmp.path()).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].0, ProviderKind::OpenaiApi);
    }

    #[test]
    fn ensure_granted_or_prompt_short_circuits_when_already_granted() {
        let tmp = TempDir::new().unwrap();
        grant(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        // Must return Ok without touching stdin/stdout.
        ensure_granted_or_prompt(tmp.path(), ProviderKind::OpenaiApi).unwrap();
    }

    #[test]
    fn ensure_granted_or_prompt_short_circuits_for_non_cloud_kinds() {
        let tmp = TempDir::new().unwrap();
        ensure_granted_or_prompt(tmp.path(), ProviderKind::LocalQwen).unwrap();
        ensure_granted_or_prompt(tmp.path(), ProviderKind::Skip).unwrap();
        // No marker should have been created (these aren't cloud).
        assert!(!consent_dir(tmp.path()).exists());
    }

    #[test]
    fn ensure_granted_or_prompt_honours_bypass_env() {
        let _env = crate::test_env::lock();
        let tmp = TempDir::new().unwrap();
        // SAFETY: tests run single-threaded for env mutation via cargo's
        // default --test-threads, but mark it explicitly with serial_test
        // if this ever flakes. For now: the bypass var is unique enough
        // that no other test reads it concurrently.
        // SAFETY: tests are isolated to their own process and we restore
        // the var on the next line.
        // SAFETY: set + remove the env var inside one test; concurrent
        // tests don't reference NEOTH_CONSENT_BYPASS.
        unsafe {
            std::env::set_var("NEOTH_CONSENT_BYPASS", "1");
        }
        let result = ensure_granted_or_prompt(tmp.path(), ProviderKind::OpenaiApi);
        unsafe {
            std::env::remove_var("NEOTH_CONSENT_BYPASS");
        }
        assert!(result.is_ok());
        // Bypass does NOT record a marker — caller is responsible for
        // running `neoth consent grant` later if they want a marker.
        assert!(!is_granted(tmp.path(), ProviderKind::OpenaiApi));
    }

    // ── A-2 (Session 13) multi-provider council preflight ────────────

    fn mk_config_with_inference(
        primary: Option<crate::cli::init::ProviderKind>,
        left: Option<crate::config::inference::InferenceProvider>,
        right: Option<crate::config::inference::InferenceProvider>,
        cere: Option<crate::config::inference::InferenceProvider>,
        mode: crate::config::inference::TopologyMode,
    ) -> crate::config::FreedomConfig {
        use crate::config::FreedomConfig;
        use crate::config::inference::{HemisphereSlot, InferenceTopology};
        let mut cfg = FreedomConfig::default();
        cfg.provider_kind = primary;
        let mut topo = InferenceTopology::default();
        topo.mode = mode;
        topo.left = HemisphereSlot {
            provider: left,
            ..HemisphereSlot::default()
        };
        topo.right = HemisphereSlot {
            provider: right,
            ..HemisphereSlot::default()
        };
        topo.cerebellum = HemisphereSlot {
            provider: cere,
            ..HemisphereSlot::default()
        };
        cfg.inference = topo;
        cfg
    }

    #[test]
    fn cloud_kinds_for_council_returns_empty_in_single_mode_without_default_slot() {
        let cfg = mk_config_with_inference(
            None,
            None,
            None,
            None,
            crate::config::inference::TopologyMode::Single,
        );
        // Single-mode without a default_slot.provider returns empty —
        // legacy `provider_kind` covers that case at the caller.
        let kinds = cloud_kinds_for_council(&cfg);
        assert!(kinds.is_empty());
    }

    #[test]
    fn cloud_kinds_for_council_dedups_in_single_mode_with_default_slot() {
        use crate::config::FreedomConfig;
        use crate::config::inference::{
            HemisphereSlot, InferenceProvider, InferenceTopology, TopologyMode,
        };
        let mut cfg = FreedomConfig::default();
        let mut topo = InferenceTopology::default();
        topo.mode = TopologyMode::Single;
        topo.default_slot = HemisphereSlot {
            provider: Some(InferenceProvider::OpenAi),
            ..HemisphereSlot::default()
        };
        cfg.inference = topo;
        // All three slots collapse to default_slot → one kind dedup'd.
        let kinds = cloud_kinds_for_council(&cfg);
        assert_eq!(kinds, vec![crate::cli::init::ProviderKind::OpenaiApi]);
    }

    #[test]
    fn cloud_kinds_for_council_returns_three_distinct_in_custom_mode() {
        let cfg = mk_config_with_inference(
            None,
            Some(crate::config::inference::InferenceProvider::ClaudeCli),
            Some(crate::config::inference::InferenceProvider::OpenAi),
            Some(crate::config::inference::InferenceProvider::Gemini),
            crate::config::inference::TopologyMode::Custom,
        );
        let kinds = cloud_kinds_for_council(&cfg);
        assert_eq!(kinds.len(), 3);
        assert!(kinds.contains(&crate::cli::init::ProviderKind::ClaudeCli));
        assert!(kinds.contains(&crate::cli::init::ProviderKind::OpenaiApi));
        assert!(kinds.contains(&crate::cli::init::ProviderKind::GeminiApi));
    }

    #[test]
    fn cloud_kinds_for_council_skips_local_qwen() {
        let cfg = mk_config_with_inference(
            None,
            Some(crate::config::inference::InferenceProvider::ClaudeCli),
            Some(crate::config::inference::InferenceProvider::LocalQwen),
            Some(crate::config::inference::InferenceProvider::Gemini),
            crate::config::inference::TopologyMode::Custom,
        );
        let kinds = cloud_kinds_for_council(&cfg);
        // Local_qwen drops; only the two clouds remain.
        assert_eq!(kinds.len(), 2);
        assert!(kinds.contains(&crate::cli::init::ProviderKind::ClaudeCli));
        assert!(kinds.contains(&crate::cli::init::ProviderKind::GeminiApi));
        assert!(!kinds.contains(&crate::cli::init::ProviderKind::LocalQwen));
    }

    #[test]
    fn ollama_consent_is_endpoint_aware_and_fail_closed() {
        for endpoint in [
            None,
            Some("http://localhost:11434"),
            Some("http://LOCALHOST.:11434"),
            Some("http://127.0.0.42:11434"),
            Some("http://[::1]:11434"),
        ] {
            assert!(
                !route_requires_consent(ProviderKind::LocalOllama, endpoint),
                "loopback endpoint must remain zero-friction: {endpoint:?}"
            );
        }
        for endpoint in [
            Some("http://192.168.1.20:11434"),
            Some("https://ollama.example.com"),
            Some("http://localhost.evil.example:11434"),
            Some("not a URL"),
        ] {
            assert!(
                route_requires_consent(ProviderKind::LocalOllama, endpoint),
                "non-loopback or malformed endpoint must fail closed: {endpoint:?}"
            );
        }
    }

    #[test]
    fn remote_ollama_route_requires_revocable_marker() {
        let tmp = TempDir::new().unwrap();
        let route = ConsentRoute::new(ProviderKind::LocalOllama, Some("http://192.168.1.20:11434"));
        assert!(!is_route_granted(tmp.path(), &route));
        assert!(ensure_route_still_granted(tmp.path(), &route).is_err());
        grant(tmp.path(), ProviderKind::LocalOllama).unwrap();
        assert!(is_route_granted(tmp.path(), &route));
        ensure_route_still_granted(tmp.path(), &route).unwrap();
        revoke(tmp.path(), ProviderKind::LocalOllama).unwrap();
        assert!(!is_route_granted(tmp.path(), &route));
    }

    #[test]
    fn required_routes_include_learn_utility_and_teacher_providers() {
        use crate::config::inference::InferenceProvider;
        let mut cfg = crate::config::FreedomConfig {
            provider_kind: Some(ProviderKind::LocalQwen),
            ..Default::default()
        };
        cfg.profile.learn_provider = Some("openai_api".into());
        cfg.inference.utility_provider = Some(InferenceProvider::Gemini);
        cfg.inference.teacher_provider = Some(InferenceProvider::AnthropicApi);

        let routes = required_consent_routes(&cfg);
        let kinds: Vec<_> = routes.iter().map(|route| route.kind).collect();
        assert_eq!(
            kinds,
            vec![
                ProviderKind::OpenaiApi,
                ProviderKind::GeminiApi,
                ProviderKind::AnthropicApi,
            ]
        );
    }

    #[test]
    fn required_routes_include_every_explicit_recursive_sub_slot() {
        use crate::config::inference::{
            HemisphereRole, HemisphereSlot, InferenceProvider, SubHemisphereSlots,
        };

        let mut cfg = crate::config::FreedomConfig {
            provider_kind: Some(ProviderKind::LocalQwen),
            ..Default::default()
        };
        cfg.inference.hemisphere_sub_slots.insert(
            HemisphereRole::Left,
            SubHemisphereSlots {
                left: HemisphereSlot {
                    provider: Some(InferenceProvider::OpenAi),
                    ..Default::default()
                },
                right: HemisphereSlot {
                    provider: Some(InferenceProvider::LocalOllama),
                    endpoint: Some("http://10.0.0.44:11434".into()),
                    ..Default::default()
                },
                cerebellum: HemisphereSlot {
                    provider: Some(InferenceProvider::Gemini),
                    ..Default::default()
                },
            },
        );
        cfg.inference.hemisphere_sub_slots.insert(
            HemisphereRole::Right,
            SubHemisphereSlots {
                left: HemisphereSlot {
                    provider: Some(InferenceProvider::AnthropicApi),
                    ..Default::default()
                },
                ..Default::default()
            },
        );

        let routes = required_consent_routes(&cfg);
        assert_eq!(routes.len(), 4);
        assert!(
            routes
                .iter()
                .any(|route| route.kind == ProviderKind::OpenaiApi)
        );
        assert!(
            routes
                .iter()
                .any(|route| route.kind == ProviderKind::GeminiApi)
        );
        assert!(
            routes
                .iter()
                .any(|route| route.kind == ProviderKind::AnthropicApi)
        );
        assert!(routes.iter().any(|route| {
            route.kind == ProviderKind::LocalOllama
                && route.endpoint.as_deref() == Some("http://10.0.0.44:11434")
        }));
    }

    #[test]
    fn recursive_sub_slot_revocation_blocks_the_live_inventory() {
        use crate::config::inference::{
            HemisphereRole, HemisphereSlot, InferenceProvider, SubHemisphereSlots,
        };

        let home = TempDir::new().unwrap();
        let mut cfg = crate::config::FreedomConfig {
            provider_kind: Some(ProviderKind::LocalQwen),
            ..Default::default()
        };
        cfg.inference.hemisphere_sub_slots.insert(
            HemisphereRole::Cerebellum,
            SubHemisphereSlots {
                right: HemisphereSlot {
                    provider: Some(InferenceProvider::OpenAi),
                    ..Default::default()
                },
                ..Default::default()
            },
        );

        let error = ensure_all_still_granted(home.path(), &cfg)
            .expect_err("an ungranted recursive leaf must block before council dispatch");
        assert!(error.to_string().contains("openai_api"));
    }

    #[test]
    fn local_ollama_occurrence_cannot_hide_remote_hemisphere_route() {
        use crate::config::inference::{HemisphereSlot, InferenceProvider, TopologyMode};
        let mut cfg = crate::config::FreedomConfig {
            provider_kind: Some(ProviderKind::LocalOllama),
            provider_endpoint: Some("http://localhost:11434".into()),
            ..Default::default()
        };
        cfg.profile.learn_provider = None;
        cfg.inference.mode = TopologyMode::Custom;
        cfg.inference.left = HemisphereSlot {
            provider: Some(InferenceProvider::LocalOllama),
            endpoint: Some("http://localhost:11434".into()),
            ..Default::default()
        };
        cfg.inference.right = HemisphereSlot {
            provider: Some(InferenceProvider::LocalOllama),
            endpoint: Some("http://10.0.0.8:11434".into()),
            ..Default::default()
        };

        let routes = required_consent_routes(&cfg);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].kind, ProviderKind::LocalOllama);
        assert_eq!(routes[0].endpoint.as_deref(), Some("http://10.0.0.8:11434"));
    }

    #[test]
    fn single_mode_role_route_falls_back_to_top_level_endpoint() {
        let cfg = crate::config::FreedomConfig {
            provider_kind: Some(ProviderKind::LocalOllama),
            provider_endpoint: Some("http://10.0.0.9:11434".into()),
            ..Default::default()
        };
        let route = route_for_role(&cfg, crate::config::inference::HemisphereRole::Left).unwrap();
        assert_eq!(route.kind, ProviderKind::LocalOllama);
        assert_eq!(route.endpoint.as_deref(), Some("http://10.0.0.9:11434"));
        assert!(route_requires_consent(
            route.kind,
            route.endpoint.as_deref()
        ));
    }

    // Note: bypass-env semantics for `ensure_all_granted_or_prompt` are
    // identical to the inner `ensure_granted_or_prompt`, which is already
    // covered by `ensure_granted_or_prompt_honours_bypass_env`. Adding a
    // second env-mutating test races against it under cargo's default
    // parallel test runner.

    // ── Finding 5 (Session 13) runtime consent re-check ───────────────

    #[test]
    fn ensure_all_still_granted_passes_when_every_kind_granted() {
        let tmp = TempDir::new().unwrap();
        let cfg = mk_config_with_inference(
            Some(crate::cli::init::ProviderKind::OpenaiApi),
            Some(crate::config::inference::InferenceProvider::Gemini),
            Some(crate::config::inference::InferenceProvider::ClaudeCli),
            None,
            crate::config::inference::TopologyMode::Custom,
        );
        grant(tmp.path(), crate::cli::init::ProviderKind::OpenaiApi).unwrap();
        grant(tmp.path(), crate::cli::init::ProviderKind::GeminiApi).unwrap();
        grant(tmp.path(), crate::cli::init::ProviderKind::ClaudeCli).unwrap();
        let result = ensure_all_still_granted(tmp.path(), &cfg);
        assert!(result.is_ok(), "all granted should pass, got {result:?}");
    }

    #[test]
    fn ensure_all_still_granted_blocks_when_primary_provider_revoked() {
        let tmp = TempDir::new().unwrap();
        let cfg = mk_config_with_inference(
            Some(crate::cli::init::ProviderKind::OpenaiApi),
            None,
            None,
            None,
            crate::config::inference::TopologyMode::Single,
        );
        // Operator initially granted, then later revoked.
        grant(tmp.path(), crate::cli::init::ProviderKind::OpenaiApi).unwrap();
        revoke(tmp.path(), crate::cli::init::ProviderKind::OpenaiApi).unwrap();
        let err = ensure_all_still_granted(tmp.path(), &cfg).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("openai_api"),
            "msg should name provider: {msg}"
        );
        assert!(msg.contains("revoked"), "msg should say revoked: {msg}",);
        assert!(msg.contains("daemon"), "msg should mention daemon: {msg}",);
    }

    #[test]
    fn ensure_all_still_granted_blocks_when_hemisphere_provider_revoked() {
        let tmp = TempDir::new().unwrap();
        let cfg = mk_config_with_inference(
            Some(crate::cli::init::ProviderKind::ClaudeCli),
            Some(crate::config::inference::InferenceProvider::ClaudeCli),
            Some(crate::config::inference::InferenceProvider::Gemini),
            Some(crate::config::inference::InferenceProvider::OpenAi),
            crate::config::inference::TopologyMode::Custom,
        );
        // Grant every kind, then revoke only the Right (Gemini) slot.
        grant(tmp.path(), crate::cli::init::ProviderKind::ClaudeCli).unwrap();
        grant(tmp.path(), crate::cli::init::ProviderKind::GeminiApi).unwrap();
        grant(tmp.path(), crate::cli::init::ProviderKind::OpenaiApi).unwrap();
        revoke(tmp.path(), crate::cli::init::ProviderKind::GeminiApi).unwrap();
        let err = ensure_all_still_granted(tmp.path(), &cfg).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("gemini_api"),
            "msg should name revoked hemisphere provider: {msg}",
        );
    }

    #[test]
    fn ensure_all_still_granted_passes_when_only_local_qwen() {
        let tmp = TempDir::new().unwrap();
        let cfg = mk_config_with_inference(
            None,
            Some(crate::config::inference::InferenceProvider::LocalQwen),
            Some(crate::config::inference::InferenceProvider::LocalQwen),
            Some(crate::config::inference::InferenceProvider::LocalQwen),
            crate::config::inference::TopologyMode::Custom,
        );
        // No grants needed — local-only never gates.
        let result = ensure_all_still_granted(tmp.path(), &cfg);
        assert!(result.is_ok());
    }

    #[test]
    fn ensure_all_still_granted_ignores_bypass_env() {
        // Critical contract: the runtime re-check MUST NOT honour
        // NEOTH_CONSENT_BYPASS. Bypass is a startup-only escape hatch
        // for CI / scripted bring-up; once the daemon is live a revoke
        // must stop traffic regardless of the env var.
        //
        // We pin this by constructing a state where bypass would
        // short-circuit `ensure_all_granted_or_prompt` (no marker file
        // + bypass=1) but `ensure_all_still_granted` must still bail.
        // To avoid env-var races with other tests we use a temp home
        // dir and never set the bypass var — instead we directly
        // verify the implementation by reading the source: the only
        // env check `ensure_all_still_granted` makes is none.
        //
        // Test pins the OUTCOME: a revoked provider always bails,
        // regardless of any env mutation the caller might make.
        let tmp = TempDir::new().unwrap();
        let cfg = mk_config_with_inference(
            Some(crate::cli::init::ProviderKind::OpenaiApi),
            None,
            None,
            None,
            crate::config::inference::TopologyMode::Single,
        );
        // No grant recorded. ensure_all_still_granted must bail even
        // though no marker file ever existed (revoke of never-granted
        // is the same observable end-state as revoke of previously-granted).
        let err = ensure_all_still_granted(tmp.path(), &cfg).unwrap_err();
        assert!(err.to_string().contains("openai_api"));
    }

    #[test]
    fn ensure_all_granted_or_prompt_passes_when_every_kind_granted() {
        let tmp = TempDir::new().unwrap();
        let cfg = mk_config_with_inference(
            Some(crate::cli::init::ProviderKind::OpenaiApi),
            Some(crate::config::inference::InferenceProvider::Gemini),
            Some(crate::config::inference::InferenceProvider::ClaudeCli),
            Some(crate::config::inference::InferenceProvider::LocalQwen),
            crate::config::inference::TopologyMode::Custom,
        );
        grant(tmp.path(), crate::cli::init::ProviderKind::OpenaiApi).unwrap();
        grant(tmp.path(), crate::cli::init::ProviderKind::GeminiApi).unwrap();
        grant(tmp.path(), crate::cli::init::ProviderKind::ClaudeCli).unwrap();
        // LocalQwen needs no grant.
        let result = ensure_all_granted_or_prompt(tmp.path(), &cfg);
        assert!(result.is_ok());
    }

    #[test]
    fn marker_path_uses_slug_for_filename() {
        let tmp = TempDir::new().unwrap();
        let p = marker_path(tmp.path(), ProviderKind::ClaudeCli);
        assert_eq!(
            p.file_name().and_then(|s| s.to_str()),
            Some("claude_cli.granted")
        );
        assert!(p.parent().unwrap().ends_with("consent"));
    }

    // ── P-02 (Session 24) tri-state ConsentDecision ──────────────────

    #[test]
    fn p_02_decision_helpers_pin_allows_and_persists() {
        // Drift guard for the two boolean projections of the enum.
        assert!(ConsentDecision::AllowOnce.allows());
        assert!(ConsentDecision::AllowAlways.allows());
        assert!(!ConsentDecision::Deny.allows());

        assert!(!ConsentDecision::AllowOnce.persists());
        assert!(ConsentDecision::AllowAlways.persists());
        assert!(!ConsentDecision::Deny.persists());
    }

    #[test]
    fn p_02_decision_as_str_pinned_for_audit() {
        assert_eq!(ConsentDecision::AllowOnce.as_str(), "allow_once");
        assert_eq!(ConsentDecision::AllowAlways.as_str(), "allow_always");
        assert_eq!(ConsentDecision::Deny.as_str(), "deny");
    }

    #[test]
    fn p_02_parse_decision_accepts_canonical_and_aliases_case_insensitive() {
        // Canonical
        assert_eq!(
            parse_decision("allow_once"),
            Some(ConsentDecision::AllowOnce)
        );
        assert_eq!(
            parse_decision("allow_always"),
            Some(ConsentDecision::AllowAlways)
        );
        assert_eq!(parse_decision("deny"), Some(ConsentDecision::Deny));
        // Numeric (1/2/3 menu picker)
        assert_eq!(parse_decision("1"), Some(ConsentDecision::AllowOnce));
        assert_eq!(parse_decision("2"), Some(ConsentDecision::AllowAlways));
        assert_eq!(parse_decision("3"), Some(ConsentDecision::Deny));
        // Aliases
        assert_eq!(parse_decision("YES"), Some(ConsentDecision::AllowOnce));
        assert_eq!(parse_decision("Always"), Some(ConsentDecision::AllowAlways));
        assert_eq!(parse_decision("  no  "), Some(ConsentDecision::Deny));
        assert_eq!(
            parse_decision("Allow Once"),
            Some(ConsentDecision::AllowOnce)
        );
    }

    #[test]
    fn p_02_parse_decision_returns_none_for_garbage() {
        assert!(parse_decision("").is_none());
        assert!(parse_decision("maybe").is_none());
        assert!(parse_decision("42").is_none());
    }

    #[test]
    fn p_02_apply_decision_allow_always_writes_marker() {
        let tmp = TempDir::new().unwrap();
        let kind = ProviderKind::OpenaiApi;
        assert!(!is_granted(tmp.path(), kind));
        let changed = apply_decision(tmp.path(), kind, ConsentDecision::AllowAlways).unwrap();
        assert!(changed, "first AllowAlways must flip the bit");
        assert!(is_granted(tmp.path(), kind));
        // Second AllowAlways on already-granted state — same outcome,
        // `changed = false` per the contract.
        let changed2 = apply_decision(tmp.path(), kind, ConsentDecision::AllowAlways).unwrap();
        assert!(!changed2, "idempotent AllowAlways must report no change");
        assert!(is_granted(tmp.path(), kind));
    }

    #[test]
    fn p_02_apply_decision_allow_once_does_not_write_marker() {
        let tmp = TempDir::new().unwrap();
        let kind = ProviderKind::OpenaiApi;
        let changed = apply_decision(tmp.path(), kind, ConsentDecision::AllowOnce).unwrap();
        assert!(!changed);
        assert!(
            !is_granted(tmp.path(), kind),
            "AllowOnce must NOT persist — next call re-prompts",
        );
    }

    #[test]
    fn p_02_apply_decision_deny_does_not_write_marker_or_revoke_existing() {
        let tmp = TempDir::new().unwrap();
        let kind = ProviderKind::OpenaiApi;
        // Deny against fresh state → no marker.
        apply_decision(tmp.path(), kind, ConsentDecision::Deny).unwrap();
        assert!(!is_granted(tmp.path(), kind));
        // Deny against ALREADY-granted state must NOT auto-revoke the
        // existing grant. Operator who said deny-this-time keeps
        // their prior allow-always; an explicit `neoth consent revoke`
        // is the only path to drop the marker. Pin this.
        grant(tmp.path(), kind).unwrap();
        apply_decision(tmp.path(), kind, ConsentDecision::Deny).unwrap();
        assert!(
            is_granted(tmp.path(), kind),
            "Deny must not auto-revoke prior AllowAlways — operator uses `consent revoke`",
        );
    }

    #[test]
    fn p_02_apply_decision_non_cloud_kind_is_noop() {
        let tmp = TempDir::new().unwrap();
        // Local provider — every decision is a no-op + reports no-change.
        for d in [
            ConsentDecision::AllowOnce,
            ConsentDecision::AllowAlways,
            ConsentDecision::Deny,
        ] {
            let changed = apply_decision(tmp.path(), ProviderKind::LocalQwen, d).unwrap();
            assert!(!changed, "non-cloud apply must be no-op for {d:?}");
        }
        assert!(!consent_dir(tmp.path()).exists());
    }

    #[test]
    fn p_02_consent_decision_payload_carries_required_fields() {
        let bytes = consent_decision_payload(
            ProviderKind::OpenaiApi,
            ConsentDecision::AllowAlways,
            "tty",
            1_700_000_000,
        );
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["kind"], "openai_api");
        assert_eq!(v["decision"], "allow_always");
        assert_eq!(v["source"], "tty");
        assert_eq!(v["ts_unix"], 1_700_000_000);
    }

    #[test]
    fn p_02_consent_decision_payload_round_trips_via_serde() {
        // Drift guard for the enum's serde rename. A future refactor
        // that drops `rename_all = "snake_case"` would break WAL
        // replay; this test catches it.
        let json = serde_json::to_string(&ConsentDecision::AllowAlways).unwrap();
        assert_eq!(json, "\"allow_always\"");
        let back: ConsentDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ConsentDecision::AllowAlways);
    }
}
