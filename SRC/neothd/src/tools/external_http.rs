//! Central permission + WAL boundary for real outbound HTTP requests.
//!
//! Callers describe the exact wire request, then execute it through
//! [`ExternalHttpAuthorizer::execute`]. The network closure receives an
//! unforgeable [`ExternalHttpPermit`] only after the autonomy gate and the
//! mandatory intent frame have succeeded. Every returned network outcome is
//! closed by a matching result frame before it is released to the caller.

use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

#[cfg(not(test))]
use std::path::PathBuf;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::permissions::gate::ChannelAsker;
use crate::permissions::ifc::{EgressProvenance, ExplicitExternalResearchRelease};
use crate::permissions::{Action, AutonomyPolicySnapshot, ConfirmStrategy, Gate};
use crate::wal::events::{EVENT_TYPE_EXTENDED, ExtendedSubtype};
use crate::wal::writer::WalWriterHandle;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalHttpSurface {
    Fetch,
    JinaReader,
    SearchBrave,
    SearchTavily,
    SearchSearxng,
    Arxiv,
    HackerNews,
}

impl ExternalHttpSurface {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fetch => "fetch",
            Self::JinaReader => "jina_reader",
            Self::SearchBrave => "search_brave",
            Self::SearchTavily => "search_tavily",
            Self::SearchSearxng => "search_searxng",
            Self::Arxiv => "arxiv",
            Self::HackerNews => "hacker_news",
        }
    }
}

/// Exact request descriptor. The URL/body never enter WAL. Legacy callers
/// retain their historical SHA-256 audit binding; explicit released research
/// uses a random request correlation in WAL and keeps the topic-bearing permit
/// binding memory-only. API credentials belong in headers and must not be
/// included in `body_binding`.
#[derive(Clone)]
pub struct ExternalHttpRequest {
    method: &'static str,
    url: String,
    surface: ExternalHttpSurface,
    body_binding_sha256: String,
    search_query_sha256: Option<String>,
}

impl ExternalHttpRequest {
    pub fn get(url: impl Into<String>, surface: ExternalHttpSurface) -> Self {
        Self::new("GET", url, surface, &[])
    }

    pub fn post(url: impl Into<String>, surface: ExternalHttpSurface, body_binding: &[u8]) -> Self {
        Self::new("POST", url, surface, body_binding)
    }

    fn new(
        method: &'static str,
        url: impl Into<String>,
        surface: ExternalHttpSurface,
        body_binding: &[u8],
    ) -> Self {
        let url = url.into();
        Self {
            method,
            search_query_sha256: released_search_query_sha256(&url, surface, body_binding),
            url,
            surface,
            body_binding_sha256: hex::encode(Sha256::digest(body_binding)),
        }
    }

    fn binding_sha256(&self, egress_provenance_binding: &str) -> String {
        let mut digest = Sha256::new();
        digest.update(self.method.as_bytes());
        digest.update([0]);
        digest.update(self.url.as_bytes());
        digest.update([0]);
        digest.update(self.surface.as_str().as_bytes());
        digest.update([0]);
        digest.update(self.body_binding_sha256.as_bytes());
        digest.update([0]);
        digest.update(egress_provenance_binding.as_bytes());
        hex::encode(digest.finalize())
    }
}

impl fmt::Debug for ExternalHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExternalHttpRequest")
            .field("method", &self.method)
            .field("url", &"<redacted>")
            .field("surface", &self.surface)
            .field("body_binding_sha256", &"<redacted>")
            .field("search_query_sha256", &"<redacted>")
            .finish()
    }
}

fn released_search_query_sha256(
    url: &str,
    surface: ExternalHttpSurface,
    body: &[u8],
) -> Option<String> {
    let query = match surface {
        ExternalHttpSurface::SearchBrave | ExternalHttpSurface::SearchSearxng => {
            let parsed = url::Url::parse(url).ok()?;
            let mut queries = parsed
                .query_pairs()
                .filter(|(name, _)| name == "q")
                .map(|(_, value)| value.into_owned());
            let query = queries.next()?;
            if queries.next().is_some() {
                return None;
            }
            query
        }
        ExternalHttpSurface::SearchTavily => serde_json::from_slice::<serde_json::Value>(body)
            .ok()?
            .get("query")?
            .as_str()?
            .to_owned(),
        _ => return None,
    };
    Some(hex::encode(Sha256::digest(query.as_bytes())))
}

/// Capability minted only by [`ExternalHttpAuthorizer::execute`]. Its fields
/// are private so a caller cannot fabricate authority or reuse it for another
/// URL/body/surface tuple.
pub struct ExternalHttpPermit {
    request_id: String,
    permit_binding_sha256: String,
    egress_provenance_binding: String,
}

impl ExternalHttpPermit {
    pub fn require(&self, request: &ExternalHttpRequest) -> Result<()> {
        let binding = request.binding_sha256(&self.egress_provenance_binding);
        if binding != self.permit_binding_sha256 {
            anyhow::bail!(
                "external HTTP permit/request/provenance mismatch for {}",
                request.surface.as_str()
            );
        }
        Ok(())
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }
}

impl fmt::Debug for ExternalHttpPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExternalHttpPermit")
            .field("request_id", &self.request_id)
            .field("permit_binding_sha256", &"<redacted>")
            .field("egress_provenance_binding", &"<redacted>")
            .finish()
    }
}

#[async_trait::async_trait]
pub trait ExternalHttpAuditSink: Send + Sync {
    async fn append_external_http(&self, subtype: ExtendedSubtype, payload: Vec<u8>) -> Result<()>;
}

#[async_trait::async_trait]
impl ExternalHttpAuditSink for WalWriterHandle {
    async fn append_external_http(&self, subtype: ExtendedSubtype, payload: Vec<u8>) -> Result<()> {
        let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
            .event_subtype(subtype as u8)
            .build();
        self.append(header, payload)
            .await
            .context("append mandatory external HTTP audit frame")?;
        Ok(())
    }
}

#[cfg(not(test))]
struct DaemonAuditSink {
    home: PathBuf,
}

#[async_trait::async_trait]
#[cfg(not(test))]
impl ExternalHttpAuditSink for DaemonAuditSink {
    async fn append_external_http(&self, subtype: ExtendedSubtype, payload: Vec<u8>) -> Result<()> {
        crate::daemon::audit_rpc::try_post_audit_frame_with_subtype(
            &self.home,
            EVENT_TYPE_EXTENDED,
            subtype as u8,
            &payload,
        )
        .await
        .context("forward mandatory external HTTP audit frame to daemon")
    }
}

/// Owns the autonomy policy and mandatory audit transport for a set of HTTP
/// requests. Reuse one instance for a multi-request operation such as deep
/// research.
pub struct ExternalHttpAuthorizer {
    policy: ExternalHttpPolicySource,
    confirm: ConfirmStrategy,
    channel_asker: Option<Arc<dyn ChannelAsker>>,
    sink: Arc<dyn ExternalHttpAuditSink>,
    /// `LegacyUnscoped` preserves pre-C7 callers without falsely classifying
    /// their data as public. Only the pinned-operator explicit-release
    /// `/research` constructor below may opt into the trusted provenance path.
    egress_provenance: EgressProvenance,
}

enum ExternalHttpPolicySource {
    Fixed(AutonomyPolicySnapshot),
    Reload(Arc<crate::config::reload::ReloadController>),
}

/// Immutable metadata shared by the matching external-HTTP intent and result.
///
/// Constructing this only after URL validation binds the terminal frame to the
/// exact request that passed the autonomy gate. Keeping the lifecycle fields
/// together makes it impossible for a call site to accidentally pair a result
/// with another request's correlation, binding, destination, or release ID.
struct ExternalHttpAuditContext {
    request_id: String,
    request_binding_sha256: String,
    method: &'static str,
    destination: String,
    surface: ExternalHttpSurface,
    egress_provenance_tag: &'static str,
    research_release_id: Option<String>,
}

const RELEASED_RESEARCH_AUDIT_LABEL: &str = "released_research_search";

impl ExternalHttpAuditContext {
    fn is_operator_released_research(&self) -> bool {
        self.research_release_id.is_some()
    }

    fn persisted_destination(&self) -> &str {
        if self.is_operator_released_research() {
            RELEASED_RESEARCH_AUDIT_LABEL
        } else {
            &self.destination
        }
    }

    fn persisted_method(&self) -> &str {
        if self.is_operator_released_research() {
            RELEASED_RESEARCH_AUDIT_LABEL
        } else {
            self.method
        }
    }

    fn persisted_surface(&self) -> &str {
        if self.is_operator_released_research() {
            RELEASED_RESEARCH_AUDIT_LABEL
        } else {
            self.surface.as_str()
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum ReleasedExternalHttpFailure {
    #[error("released external HTTP request failed before transport")]
    PreTransport,
    #[error("released external HTTP request failed")]
    Transport,
    #[error("released external HTTP terminal audit failed")]
    TerminalAudit,
    #[error("released external HTTP request and terminal audit failed")]
    TransportAndTerminalAudit,
}

impl ExternalHttpPolicySource {
    fn current(&self) -> AutonomyPolicySnapshot {
        match self {
            Self::Fixed(policy) => policy.clone(),
            Self::Reload(controller) => controller.autonomy_policy(),
        }
    }
}

impl ExternalHttpAuthorizer {
    /// Interactive one-shot CLI context. A live daemon receives the frames over
    /// authenticated audit RPC; otherwise the process owns a unique standalone
    /// WAL segment. Any transport setup failure blocks the request.
    #[cfg(not(test))]
    pub fn interactive(policy: AutonomyPolicySnapshot) -> Result<Self> {
        let home = crate::config::FreedomConfig::default_neoth_home();
        let pidfile = home.join("neothd.pid");
        let daemon_live = crate::daemon::pidfile::live_daemon_pid(&pidfile)
            .with_context(|| format!("inspect daemon pidfile {}", pidfile.display()))?
            .is_some();
        let sink: Arc<dyn ExternalHttpAuditSink> = if daemon_live {
            Arc::new(DaemonAuditSink { home })
        } else {
            let wal_dir = home.join("wal");
            std::fs::create_dir_all(&wal_dir).with_context(|| {
                format!(
                    "create mandatory external HTTP WAL directory {}",
                    wal_dir.display()
                )
            })?;
            let segment =
                crate::wal::writer::unique_standalone_segment_path(&wal_dir, "external-http");
            let (writer, _join) = crate::wal::writer::spawn_for_home(segment, home)
                .context("spawn mandatory external HTTP WAL writer")?;
            Arc::new(writer)
        };
        Ok(Self {
            policy: ExternalHttpPolicySource::Fixed(policy),
            confirm: Gate::auto_confirm(),
            channel_asker: None,
            sink,
            egress_provenance: EgressProvenance::LegacyUnscoped,
        })
    }

    #[cfg(test)]
    pub fn interactive(policy: AutonomyPolicySnapshot) -> Result<Self> {
        let _ = policy;
        Ok(Self::test_allow())
    }

    pub fn with_writer(
        policy: AutonomyPolicySnapshot,
        confirm: ConfirmStrategy,
        writer: WalWriterHandle,
    ) -> Self {
        Self {
            policy: ExternalHttpPolicySource::Fixed(policy),
            confirm,
            channel_asker: None,
            sink: Arc::new(writer),
            egress_provenance: EgressProvenance::LegacyUnscoped,
        }
    }

    /// Long-running daemon context. Every request obtains a fresh immutable
    /// policy snapshot from the reload controller immediately before gating.
    pub fn with_reload_writer(
        controller: Arc<crate::config::reload::ReloadController>,
        confirm: ConfirmStrategy,
        writer: WalWriterHandle,
    ) -> Self {
        Self {
            policy: ExternalHttpPolicySource::Reload(controller),
            confirm,
            channel_asker: None,
            sink: Arc::new(writer),
            egress_provenance: EgressProvenance::LegacyUnscoped,
        }
    }

    pub fn with_channel_writer(
        policy: AutonomyPolicySnapshot,
        writer: WalWriterHandle,
        asker: Arc<dyn ChannelAsker>,
    ) -> Self {
        Self {
            policy: ExternalHttpPolicySource::Fixed(policy),
            confirm: ConfirmStrategy::Channel,
            channel_asker: Some(asker),
            sink: Arc::new(writer),
            egress_provenance: EgressProvenance::LegacyUnscoped,
        }
    }

    /// Pinned-operator explicit-release channel `/research` context.
    ///
    /// This is intentionally crate-visible and takes the parser-minted topic
    /// binding rather than any caller-supplied label. The caller has already
    /// proven the pinned operator and recognized `/research
    /// --release-external <topic>`; all other HTTP call sites retain
    /// `LegacyUnscoped` until they gain an equally narrow trusted ingress
    /// boundary. A public IFC release still proceeds through the ordinary
    /// autonomy/confirmation gate below.
    pub(crate) fn with_operator_released_channel_research_writer(
        policy: AutonomyPolicySnapshot,
        writer: WalWriterHandle,
        asker: Option<Arc<dyn ChannelAsker>>,
        release: ExplicitExternalResearchRelease,
    ) -> Self {
        let confirm = if asker.is_some() {
            ConfirmStrategy::Channel
        } else {
            ConfirmStrategy::FailClosed
        };
        Self {
            policy: ExternalHttpPolicySource::Fixed(policy),
            confirm,
            channel_asker: asker,
            sink: Arc::new(writer),
            egress_provenance: release.into_egress_provenance(),
        }
    }

    /// Opaque lifecycle correlation for the explicit released-research path.
    /// Generic/legacy authorizers return `None`; the released topic digest is
    /// intentionally not exposed to production callers.
    pub(crate) fn arm_operator_released_exact_topic(&self, topic: &str) -> Result<String> {
        self.egress_provenance
            .arm_operator_released_exact_topic(topic)
            .map(str::to_owned)
            .context("arm exact operator-released research topic")
    }

    /// Would this surface be refused right now, without asking anyone?
    ///
    /// For an UNATTENDED caller — a cron with no operator to confirm — a
    /// `Confirm` decision under a fail-closed strategy is a guaranteed refusal.
    /// Such a caller needs to know that BEFORE it treats the refusal as a
    /// failure: a periodic task that reports an error it can never avoid retries
    /// and warns on every tick forever. This lets it no-op cleanly instead.
    ///
    /// Deliberately conservative: `false` means "not certainly refused", never
    /// "permitted". The real gate still runs inside [`Self::execute`] — this is
    /// a scheduling hint, never an authorisation.
    #[must_use]
    pub fn is_certainly_denied(&self, surface: ExternalHttpSurface) -> bool {
        if !matches!(self.confirm, ConfirmStrategy::FailClosed) || self.channel_asker.is_some() {
            return false;
        }
        let action = Action::ExternalHttpRequest {
            method: "GET".to_string(),
            destination: String::new(),
            surface: surface.as_str().to_string(),
            request_id: String::new(),
            request_binding_sha256: String::new(),
        };
        matches!(
            crate::permissions::evaluate(&action, &self.policy.current()),
            crate::permissions::Decision::Confirm(_) | crate::permissions::Decision::Deny(_)
        )
    }

    /// Gate and audit an external request before returning its outcome.
    ///
    /// The permit is cryptographically bound to the exact request, but the
    /// supplied transport closure must still call [`ExternalHttpPermit::require`]
    /// before it performs an effect. Rust's type system does not prevent that
    /// closure from contacting another destination or acting before it verifies
    /// the permit. Compiler-enforced non-substitution requires moving transport
    /// execution behind this boundary; that larger C7 refactor remains open.
    pub async fn execute<F, Fut, T>(&self, request: ExternalHttpRequest, network: F) -> Result<T>
    where
        F: FnOnce(ExternalHttpPermit) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        self.execute_with_permit_verifier(request, ExternalHttpPermit::require, network)
            .await
    }

    async fn execute_with_permit_verifier<F, Fut, T, V>(
        &self,
        request: ExternalHttpRequest,
        verify_permit: V,
        network: F,
    ) -> Result<T>
    where
        F: FnOnce(ExternalHttpPermit) -> Fut,
        Fut: Future<Output = Result<T>>,
        V: FnOnce(&ExternalHttpPermit, &ExternalHttpRequest) -> Result<()>,
    {
        let released = self.egress_provenance.released_research_id().is_some();
        let outcome = self
            .execute_inner(request, verify_permit, network)
            .await;
        match outcome {
            Err(error) if released => match error.downcast_ref::<ReleasedExternalHttpFailure>() {
                Some(_) => Err(error),
                None => Err(ReleasedExternalHttpFailure::PreTransport.into()),
            },
            outcome => outcome,
        }
    }

    async fn execute_inner<F, Fut, T, V>(
        &self,
        request: ExternalHttpRequest,
        verify_permit: V,
        network: F,
    ) -> Result<T>
    where
        F: FnOnce(ExternalHttpPermit) -> Fut,
        Fut: Future<Output = Result<T>>,
        V: FnOnce(&ExternalHttpPermit, &ExternalHttpRequest) -> Result<()>,
    {
        // C7 boundary: trusted provenance must satisfy IFC before the
        // confirmer, permission/audit intent, permit, or transport can run.
        // Legacy callers intentionally have no source classification here;
        // treating their absence as `Public` would be a false provenance
        // claim and a breaking behavioural change.
        let trusted_provenance = self.egress_provenance.sources();
        if let Some(sources) = trusted_provenance {
            crate::permissions::may_flow_to_action(
                sources,
                crate::permissions::ActionKind::ExternalHttpRequest,
            )
            .context("external HTTP IFC denied trusted egress provenance")?;
            self.egress_provenance
                .consume_operator_released_search_query(request.search_query_sha256.as_deref())
                .context("consume exact operator-released research request")?;
        }

        let parsed = validate_request_url(&request.url)?;
        let local = classify_local_searxng(&request, &parsed)?;
        let request_id = uuid::Uuid::now_v7().to_string();
        let egress_provenance_binding = self.egress_provenance.binding_material();
        let permit_binding_sha256 = request.binding_sha256(&egress_provenance_binding);
        let egress_provenance_tag = self.egress_provenance.audit_tag();
        let research_release_id = self.egress_provenance.released_research_id();
        let request_binding_sha256 = if research_release_id.is_some() {
            let mut digest = Sha256::new();
            digest.update(b"NEOTH\0EXTERNAL_HTTP\0AUDIT_BINDING\0V1");
            digest.update(request_id.as_bytes());
            hex::encode(digest.finalize())
        } else {
            permit_binding_sha256.clone()
        };
        let audit = ExternalHttpAuditContext {
            request_id,
            request_binding_sha256,
            method: request.method,
            destination: origin_without_credentials(&parsed)?,
            surface: request.surface,
            egress_provenance_tag,
            research_release_id: research_release_id.map(str::to_owned),
        };
        // Legacy local SearXNG keeps its historical direct-local contract.
        // Explicitly released research never takes that shortcut: private/LAN
        // address space is not a trust boundary, so confirmation and both WAL
        // lifecycle frames remain mandatory before/after transport.
        let requires_lifecycle_gate = !local || trusted_provenance.is_some();

        if requires_lifecycle_gate {
            let action = Action::ExternalHttpRequest {
                method: audit.method.to_string(),
                destination: audit.destination.clone(),
                surface: audit.surface.as_str().to_string(),
                request_id: audit.request_id.clone(),
                request_binding_sha256: audit.request_binding_sha256.clone(),
            };
            let mut gate = Gate::for_policy(self.policy.current()).with_confirm(self.confirm);
            if let Some(asker) = &self.channel_asker {
                gate = gate.with_channel_asker(Arc::clone(asker));
            }
            gate.check(&action, None)
                .await
                .context("external HTTP autonomy gate denied request")?;
            self.append_intent(&audit).await?;
        }

        let permit = ExternalHttpPermit {
            request_id: audit.request_id.clone(),
            permit_binding_sha256,
            egress_provenance_binding,
        };
        if let Err(error) = verify_permit(&permit, &request) {
            if audit.is_operator_released_research() && requires_lifecycle_gate {
                let verification: Result<()> = Err(error);
                self.append_result(&audit, &verification).await?;
                return verification;
            }
            return Err(error);
        }
        let outcome = network(permit).await;
        if !requires_lifecycle_gate {
            return outcome;
        }

        let terminal = self.append_result(&audit, &outcome).await;
        if audit.is_operator_released_research() {
            return match (outcome, terminal) {
                (Ok(value), Ok(())) => Ok(value),
                (Err(_), Ok(())) => Err(ReleasedExternalHttpFailure::Transport.into()),
                (Ok(_), Err(_)) => Err(ReleasedExternalHttpFailure::TerminalAudit.into()),
                (Err(_), Err(_)) => {
                    Err(ReleasedExternalHttpFailure::TransportAndTerminalAudit.into())
                }
            };
        }
        match (outcome, terminal) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(audit)) => Err(audit),
            (Err(operation), Err(audit)) => Err(anyhow::anyhow!(
                "external HTTP request failed: {operation:#}; terminal audit also failed: {audit:#}"
            )),
        }
    }

    async fn append_intent(&self, audit: &ExternalHttpAuditContext) -> Result<()> {
        let payload = serde_json::to_vec(&serde_json::json!({
            "request_id": audit.request_id,
            "request_binding_sha256": audit.request_binding_sha256,
            "method": audit.persisted_method(),
            "destination": audit.persisted_destination(),
            "surface": audit.persisted_surface(),
            "egress_provenance": audit.egress_provenance_tag,
            "research_release_id": audit.research_release_id,
            "status": "intent",
            "ts_unix": crate::time::now_unix_secs(),
        }))?;
        self.sink
            .append_external_http(ExtendedSubtype::ExternalHttpIntent, payload)
            .await
            .context("append mandatory external HTTP intent")
    }

    async fn append_result<T>(
        &self,
        audit: &ExternalHttpAuditContext,
        outcome: &Result<T>,
    ) -> Result<()> {
        // A released-research error can repeat the exact search URL.  Its
        // formatted text is therefore topic-bearing and must never become a
        // deterministic WAL value (including through a digest).  The stable
        // coarse code records the terminal state without weakening the legacy
        // audit contract for unscoped callers.
        let (status, error_sha256, released_error_code) = match outcome {
            Ok(_) => ("success", None, None),
            Err(_) if audit.research_release_id.is_some() => {
                ("failure", None, Some("external_http_request_failed"))
            }
            Err(error) => (
                "failure",
                Some(hex::encode(Sha256::digest(format!("{error:#}").as_bytes()))),
                None,
            ),
        };
        let mut payload = serde_json::json!({
            "request_id": audit.request_id,
            "request_binding_sha256": audit.request_binding_sha256,
            "method": audit.persisted_method(),
            "destination": audit.persisted_destination(),
            "surface": audit.persisted_surface(),
            "egress_provenance": audit.egress_provenance_tag,
            "research_release_id": audit.research_release_id,
            "status": status,
            "error_sha256": error_sha256,
            "ts_unix": crate::time::now_unix_secs(),
        });
        if let (Some(error_code), Some(object)) = (released_error_code, payload.as_object_mut()) {
            object.insert(
                "error_code".to_owned(),
                serde_json::Value::String(error_code.to_owned()),
            );
        }
        let payload = serde_json::to_vec(&payload)?;
        self.sink
            .append_external_http(ExtendedSubtype::ExternalHttpResult, payload)
            .await
            .context("append mandatory external HTTP result")
    }

    #[cfg(test)]
    pub(crate) fn test_allow() -> Self {
        Self::test_policy(
            AutonomyPolicySnapshot::test_level(crate::permissions::AutonomyLevel::Standard),
            ConfirmStrategy::AlwaysAllow,
        )
    }

    #[cfg(test)]
    pub(crate) fn test_policy(policy: AutonomyPolicySnapshot, confirm: ConfirmStrategy) -> Self {
        Self {
            policy: ExternalHttpPolicySource::Fixed(policy),
            confirm,
            channel_asker: None,
            sink: Arc::new(NoopAuditSink),
            egress_provenance: EgressProvenance::LegacyUnscoped,
        }
    }

    #[cfg(test)]
    pub(crate) fn test_reload(
        controller: Arc<crate::config::reload::ReloadController>,
        confirm: ConfirmStrategy,
    ) -> Self {
        Self {
            policy: ExternalHttpPolicySource::Reload(controller),
            confirm,
            channel_asker: None,
            sink: Arc::new(NoopAuditSink),
            egress_provenance: EgressProvenance::LegacyUnscoped,
        }
    }
}

fn validate_request_url(raw: &str) -> Result<url::Url> {
    let parsed = url::Url::parse(raw).with_context(|| format!("invalid HTTP URL: {raw}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        anyhow::bail!("external HTTP only permits http(s) URLs");
    }
    if parsed.host_str().is_none() {
        anyhow::bail!("external HTTP URL has no host");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        anyhow::bail!("external HTTP URL must not carry credentials");
    }
    Ok(parsed)
}

fn origin_without_credentials(url: &url::Url) -> Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("external HTTP URL has no host"))?;
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    Ok(match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    })
}

/// May this SearXNG request skip the autonomy gate and the WAL audit?
///
/// Decided WITHOUT DNS. The previous version resolved the host here and let the
/// fetch resolve it again independently, so a name that answered with a local
/// address at classification time and a public one at fetch time produced an
/// external egress with NO gate and NO audit frame — a DNS-rebinding hole in
/// the one module whose entire promise is audit integrity.
///
/// A decision that cannot be re-decided is the fix: only an address that is
/// local *by construction* qualifies.
/// - an IP literal that is loopback/private/link-local (`http://127.0.0.1:8888`,
///   `http://192.168.1.5:8888`) — nothing to resolve, nothing to rebind;
/// - the reserved name `localhost`, which resolvers map to loopback and which no
///   external DNS answer can redirect.
///
/// Every other host — including a LAN hostname that happens to resolve
/// privately — takes the normal gated, audited path. That is the case an
/// attacker can influence, and skipping the audit for it was never safe.
fn classify_local_searxng(request: &ExternalHttpRequest, url: &url::Url) -> Result<bool> {
    if request.surface != ExternalHttpSurface::SearchSearxng {
        return Ok(false);
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("SearXNG URL has no host"))?;
    // `port_or_known_default` is still required: a URL we cannot address is
    // rejected here rather than surfacing later as an opaque fetch failure.
    url.port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("SearXNG URL has no resolvable port"))?;
    match url.host() {
        Some(url::Host::Ipv4(v4)) => Ok(is_local_ip(IpAddr::V4(v4))),
        Some(url::Host::Ipv6(v6)) => Ok(is_local_ip(IpAddr::V6(v6))),
        _ => Ok(host.eq_ignore_ascii_case("localhost")),
    }
}

fn is_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || is_shared_v4(v4)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unique_local()
                || is_link_local_v6(v6)
                || v6.to_ipv4_mapped().is_some_and(|v4| is_local_ip(v4.into()))
        }
    }
}

fn is_shared_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && octets[1] & 0xc0 == 64
}

fn is_link_local_v6(ip: Ipv6Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 0xfe && octets[1] & 0xc0 == 0x80
}

#[cfg(test)]
struct NoopAuditSink;

#[cfg(test)]
#[async_trait::async_trait]
impl ExternalHttpAuditSink for NoopAuditSink {
    async fn append_external_http(
        &self,
        _subtype: ExtendedSubtype,
        _payload: Vec<u8>,
    ) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::*;

    /// PR4-021: the gate/audit skip must not depend on a DNS answer, because
    /// the fetch resolves the host again and the two answers can differ.
    #[test]
    fn searxng_local_skip_never_depends_on_dns() {
        let classify = |url: &str| {
            let request = ExternalHttpRequest::get(url, ExternalHttpSurface::SearchSearxng);
            let parsed = validate_request_url(url).expect("valid url");
            classify_local_searxng(&request, &parsed).expect("classified")
        };

        // Local by construction: nothing to resolve, nothing to rebind.
        assert!(classify("http://127.0.0.1:8888"));
        assert!(classify("http://192.168.1.5:8888"));
        assert!(classify("http://[::1]:8888"));
        assert!(classify("http://localhost:8888"));
        assert!(classify("http://LOCALHOST:8888"));

        // Anything an attacker-influenced DNS answer could move: gated+audited.
        assert!(!classify("http://searx.example.com:8888"));
        assert!(!classify("http://searx.internal:8888"));
        assert!(!classify("http://8.8.8.8:8888"));
    }

    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<(ExtendedSubtype, serde_json::Value)>>,
        attempts: Mutex<Vec<(ExtendedSubtype, serde_json::Value)>>,
        fail: Option<ExtendedSubtype>,
        sequence: Option<Arc<Mutex<Vec<&'static str>>>>,
    }

    #[async_trait::async_trait]
    impl ExternalHttpAuditSink for RecordingSink {
        async fn append_external_http(
            &self,
            subtype: ExtendedSubtype,
            payload: Vec<u8>,
        ) -> Result<()> {
            let decoded = serde_json::from_slice(&payload)?;
            self.attempts
                .lock()
                .unwrap()
                .push((subtype, decoded.clone()));
            if self.fail == Some(subtype) {
                anyhow::bail!("injected audit failure");
            }
            if let Some(sequence) = &self.sequence {
                sequence.lock().unwrap().push(match subtype {
                    ExtendedSubtype::ExternalHttpIntent => "intent",
                    ExtendedSubtype::ExternalHttpResult => "result",
                    _ => "other",
                });
            }
            self.events.lock().unwrap().push((subtype, decoded));
            Ok(())
        }
    }

    fn authorizer(sink: Arc<dyn ExternalHttpAuditSink>) -> ExternalHttpAuthorizer {
        ExternalHttpAuthorizer {
            policy: ExternalHttpPolicySource::Fixed(AutonomyPolicySnapshot::test_level(
                crate::permissions::AutonomyLevel::Standard,
            )),
            confirm: ConfirmStrategy::AlwaysAllow,
            channel_asker: None,
            sink,
            egress_provenance: EgressProvenance::LegacyUnscoped,
        }
    }

    fn assert_released_payload_is_provider_neutral(
        payload: &serde_json::Value,
        forbidden: &[&str],
    ) {
        assert_eq!(payload["destination"], RELEASED_RESEARCH_AUDIT_LABEL);
        assert_eq!(payload["method"], RELEASED_RESEARCH_AUDIT_LABEL);
        assert_eq!(payload["surface"], RELEASED_RESEARCH_AUDIT_LABEL);
        let encoded = serde_json::to_string(payload).unwrap();
        for marker in forbidden {
            assert!(
                !encoded.contains(marker),
                "released audit payload leaked marker {marker:?}: {encoded}"
            );
        }
    }

    fn assert_released_pretransport_error_is_coarse(error: &anyhow::Error, forbidden: &[&str]) {
        assert!(matches!(
            error.downcast_ref::<ReleasedExternalHttpFailure>(),
            Some(ReleasedExternalHttpFailure::PreTransport)
        ));
        assert_eq!(
            error.to_string(),
            "released external HTTP request failed before transport"
        );
        let returned = format!("{error:#}");
        for marker in forbidden {
            assert!(!returned.contains(marker));
        }
    }

    #[tokio::test]
    async fn intent_failure_prevents_network() {
        let called = AtomicBool::new(false);
        let auth = authorizer(Arc::new(RecordingSink {
            fail: Some(ExtendedSubtype::ExternalHttpIntent),
            ..RecordingSink::default()
        }));
        let result = auth
            .execute(
                ExternalHttpRequest::get("https://example.com/x", ExternalHttpSurface::Fetch),
                |_permit| async {
                    called.store(true, Ordering::SeqCst);
                    Ok(())
                },
            )
            .await;
        assert!(result.is_err());
        assert!(!called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn success_and_failure_close_the_same_request_binding() {
        for fail_network in [false, true] {
            let sink = Arc::new(RecordingSink::default());
            let auth = authorizer(sink.clone());
            let result = auth
                .execute(
                    ExternalHttpRequest::get(
                        "https://example.com/x?q=secret",
                        ExternalHttpSurface::Fetch,
                    ),
                    |_permit| async move {
                        if fail_network {
                            anyhow::bail!("network failed")
                        }
                        Ok(())
                    },
                )
                .await;
            assert_eq!(result.is_err(), fail_network);
            let events = sink.events.lock().unwrap();
            assert_eq!(events.len(), 2);
            assert_eq!(events[0].0, ExtendedSubtype::ExternalHttpIntent);
            assert_eq!(events[1].0, ExtendedSubtype::ExternalHttpResult);
            assert_eq!(events[0].1["method"], "GET");
            assert_eq!(events[1].1["method"], "GET");
            assert_eq!(events[0].1["request_id"], events[1].1["request_id"]);
            assert_eq!(
                events[0].1["request_binding_sha256"],
                events[1].1["request_binding_sha256"]
            );
            assert_eq!(
                events[1].1["status"],
                if fail_network { "failure" } else { "success" }
            );
            let text = serde_json::to_string(&events[0].1).unwrap();
            assert!(!text.contains("secret"));
        }
    }

    #[tokio::test]
    async fn loopback_searxng_is_local_but_loopback_fetch_is_external() {
        let sink = Arc::new(RecordingSink::default());
        let auth = authorizer(sink.clone());
        auth.execute(
            ExternalHttpRequest::get(
                "http://127.0.0.1:8888/search",
                ExternalHttpSurface::SearchSearxng,
            ),
            |_permit| async { Ok(()) },
        )
        .await
        .unwrap();
        assert!(sink.events.lock().unwrap().is_empty());

        auth.execute(
            ExternalHttpRequest::get("http://127.0.0.1:8888/page", ExternalHttpSurface::Fetch),
            |_permit| async { Ok(()) },
        )
        .await
        .unwrap();
        assert_eq!(sink.events.lock().unwrap().len(), 2);
    }

    #[test]
    fn permit_is_bound_to_exact_url_and_body() {
        let first = ExternalHttpRequest::post(
            "https://example.com/api",
            ExternalHttpSurface::SearchTavily,
            br#"{"query":"one"}"#,
        );
        let second = ExternalHttpRequest::post(
            "https://example.com/api",
            ExternalHttpSurface::SearchTavily,
            br#"{"query":"two"}"#,
        );
        let permit = ExternalHttpPermit {
            request_id: "id".into(),
            permit_binding_sha256: first.binding_sha256("legacy_unscoped"),
            egress_provenance_binding: "legacy_unscoped".into(),
        };
        assert!(permit.require(&first).is_ok());
        assert!(permit.require(&second).is_err());
    }

    #[test]
    fn permit_rejects_a_provenance_binding_mismatch() {
        let request =
            ExternalHttpRequest::get("https://example.com/api", ExternalHttpSurface::SearchBrave);
        let permit = ExternalHttpPermit {
            request_id: "id".into(),
            permit_binding_sha256: request
                .binding_sha256("operator_released_channel_research:public:test-topic-binding"),
            egress_provenance_binding: "legacy_unscoped".into(),
        };

        assert!(permit.require(&request).is_err());
    }

    #[test]
    fn released_search_query_binding_is_derived_from_actual_wire_fields() {
        let expected = hex::encode(Sha256::digest(b"approved topic"));
        let brave = ExternalHttpRequest::get(
            "https://api.search.brave.com/res/v1/web/search?q=approved%20topic",
            ExternalHttpSurface::SearchBrave,
        );
        let searxng = ExternalHttpRequest::get(
            "http://127.0.0.1:8888/search?format=json&q=approved+topic",
            ExternalHttpSurface::SearchSearxng,
        );
        let tavily = ExternalHttpRequest::post(
            "https://api.tavily.com/search",
            ExternalHttpSurface::SearchTavily,
            br#"{"query":"approved topic","max_results":5}"#,
        );
        for request in [brave, searxng, tavily] {
            assert_eq!(
                request.search_query_sha256.as_deref(),
                Some(expected.as_str())
            );
        }

        let duplicate = ExternalHttpRequest::get(
            "https://example.test/search?q=approved%20topic&q=different",
            ExternalHttpSurface::SearchBrave,
        );
        assert!(duplicate.search_query_sha256.is_none());
        let fetch = ExternalHttpRequest::get(
            "https://example.test/?q=approved%20topic",
            ExternalHttpSurface::Fetch,
        );
        assert!(fetch.search_query_sha256.is_none());
    }

    #[test]
    fn request_and_permit_debug_output_redacts_topic_bearing_bindings() {
        let request = ExternalHttpRequest::get(
            "https://example.test/?q=low-entropy-topic",
            ExternalHttpSurface::SearchBrave,
        );
        let permit = ExternalHttpPermit {
            request_id: "request-id".into(),
            permit_binding_sha256: "sensitive-permit-binding".into(),
            egress_provenance_binding: "sensitive-provenance-binding".into(),
        };
        let request_debug = format!("{request:?}");
        let permit_debug = format!("{permit:?}");
        assert!(!request_debug.contains("low-entropy-topic"));
        assert!(!permit_debug.contains("sensitive-permit-binding"));
        assert!(!permit_debug.contains("sensitive-provenance-binding"));
    }

    struct CountingAsker {
        asked: AtomicBool,
        approve: bool,
        sequence: Option<Arc<Mutex<Vec<&'static str>>>>,
        reasons: Mutex<Vec<String>>,
    }

    impl CountingAsker {
        fn approving() -> Self {
            Self {
                asked: AtomicBool::new(false),
                approve: true,
                sequence: None,
                reasons: Mutex::new(Vec::new()),
            }
        }

        fn rejecting() -> Self {
            Self {
                asked: AtomicBool::new(false),
                approve: false,
                sequence: None,
                reasons: Mutex::new(Vec::new()),
            }
        }

        fn approving_with_sequence(sequence: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self {
                asked: AtomicBool::new(false),
                approve: true,
                sequence: Some(sequence),
                reasons: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl ChannelAsker for CountingAsker {
        async fn ask(&self, reason: &str) -> Option<bool> {
            self.asked.store(true, Ordering::SeqCst);
            self.reasons.lock().unwrap().push(reason.to_owned());
            if let Some(sequence) = &self.sequence {
                sequence.lock().unwrap().push("confirm");
            }
            Some(self.approve)
        }
    }

    #[tokio::test]
    async fn non_public_trusted_provenance_stops_before_confirmer_or_network() {
        for label in [
            crate::permissions::InformationLabel::Internal,
            crate::permissions::InformationLabel::Confidential,
            crate::permissions::InformationLabel::Secret,
        ] {
            let asked = Arc::new(CountingAsker::approving());
            let called = AtomicBool::new(false);
            let sink = Arc::new(RecordingSink::default());
            let auth = ExternalHttpAuthorizer {
                policy: ExternalHttpPolicySource::Fixed(AutonomyPolicySnapshot::test_level(
                    crate::permissions::AutonomyLevel::Standard,
                )),
                confirm: ConfirmStrategy::Channel,
                channel_asker: Some(asked.clone()),
                sink: sink.clone(),
                egress_provenance: EgressProvenance::test_operator_released_channel_research(
                    crate::permissions::SourceLabels::from_labels([label]).unwrap(),
                ),
            };

            let result = auth
                .execute(
                    ExternalHttpRequest::get("https://example.com/x", ExternalHttpSurface::Fetch),
                    |_permit| async {
                        called.store(true, Ordering::SeqCst);
                        Ok(())
                    },
                )
                .await;

            assert!(result.is_err(), "{label} trusted egress must be denied");
            assert!(!asked.asked.load(Ordering::SeqCst));
            assert!(!called.load(Ordering::SeqCst));
            assert!(sink.events.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn released_topic_or_wire_query_mismatch_stops_before_confirmation_and_transport() {
        let asked = Arc::new(CountingAsker::approving());
        let called = AtomicBool::new(false);
        let sink = Arc::new(RecordingSink::default());
        let auth = ExternalHttpAuthorizer {
            policy: ExternalHttpPolicySource::Fixed(AutonomyPolicySnapshot::test_level(
                crate::permissions::AutonomyLevel::Standard,
            )),
            confirm: ConfirmStrategy::Channel,
            channel_asker: Some(asked.clone()),
            sink: sink.clone(),
            egress_provenance: ExplicitExternalResearchRelease::test_for_exact_topic(
                "approved topic",
            )
            .into_egress_provenance(),
        };

        assert!(
            auth.arm_operator_released_exact_topic("different topic")
                .is_err()
        );
        assert!(!asked.asked.load(Ordering::SeqCst));
        assert!(sink.events.lock().unwrap().is_empty());

        auth.arm_operator_released_exact_topic("approved topic")
            .unwrap();
        assert!(
            auth.execute(
                ExternalHttpRequest::get(
                    "https://api.search.brave.com/res/v1/web/search?q=different",
                    ExternalHttpSurface::SearchBrave,
                ),
                |_permit| async {
                    called.store(true, Ordering::SeqCst);
                    Ok(())
                },
            )
            .await
            .is_err()
        );
        assert!(!asked.asked.load(Ordering::SeqCst));
        assert!(!called.load(Ordering::SeqCst));
        assert!(sink.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn released_search_capability_spends_exactly_once() {
        let called = AtomicUsize::new(0);
        let sink = Arc::new(RecordingSink::default());
        let auth = ExternalHttpAuthorizer {
            policy: ExternalHttpPolicySource::Fixed(AutonomyPolicySnapshot::test_level(
                crate::permissions::AutonomyLevel::Full,
            )),
            confirm: ConfirmStrategy::AlwaysAllow,
            channel_asker: None,
            sink: sink.clone(),
            egress_provenance: ExplicitExternalResearchRelease::test_for_exact_topic(
                "approved topic",
            )
            .into_egress_provenance(),
        };
        auth.arm_operator_released_exact_topic("approved topic")
            .unwrap();
        let request = || {
            ExternalHttpRequest::get(
                "https://api.search.brave.com/res/v1/web/search?q=approved%20topic",
                ExternalHttpSurface::SearchBrave,
            )
        };

        auth.execute(request(), |_permit| async {
            called.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .await
        .unwrap();
        assert!(
            auth.execute(request(), |_permit| async {
                called.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await
            .is_err()
        );
        assert_eq!(called.load(Ordering::SeqCst), 1);
        assert_eq!(sink.events.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn operator_released_research_still_uses_the_autonomy_gate() {
        let sequence = Arc::new(Mutex::new(Vec::new()));
        let asked = Arc::new(CountingAsker::approving_with_sequence(Arc::clone(
            &sequence,
        )));
        let called = AtomicBool::new(false);
        let sink = Arc::new(RecordingSink {
            sequence: Some(Arc::clone(&sequence)),
            ..RecordingSink::default()
        });
        let auth = ExternalHttpAuthorizer {
            policy: ExternalHttpPolicySource::Fixed(AutonomyPolicySnapshot::test_level(
                crate::permissions::AutonomyLevel::Standard,
            )),
            confirm: ConfirmStrategy::Channel,
            channel_asker: Some(asked.clone()),
            sink: sink.clone(),
            egress_provenance: ExplicitExternalResearchRelease::test_for_exact_topic(
                "approved topic",
            )
            .into_egress_provenance(),
        };
        auth.arm_operator_released_exact_topic("approved topic")
            .unwrap();

        auth.execute(
            ExternalHttpRequest::get(
                "https://api.search.brave.com/res/v1/web/search?q=approved%20topic",
                ExternalHttpSurface::SearchBrave,
            ),
            |_permit| async {
                called.store(true, Ordering::SeqCst);
                sequence.lock().unwrap().push("transport");
                Ok(())
            },
        )
        .await
        .unwrap();

        assert!(asked.asked.load(Ordering::SeqCst));
        let reasons = asked.reasons.lock().unwrap();
        assert_eq!(reasons.len(), 1);
        assert!(reasons[0].contains("https://api.search.brave.com"));
        assert!(reasons[0].contains("search_brave"));
        drop(reasons);
        assert!(called.load(Ordering::SeqCst));
        assert_eq!(
            sequence.lock().unwrap().as_slice(),
            ["confirm", "intent", "transport", "result"]
        );
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        for (_, payload) in events.iter() {
            assert_released_payload_is_provider_neutral(
                payload,
                &["api.search.brave.com", "search_brave", "approved topic"],
            );
        }
        assert_eq!(
            events[0].1["egress_provenance"],
            "operator_released_channel_research"
        );
        assert_eq!(
            events[0].1["research_release_id"],
            "test-research-release-id"
        );
        assert_eq!(
            events[1].1["research_release_id"],
            "test-research-release-id"
        );
        let request_id = events[0].1["request_id"].as_str().unwrap();
        let mut audit_digest = Sha256::new();
        audit_digest.update(b"NEOTH\0EXTERNAL_HTTP\0AUDIT_BINDING\0V1");
        audit_digest.update(request_id.as_bytes());
        assert_eq!(
            events[0].1["request_binding_sha256"],
            hex::encode(audit_digest.finalize())
        );
        let private_permit_binding = ExternalHttpRequest::get(
            "https://api.search.brave.com/res/v1/web/search?q=approved%20topic",
            ExternalHttpSurface::SearchBrave,
        )
        .binding_sha256(&auth.egress_provenance.binding_material());
        assert_ne!(
            events[0].1["request_binding_sha256"],
            private_permit_binding
        );
        assert!(events[0].1.get("released_topic_sha256").is_none());
        assert!(events[1].1.get("released_topic_sha256").is_none());
    }

    #[tokio::test]
    async fn released_tavily_post_is_real_at_gate_and_provider_neutral_in_wal() {
        let topic = "private tavily topic";
        let body = br#"{"query":"private tavily topic"}"#;
        let asked = Arc::new(CountingAsker::approving());
        let sink = Arc::new(RecordingSink::default());
        let auth = ExternalHttpAuthorizer {
            policy: ExternalHttpPolicySource::Fixed(AutonomyPolicySnapshot::test_level(
                crate::permissions::AutonomyLevel::Standard,
            )),
            confirm: ConfirmStrategy::Channel,
            channel_asker: Some(asked.clone()),
            sink: sink.clone(),
            egress_provenance: ExplicitExternalResearchRelease::test_for_exact_topic(topic)
                .into_egress_provenance(),
        };
        auth.arm_operator_released_exact_topic(topic).unwrap();

        auth.execute(
            ExternalHttpRequest::post(
                "https://api.tavily.com/search",
                ExternalHttpSurface::SearchTavily,
                body,
            ),
            |_permit| async { Ok(()) },
        )
        .await
        .unwrap();

        let reasons = asked.reasons.lock().unwrap();
        assert_eq!(reasons.len(), 1);
        assert!(reasons[0].contains("POST"));
        assert!(reasons[0].contains("https://api.tavily.com"));
        assert!(reasons[0].contains("search_tavily"));
        drop(reasons);

        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        for (_, payload) in events.iter() {
            assert_released_payload_is_provider_neutral(
                payload,
                &[
                    "POST",
                    "tavily",
                    "api.tavily.com",
                    "search_tavily",
                    topic,
                    &hex::encode(Sha256::digest(topic.as_bytes())),
                ],
            );
        }
    }

    #[tokio::test]
    async fn released_pretransport_failures_are_coarse_and_data_free() {
        let topic = "c7 pretransport private topic";
        let body = br#"{"query":"c7 pretransport private topic"}"#;

        let invalid_sink = Arc::new(RecordingSink::default());
        let invalid_auth = ExternalHttpAuthorizer {
            policy: ExternalHttpPolicySource::Fixed(AutonomyPolicySnapshot::test_level(
                crate::permissions::AutonomyLevel::Standard,
            )),
            confirm: ConfirmStrategy::AlwaysAllow,
            channel_asker: None,
            sink: invalid_sink.clone(),
            egress_provenance: ExplicitExternalResearchRelease::test_for_exact_topic(topic)
                .into_egress_provenance(),
        };
        invalid_auth
            .arm_operator_released_exact_topic(topic)
            .unwrap();
        let invalid: Result<()> = invalid_auth
            .execute(
                ExternalHttpRequest::post(
                    "not-a-url/c7-pretransport-private-topic",
                    ExternalHttpSurface::SearchTavily,
                    body,
                ),
                |_permit| async { Ok(()) },
            )
            .await;
        let invalid = invalid.expect_err("invalid released URL must fail closed");
        assert_released_pretransport_error_is_coarse(
            &invalid,
            &[topic, "not-a-url", "SearchTavily", "invalid HTTP URL"],
        );
        assert!(invalid_sink.attempts.lock().unwrap().is_empty());

        let denying_asker = Arc::new(CountingAsker::rejecting());
        let denied_sink = Arc::new(RecordingSink::default());
        let denied_auth = ExternalHttpAuthorizer {
            policy: ExternalHttpPolicySource::Fixed(AutonomyPolicySnapshot::test_level(
                crate::permissions::AutonomyLevel::Standard,
            )),
            confirm: ConfirmStrategy::Channel,
            channel_asker: Some(denying_asker),
            sink: denied_sink.clone(),
            egress_provenance: ExplicitExternalResearchRelease::test_for_exact_topic(topic)
                .into_egress_provenance(),
        };
        denied_auth
            .arm_operator_released_exact_topic(topic)
            .unwrap();
        let denied: Result<()> = denied_auth
            .execute(
                ExternalHttpRequest::post(
                    "https://api.tavily.com/search",
                    ExternalHttpSurface::SearchTavily,
                    body,
                ),
                |_permit| async { Ok(()) },
            )
            .await;
        let denied = denied.expect_err("denied released request must fail closed");
        assert_released_pretransport_error_is_coarse(
            &denied,
            &[topic, "api.tavily.com", "POST", "search_tavily", "operator denied"],
        );
        assert!(denied_sink.attempts.lock().unwrap().is_empty());

        let intent_sink = Arc::new(RecordingSink {
            fail: Some(ExtendedSubtype::ExternalHttpIntent),
            ..RecordingSink::default()
        });
        let intent_auth = ExternalHttpAuthorizer {
            policy: ExternalHttpPolicySource::Fixed(AutonomyPolicySnapshot::test_level(
                crate::permissions::AutonomyLevel::Standard,
            )),
            confirm: ConfirmStrategy::AlwaysAllow,
            channel_asker: None,
            sink: intent_sink.clone(),
            egress_provenance: ExplicitExternalResearchRelease::test_for_exact_topic(topic)
                .into_egress_provenance(),
        };
        intent_auth
            .arm_operator_released_exact_topic(topic)
            .unwrap();
        let intent: Result<()> = intent_auth
            .execute(
                ExternalHttpRequest::post(
                    "https://api.tavily.com/search",
                    ExternalHttpSurface::SearchTavily,
                    body,
                ),
                |_permit| async { Ok(()) },
            )
            .await;
        let intent = intent.expect_err("released intent failure must fail closed");
        assert_released_pretransport_error_is_coarse(
            &intent,
            &[topic, "api.tavily.com", "POST", "search_tavily", "injected audit failure"],
        );
        let intent_attempts = intent_sink.attempts.lock().unwrap();
        assert_eq!(intent_attempts.len(), 1);
        assert_released_payload_is_provider_neutral(
            &intent_attempts[0].1,
            &[topic, "api.tavily.com", "POST", "search_tavily"],
        );
        drop(intent_attempts);

        let permit_sink = Arc::new(RecordingSink::default());
        let permit_auth = ExternalHttpAuthorizer {
            policy: ExternalHttpPolicySource::Fixed(AutonomyPolicySnapshot::test_level(
                crate::permissions::AutonomyLevel::Standard,
            )),
            confirm: ConfirmStrategy::AlwaysAllow,
            channel_asker: None,
            sink: permit_sink.clone(),
            egress_provenance: ExplicitExternalResearchRelease::test_for_exact_topic(topic)
                .into_egress_provenance(),
        };
        permit_auth
            .arm_operator_released_exact_topic(topic)
            .unwrap();
        let called = AtomicBool::new(false);
        let permit: Result<()> = permit_auth
            .execute_with_permit_verifier(
                ExternalHttpRequest::post(
                    "https://api.tavily.com/search",
                    ExternalHttpSurface::SearchTavily,
                    body,
                ),
                |_permit, _request| {
                    anyhow::bail!("permit mismatch for c7 pretransport private topic")
                },
                |_permit| async {
                    called.store(true, Ordering::SeqCst);
                    Ok(())
                },
            )
            .await;
        let permit = permit.expect_err("released permit failure must fail closed");
        assert_released_pretransport_error_is_coarse(
            &permit,
            &[topic, "api.tavily.com", "POST", "search_tavily", "permit mismatch"],
        );
        assert!(!called.load(Ordering::SeqCst));
        let permit_attempts = permit_sink.attempts.lock().unwrap();
        assert_eq!(permit_attempts.len(), 2);
        for (_, payload) in permit_attempts.iter() {
            assert_released_payload_is_provider_neutral(
                payload,
                &[topic, "api.tavily.com", "POST", "search_tavily", "permit mismatch"],
            );
        }
    }

    #[tokio::test]
    async fn released_research_failure_never_hashes_or_persists_topic_bearing_error() {
        let topic = "c7 private topic 2026";
        let request_url =
            "https://api.search.brave.com/res/v1/web/search?q=c7%20private%20topic%202026";
        let topic_bearing_error_url =
            "https://failed.example.invalid/retry?q=c7%20private%20topic%202026";
        let error_text = format!("upstream retry failed for {topic_bearing_error_url}");
        let topic_bearing_error = anyhow::anyhow!(error_text.clone());
        let topic_sha256 = hex::encode(Sha256::digest(topic.as_bytes()));
        let legacy_error_sha256 = hex::encode(Sha256::digest(
            format!("{topic_bearing_error:#}").as_bytes(),
        ));
        let sink = Arc::new(RecordingSink::default());
        let auth = ExternalHttpAuthorizer {
            policy: ExternalHttpPolicySource::Fixed(AutonomyPolicySnapshot::test_level(
                crate::permissions::AutonomyLevel::Standard,
            )),
            confirm: ConfirmStrategy::AlwaysAllow,
            channel_asker: None,
            sink: sink.clone(),
            egress_provenance: ExplicitExternalResearchRelease::test_for_exact_topic(topic)
                .into_egress_provenance(),
        };
        auth.arm_operator_released_exact_topic(topic).unwrap();

        let result: Result<()> = auth
            .execute(
                ExternalHttpRequest::get(request_url, ExternalHttpSurface::SearchBrave),
                move |_permit| async move { Err(anyhow::anyhow!(error_text)) },
            )
            .await;
        let error = result.expect_err("released transport failure must remain fail-closed");
        assert!(matches!(
            error.downcast_ref::<ReleasedExternalHttpFailure>(),
            Some(ReleasedExternalHttpFailure::Transport)
        ));
        assert_eq!(error.to_string(), "released external HTTP request failed");
        let returned = format!("{error:#}");
        for marker in [
            topic,
            request_url,
            "api.search.brave.com",
            "search_brave",
            topic_bearing_error_url,
            &legacy_error_sha256,
            &topic_sha256,
        ] {
            assert!(!returned.contains(marker));
        }

        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        let request_id = events[0].1["request_id"].as_str().unwrap();
        let mut expected_audit_binding = Sha256::new();
        expected_audit_binding.update(b"NEOTH\0EXTERNAL_HTTP\0AUDIT_BINDING\0V1");
        expected_audit_binding.update(request_id.as_bytes());
        let expected_audit_binding = hex::encode(expected_audit_binding.finalize());
        assert_eq!(
            events[0].1["request_binding_sha256"],
            expected_audit_binding
        );
        assert_eq!(
            events[1].1["request_binding_sha256"],
            expected_audit_binding
        );
        assert_eq!(events[1].1["status"], "failure");
        assert!(events[1].1["error_sha256"].is_null());
        assert_eq!(events[1].1["error_code"], "external_http_request_failed");

        for (_, payload) in events.iter() {
            assert_released_payload_is_provider_neutral(
                payload,
                &[
                    topic,
                    request_url,
                    "api.search.brave.com",
                    "search_brave",
                    topic_bearing_error_url,
                    &legacy_error_sha256,
                    &topic_sha256,
                ],
            );
            assert!(payload.get("released_topic_sha256").is_none());
        }
    }

    #[tokio::test]
    async fn released_terminal_audit_failures_are_coarse_and_provider_neutral() {
        let topic = "c7 terminal audit topic";
        let request_url =
            "https://api.search.brave.com/res/v1/web/search?q=c7%20terminal%20audit%20topic";
        let upstream_error =
            "provider failure https://api.search.brave.com/?q=c7%20terminal%20audit%20topic";
        let topic_sha256 = hex::encode(Sha256::digest(topic.as_bytes()));
        let error_sha256 = hex::encode(Sha256::digest(upstream_error.as_bytes()));

        for transport_fails in [false, true] {
            let sink = Arc::new(RecordingSink {
                fail: Some(ExtendedSubtype::ExternalHttpResult),
                ..RecordingSink::default()
            });
            let auth = ExternalHttpAuthorizer {
                policy: ExternalHttpPolicySource::Fixed(AutonomyPolicySnapshot::test_level(
                    crate::permissions::AutonomyLevel::Standard,
                )),
                confirm: ConfirmStrategy::AlwaysAllow,
                channel_asker: None,
                sink: sink.clone(),
                egress_provenance: ExplicitExternalResearchRelease::test_for_exact_topic(topic)
                    .into_egress_provenance(),
            };
            auth.arm_operator_released_exact_topic(topic).unwrap();

            let result: Result<()> = auth
                .execute(
                    ExternalHttpRequest::get(request_url, ExternalHttpSurface::SearchBrave),
                    |_permit| async move {
                        if transport_fails {
                            anyhow::bail!(upstream_error);
                        }
                        Ok(())
                    },
                )
                .await;
            let error = result.expect_err("terminal audit failure must remain fail-closed");
            if transport_fails {
                assert!(matches!(
                    error.downcast_ref::<ReleasedExternalHttpFailure>(),
                    Some(ReleasedExternalHttpFailure::TransportAndTerminalAudit)
                ));
                assert_eq!(
                    error.to_string(),
                    "released external HTTP request and terminal audit failed"
                );
            } else {
                assert!(matches!(
                    error.downcast_ref::<ReleasedExternalHttpFailure>(),
                    Some(ReleasedExternalHttpFailure::TerminalAudit)
                ));
                assert_eq!(
                    error.to_string(),
                    "released external HTTP terminal audit failed"
                );
            }

            let returned = format!("{error:#}");
            for marker in [
                topic,
                request_url,
                "api.search.brave.com",
                "search_brave",
                upstream_error,
                &topic_sha256,
                &error_sha256,
                "injected audit failure",
            ] {
                assert!(!returned.contains(marker));
            }

            assert_eq!(sink.events.lock().unwrap().len(), 1);
            let attempts = sink.attempts.lock().unwrap();
            assert_eq!(attempts.len(), 2);
            assert_eq!(attempts[0].0, ExtendedSubtype::ExternalHttpIntent);
            assert_eq!(attempts[1].0, ExtendedSubtype::ExternalHttpResult);
            for (_, payload) in attempts.iter() {
                assert_released_payload_is_provider_neutral(
                    payload,
                    &[
                        topic,
                        request_url,
                        "api.search.brave.com",
                        "search_brave",
                        upstream_error,
                        &topic_sha256,
                        &error_sha256,
                    ],
                );
            }
        }
    }

    #[tokio::test]
    async fn operator_released_local_searxng_still_uses_gate_and_lifecycle_audit() {
        for url in [
            "http://127.0.0.1:8888/search?q=approved%20topic",
            "http://192.168.1.23:8888/search?q=approved%20topic",
        ] {
            let sequence = Arc::new(Mutex::new(Vec::new()));
            let asked = Arc::new(CountingAsker::approving_with_sequence(Arc::clone(
                &sequence,
            )));
            let called = AtomicBool::new(false);
            let sink = Arc::new(RecordingSink {
                sequence: Some(Arc::clone(&sequence)),
                ..RecordingSink::default()
            });
            let auth = ExternalHttpAuthorizer {
                policy: ExternalHttpPolicySource::Fixed(AutonomyPolicySnapshot::test_level(
                    crate::permissions::AutonomyLevel::Standard,
                )),
                confirm: ConfirmStrategy::Channel,
                channel_asker: Some(asked.clone()),
                sink: sink.clone(),
                egress_provenance: ExplicitExternalResearchRelease::test_for_exact_topic(
                    "approved topic",
                )
                .into_egress_provenance(),
            };
            auth.arm_operator_released_exact_topic("approved topic")
                .unwrap();

            auth.execute(
                ExternalHttpRequest::get(url, ExternalHttpSurface::SearchSearxng),
                |_permit| async {
                    called.store(true, Ordering::SeqCst);
                    sequence.lock().unwrap().push("transport");
                    Ok(())
                },
            )
            .await
            .unwrap();

            assert!(asked.asked.load(Ordering::SeqCst));
            assert!(called.load(Ordering::SeqCst));
            assert_eq!(
                sequence.lock().unwrap().as_slice(),
                ["confirm", "intent", "transport", "result"]
            );
            assert_eq!(sink.events.lock().unwrap().len(), 2);
        }
    }

    #[tokio::test]
    async fn rejected_operator_released_local_searxng_never_audits_or_transports() {
        let asked = Arc::new(CountingAsker::rejecting());
        let called = AtomicBool::new(false);
        let sink = Arc::new(RecordingSink::default());
        let auth = ExternalHttpAuthorizer {
            policy: ExternalHttpPolicySource::Fixed(AutonomyPolicySnapshot::test_level(
                crate::permissions::AutonomyLevel::Standard,
            )),
            confirm: ConfirmStrategy::Channel,
            channel_asker: Some(asked.clone()),
            sink: sink.clone(),
            egress_provenance: ExplicitExternalResearchRelease::test_for_exact_topic(
                "approved topic",
            )
            .into_egress_provenance(),
        };
        auth.arm_operator_released_exact_topic("approved topic")
            .unwrap();

        assert!(
            auth.execute(
                ExternalHttpRequest::get(
                    "http://127.0.0.1:8888/search?q=approved%20topic",
                    ExternalHttpSurface::SearchSearxng,
                ),
                |_permit| async {
                    called.store(true, Ordering::SeqCst);
                    Ok(())
                },
            )
            .await
            .is_err()
        );
        assert!(asked.asked.load(Ordering::SeqCst));
        assert!(!called.load(Ordering::SeqCst));
        assert!(sink.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn rejecting_operator_confirmation_writes_no_intent_or_result_and_never_transports() {
        let asked = Arc::new(CountingAsker::rejecting());
        let called = AtomicBool::new(false);
        let sink = Arc::new(RecordingSink::default());
        let auth = ExternalHttpAuthorizer {
            policy: ExternalHttpPolicySource::Fixed(AutonomyPolicySnapshot::test_level(
                crate::permissions::AutonomyLevel::Standard,
            )),
            confirm: ConfirmStrategy::Channel,
            channel_asker: Some(asked.clone()),
            sink: sink.clone(),
            egress_provenance: ExplicitExternalResearchRelease::test_for_exact_topic(
                "approved topic",
            )
            .into_egress_provenance(),
        };
        auth.arm_operator_released_exact_topic("approved topic")
            .unwrap();

        assert!(
            auth.execute(
                ExternalHttpRequest::get(
                    "https://api.search.brave.com/res/v1/web/search?q=approved%20topic",
                    ExternalHttpSurface::SearchBrave,
                ),
                |_permit| async {
                    called.store(true, Ordering::SeqCst);
                    Ok(())
                },
            )
            .await
            .is_err()
        );
        assert!(asked.asked.load(Ordering::SeqCst));
        assert!(!called.load(Ordering::SeqCst));
        assert!(sink.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn terminal_result_audit_failure_is_returned_after_transport() {
        let called = AtomicBool::new(false);
        let auth = authorizer(Arc::new(RecordingSink {
            fail: Some(ExtendedSubtype::ExternalHttpResult),
            ..RecordingSink::default()
        }));

        assert!(
            auth.execute(
                ExternalHttpRequest::get("https://example.com/x", ExternalHttpSurface::Fetch),
                |_permit| async {
                    called.store(true, Ordering::SeqCst);
                    Ok(())
                },
            )
            .await
            .is_err()
        );
        assert!(called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn legacy_unscoped_callers_remain_unclassified_not_implicitly_public() {
        let sink = Arc::new(RecordingSink::default());
        let auth = authorizer(sink.clone());
        assert!(auth.egress_provenance.sources().is_none());

        auth.execute(
            ExternalHttpRequest::get("https://example.com/x", ExternalHttpSurface::Fetch),
            |_permit| async { Ok(()) },
        )
        .await
        .unwrap();

        let events = sink.events.lock().unwrap();
        assert_eq!(events[0].1["egress_provenance"], "legacy_unscoped");
    }

    #[tokio::test]
    async fn request_drift_cannot_reach_transport() {
        let called = Arc::new(AtomicBool::new(false));
        let called_by_transport = Arc::clone(&called);
        let auth = authorizer(Arc::new(RecordingSink::default()));
        let authorised = ExternalHttpRequest::get(
            "https://example.com/api/item/1",
            ExternalHttpSurface::HackerNews,
        );
        let drifted = ExternalHttpRequest::get(
            "https://example.com/api/item/2",
            ExternalHttpSurface::HackerNews,
        );

        let result = auth
            .execute(authorised, |permit| async move {
                permit.require(&drifted)?;
                called_by_transport.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await;

        assert!(
            result.is_err(),
            "a permit must reject a changed concrete URL"
        );
        assert!(
            !called.load(Ordering::SeqCst),
            "request drift must be rejected before the transport call"
        );
    }
}
