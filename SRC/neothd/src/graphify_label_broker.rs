//! A deliberately tiny, short-lived OpenAI-compatible label endpoint for
//! Graphify.
//!
//! Graphify is an untrusted subprocess.  It receives a loopback URL containing
//! an unguessable capability, never a provider credential.  Every accepted
//! request becomes a fresh [`crate::providers::Request`] and is sent through
//! the caller-owned [`AuthorizedProvider`], preserving its normal consent,
//! authorization, cost-WAL, and completion-WAL boundary.

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Bytes, Incoming as IncomingBody};
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{Method, Request as HyperRequest, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore, oneshot};
use uuid::Uuid;

use crate::providers::cost_authorization::AuthorizedProvider;
use crate::providers::{Provider as _, Request};

const PLACEHOLDER_BEARER: &str = "Bearer ollama";
const CHAT_COMPLETIONS_SUFFIX: &str = "/v1/chat/completions";
const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_MESSAGES: usize = 1;
const DEFAULT_MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 2;
const DEFAULT_MAX_CONNECTIONS: usize = 4;
const MAX_PLANNED_BATCHES: usize = 64;
const MAX_BUDGETED_BATCHES: usize = 16;
const MAX_BUDGETED_DISTINCT_IDS: usize = 1600;
const MAX_CONNECTIONS: usize = 64;
const MAX_HEADERS: usize = 32;
const DEFAULT_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(120);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(90);
const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
const LABEL_PROMPT_PREFIX: &str = concat!(
    "You are naming clusters in a knowledge graph. For each community below, ",
    "return a concise 2-5 word plain-language name describing what it is about ",
    "(e.g. \"Order Management\", \"Payment Flow\", \"Auth Middleware\"). ",
    "Respond ONLY with a JSON object mapping the community id (as a string) to ",
    "its name - no prose, no markdown fences.\n\n"
);

/// The authorization status exposed with a broker connection.
///
/// `BudgetedBatches` deliberately does not claim that the caller preplanned
/// Graphify's private cluster partitioning. It is a smaller transitional
/// envelope, not an alias for [`Self::ExactPlannedBatches`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphifyLabelBrokerAuthorizationMode {
    ExactPlannedBatches,
    BudgetedBatches,
}

/// The caller-derived authorization envelope for one Graphify invocation.
#[derive(Clone, Debug)]
pub enum GraphifyLabelBrokerAuthorization {
    /// Only these exact community-ID batches may be sent, each once.
    ExactPlannedBatches {
        planned_batches: Vec<BTreeSet<String>>,
    },
    /// A conservative temporary envelope for Graphify 0.8.41 when its private
    /// community partition cannot yet be reproduced at the caller. Requests
    /// remain grammar-bound, serial, and one-time by community ID; it does not
    /// authorize arbitrary batches or claim exact preplanning.
    BudgetedBatches {
        max_batches: usize,
        max_distinct_ids: usize,
    },
}

/// Explicit resource limits for one Graphify invocation's label broker.
///
/// The broker deliberately has no listen-address field: it always binds an
/// ephemeral IPv4 loopback address, and callers cannot widen that boundary.
#[derive(Clone, Debug)]
pub struct GraphifyLabelBrokerConfig {
    /// The explicit exact-plan or conservative-budget authorization envelope
    /// for this Graphify invocation. The connection exposes its selected mode
    /// so budgeted execution cannot be represented as an exact plan.
    pub authorization: GraphifyLabelBrokerAuthorization,
    pub max_body_bytes: usize,
    pub max_messages: usize,
    pub max_message_bytes: usize,
    pub max_concurrent_requests: usize,
    pub max_connections: usize,
    pub header_timeout: Duration,
    pub connection_timeout: Duration,
    pub request_timeout: Duration,
    pub shutdown_drain_timeout: Duration,
}

impl Default for GraphifyLabelBrokerConfig {
    fn default() -> Self {
        Self {
            // An empty plan is deliberately invalid. The caller must bind the
            // capability to the concrete Graphify work it authorized.
            authorization: GraphifyLabelBrokerAuthorization::ExactPlannedBatches {
                planned_batches: Vec::new(),
            },
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_messages: DEFAULT_MAX_MESSAGES,
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            max_concurrent_requests: DEFAULT_MAX_CONCURRENT_REQUESTS,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            header_timeout: DEFAULT_HEADER_TIMEOUT,
            connection_timeout: DEFAULT_CONNECTION_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            shutdown_drain_timeout: DEFAULT_DRAIN_TIMEOUT,
        }
    }
}

impl GraphifyLabelBrokerConfig {
    /// Start from the broker defaults while binding it to the batches selected
    /// by the caller's Graphify plan.
    pub fn for_planned_batches(planned_batches: Vec<BTreeSet<String>>) -> Result<Self> {
        let config = Self {
            authorization: GraphifyLabelBrokerAuthorization::ExactPlannedBatches {
                planned_batches,
            },
            ..Self::default()
        };
        config.validate()?;
        Ok(config)
    }

    /// Use only while the caller cannot safely reconstruct Graphify 0.8.41's
    /// exact private cluster batching. This is not exact-plan authorization:
    /// it permits at most 16 serial requests / 1600 globally unique decimal
    /// community IDs, with no repeated ID across requests.
    pub fn for_budgeted_batches(max_batches: usize, max_distinct_ids: usize) -> Result<Self> {
        let config = Self {
            authorization: GraphifyLabelBrokerAuthorization::BudgetedBatches {
                max_batches,
                max_distinct_ids,
            },
            // A budgeted invocation must remain serial so the budget is a
            // simple, auditable upper bound even if Graphify retries badly.
            max_concurrent_requests: 1,
            ..Self::default()
        };
        config.validate()?;
        Ok(config)
    }

    pub fn authorization_mode(&self) -> GraphifyLabelBrokerAuthorizationMode {
        match &self.authorization {
            GraphifyLabelBrokerAuthorization::ExactPlannedBatches { .. } => {
                GraphifyLabelBrokerAuthorizationMode::ExactPlannedBatches
            }
            GraphifyLabelBrokerAuthorization::BudgetedBatches { .. } => {
                GraphifyLabelBrokerAuthorizationMode::BudgetedBatches
            }
        }
    }

    fn validate(&self) -> Result<()> {
        if self.max_body_bytes == 0
            || self.max_messages == 0
            || self.max_message_bytes == 0
            || self.max_concurrent_requests == 0
            || self.max_connections == 0
            || self.header_timeout.is_zero()
            || self.connection_timeout.is_zero()
            || self.request_timeout.is_zero()
            || self.shutdown_drain_timeout.is_zero()
        {
            bail!("Graphify label broker limits must be non-zero");
        }
        if self.max_message_bytes > self.max_body_bytes {
            bail!("Graphify label broker message limit exceeds body limit");
        }
        if self.request_timeout > self.connection_timeout {
            bail!("Graphify label broker request timeout exceeds connection lifetime");
        }
        if self.max_body_bytes > DEFAULT_MAX_BODY_BYTES
            || self.max_concurrent_requests > 64
            || self.max_connections > MAX_CONNECTIONS
            || self.header_timeout > Duration::from_secs(60)
            || self.connection_timeout > Duration::from_secs(300)
            || self.request_timeout > Duration::from_secs(300)
            || self.shutdown_drain_timeout > Duration::from_secs(60)
        {
            bail!("Graphify label broker limit exceeds its hard maximum");
        }
        match &self.authorization {
            GraphifyLabelBrokerAuthorization::ExactPlannedBatches { planned_batches } => {
                if planned_batches.is_empty() || planned_batches.len() > MAX_PLANNED_BATCHES {
                    bail!(
                        "Graphify label broker requires 1-{MAX_PLANNED_BATCHES} planned label batches"
                    );
                }
                let mut all_community_ids = BTreeSet::new();
                let mut batch_keys = BTreeSet::new();
                for batch in planned_batches {
                    if batch.is_empty() || batch.len() > 100 {
                        bail!(
                            "Graphify label broker planned batches must contain 1-100 communities"
                        );
                    }
                    let key = batch.iter().cloned().collect::<Vec<_>>();
                    if !batch_keys.insert(key) {
                        bail!("Graphify label broker planned batches must be unique");
                    }
                    for id in batch {
                        if !valid_community_id(id) || !all_community_ids.insert(id.clone()) {
                            bail!(
                                "Graphify label broker planned community ids must be unique decimal ids"
                            );
                        }
                    }
                }
            }
            GraphifyLabelBrokerAuthorization::BudgetedBatches {
                max_batches,
                max_distinct_ids,
            } => {
                if *max_batches == 0
                    || *max_batches > MAX_BUDGETED_BATCHES
                    || *max_distinct_ids == 0
                    || *max_distinct_ids > MAX_BUDGETED_DISTINCT_IDS
                {
                    bail!(
                        "Graphify budgeted label broker requires 1-{MAX_BUDGETED_BATCHES} batches and 1-{MAX_BUDGETED_DISTINCT_IDS} distinct ids"
                    );
                }
                if self.max_concurrent_requests != 1 {
                    bail!("Graphify budgeted label broker requires max_concurrent_requests = 1");
                }
            }
        }
        Ok(())
    }
}

/// The complete, credentialless configuration passed to Graphify.
///
/// `ollama_base_url` is intentionally a capability URL rather than a secret
/// provider endpoint.  It is valid only while this one broker listener runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphifyLabelBrokerConnection {
    pub ollama_base_url: String,
    pub model: String,
    pub backend: &'static str,
    /// Exposes whether this capability has exact planned identities or the
    /// explicitly weaker, conservative budgeted authorization envelope.
    pub authorization_mode: GraphifyLabelBrokerAuthorizationMode,
}

impl GraphifyLabelBrokerConnection {
    /// Environment pairs for `graphifyy --backend ollama`.  There is no API
    /// key in this output; Graphify's fixed `Bearer ollama` is only a protocol
    /// sentinel checked at the capability endpoint.
    pub fn environment(&self) -> [(&'static str, String); 2] {
        [
            ("OLLAMA_BASE_URL", self.ollama_base_url.clone()),
            ("OLLAMA_MODEL", self.model.clone()),
        ]
    }
}

/// A single-use loopback listener.  Construct it after the parent operation
/// has already obtained its authorized NEOTH provider boundary.
pub struct GraphifyLabelBroker {
    listener: TcpListener,
    state: Arc<BrokerState>,
    connection: GraphifyLabelBrokerConnection,
}

struct BrokerState {
    provider: Arc<AuthorizedProvider>,
    expected_model: String,
    capability_path: String,
    config: GraphifyLabelBrokerConfig,
    batch_admission: Mutex<BatchAdmission>,
    provider_tasks: Arc<ProviderTaskTracker>,
    started: AtomicBool,
    closed: AtomicBool,
}

/// Broker-owned ownership of every provider call admitted through the
/// loopback capability.  A timed-out HTTP exchange may drop its result waiter,
/// but it can never detach the AuthorizedProvider call from this tracker.
struct ProviderTaskTracker {
    state: Mutex<ProviderTaskTrackerState>,
    in_flight: AtomicUsize,
    quiescent: Notify,
}

struct ProviderTaskTrackerState {
    accepting: bool,
    tasks: tokio::task::JoinSet<()>,
}

/// Decrements the shared in-flight count on every terminal task path,
/// including a provider error or a panic unwound through Tokio's JoinSet.
struct ProviderTaskGuard {
    tracker: Arc<ProviderTaskTracker>,
}

impl Drop for ProviderTaskGuard {
    fn drop(&mut self) {
        let previous = self.tracker.in_flight.fetch_sub(1, Ordering::SeqCst);
        debug_assert!(previous > 0, "provider task tracker underflow");
        self.tracker.quiescent.notify_waiters();
    }
}

impl ProviderTaskTracker {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(ProviderTaskTrackerState {
                accepting: true,
                tasks: tokio::task::JoinSet::new(),
            }),
            in_flight: AtomicUsize::new(0),
            quiescent: Notify::new(),
        })
    }

    /// Atomically admits and registers the provider call before it can run.
    /// Once shutdown has taken the join set, later connection work is rejected
    /// instead of escaping the broker's lifecycle ownership.
    fn admit_and_spawn(
        self: &Arc<Self>,
        provider: Arc<AuthorizedProvider>,
        request: Request,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> std::result::Result<
        oneshot::Receiver<std::result::Result<crate::providers::Completion, BrokerError>>,
        BrokerError,
    > {
        let mut state = self
            .state
            .lock()
            .expect("Graphify provider task tracker mutex is not poisoned");
        if !state.accepting {
            return Err(BrokerError::Unavailable);
        }

        self.in_flight.fetch_add(1, Ordering::SeqCst);
        let guard = ProviderTaskGuard {
            tracker: Arc::clone(self),
        };
        let (result_tx, result_rx) = oneshot::channel();
        state.tasks.spawn(async move {
            let _guard = guard;
            let _permit = permit;
            let result = provider.complete(request).await.map_err(|error| {
                tracing::warn!(error = %error, "Graphify label provider call failed");
                BrokerError::Upstream
            });
            // A timed-out/disconnected HTTP caller deliberately drops this
            // receiver. The task still remains broker-owned until its provider
            // and WAL lifecycle have reached this terminal point.
            let _ = result_tx.send(result);
        });
        Ok(result_rx)
    }

    /// Prevent any later admission and transfer every already-registered task
    /// to `serve` for an unbounded, honest terminal drain.
    fn stop_accepting_and_take(&self) -> tokio::task::JoinSet<()> {
        let mut state = self
            .state
            .lock()
            .expect("Graphify provider task tracker mutex is not poisoned");
        state.accepting = false;
        std::mem::take(&mut state.tasks)
    }

    async fn wait_for_quiescence(&self) {
        loop {
            if self.in_flight.load(Ordering::SeqCst) == 0 {
                return;
            }
            let notified = self.quiescent.notified();
            if self.in_flight.load(Ordering::SeqCst) == 0 {
                return;
            }
            notified.await;
        }
    }
}

/// Mutable, one-listener admission state. A single mutex intentionally makes
/// the security decision atomic: an ID cannot be admitted twice by racing two
/// HTTP connections.
enum BatchAdmission {
    ExactPlannedBatches(BTreeSet<Vec<String>>),
    BudgetedBatches {
        max_batches: usize,
        max_distinct_ids: usize,
        admitted_batches: usize,
        admitted_ids: BTreeSet<String>,
    },
}

impl BatchAdmission {
    fn from_authorization(authorization: &GraphifyLabelBrokerAuthorization) -> Self {
        match authorization {
            GraphifyLabelBrokerAuthorization::ExactPlannedBatches { planned_batches } => {
                Self::ExactPlannedBatches(
                    planned_batches
                        .iter()
                        .map(|batch| batch.iter().cloned().collect())
                        .collect(),
                )
            }
            GraphifyLabelBrokerAuthorization::BudgetedBatches {
                max_batches,
                max_distinct_ids,
            } => Self::BudgetedBatches {
                max_batches: *max_batches,
                max_distinct_ids: *max_distinct_ids,
                admitted_batches: 0,
                admitted_ids: BTreeSet::new(),
            },
        }
    }
}

impl GraphifyLabelBroker {
    /// Bind an ephemeral IPv4 loopback listener and mint its one-process
    /// capability path.  This API never accepts provider credentials.
    pub async fn bind(
        provider: Arc<AuthorizedProvider>,
        expected_model: impl Into<String>,
        config: GraphifyLabelBrokerConfig,
    ) -> Result<Self> {
        config.validate()?;
        let expected_model = expected_model.into();
        validate_model(&expected_model)?;

        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .context("bind loopback Graphify label broker")?;
        let local = listener
            .local_addr()
            .context("read Graphify label broker address")?;
        if !local.ip().is_loopback() {
            bail!("Graphify label broker unexpectedly bound outside loopback");
        }

        // UUID v4 is OS-random and URL-path safe.  It is a per-listener
        // capability, not an upstream credential.
        let capability_path = format!("/graphify-{}", Uuid::new_v4());
        let batch_admission = BatchAdmission::from_authorization(&config.authorization);
        let connection = GraphifyLabelBrokerConnection {
            ollama_base_url: format!("http://{local}{capability_path}/v1"),
            model: expected_model.clone(),
            backend: "ollama",
            authorization_mode: config.authorization_mode(),
        };
        Ok(Self {
            listener,
            state: Arc::new(BrokerState {
                provider,
                expected_model,
                capability_path,
                config,
                batch_admission: Mutex::new(batch_admission),
                provider_tasks: ProviderTaskTracker::new(),
                started: AtomicBool::new(false),
                closed: AtomicBool::new(false),
            }),
            connection,
        })
    }

    pub fn connection(&self) -> &GraphifyLabelBrokerConnection {
        &self.connection
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listener
            .local_addr()
            .expect("a live Graphify label listener always has a local address")
    }

    /// Serve until `shutdown` resolves, then stop accepting immediately.
    ///
    /// HTTP response timeouts do not cancel admitted provider calls: their WAL
    /// lifecycle is broker-owned. Before this method returns it aborts and joins
    /// remaining HTTP connection tasks, then waits for every admitted provider
    /// call to reach a terminal state. Therefore a successful `serve` return
    /// proves that no broker-owned provider/WAL work remains in flight.
    /// A broker cannot be started twice; after shutdown its capability is
    /// permanently dead.
    pub async fn serve(self, shutdown: impl Future<Output = ()> + Send + 'static) -> Result<()> {
        if self.state.started.swap(true, Ordering::SeqCst) {
            bail!("Graphify label broker cannot be reused");
        }
        let request_gate = Arc::new(Semaphore::new(self.state.config.max_concurrent_requests));
        let connection_gate = Arc::new(Semaphore::new(self.state.config.max_connections));
        let mut tasks = tokio::task::JoinSet::new();
        let mut shutdown = Box::pin(shutdown);
        let mut terminal_error = None;

        'serve: loop {
            // Acquire a connection permit before calling `accept`. This pushes
            // overload into the TCP backlog instead of creating unbounded
            // accepted sockets, Hyper futures, or Tokio tasks.
            let connection_permit = tokio::select! {
                biased;
                _ = &mut shutdown => break 'serve,
                Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                    if let Err(error) = observe_connection_task(result) {
                        terminal_error = Some(error);
                        break 'serve;
                    }
                    continue;
                }
                permit = Arc::clone(&connection_gate).acquire_owned() => {
                    permit.expect("Graphify label broker does not close its connection gate")
                }
            };

            tokio::select! {
                biased;
                _ = &mut shutdown => {
                    drop(connection_permit);
                    break 'serve;
                }
                Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                    drop(connection_permit);
                    if let Err(error) = observe_connection_task(result) {
                        terminal_error = Some(error);
                        break 'serve;
                    }
                    continue;
                }
                accepted = self.listener.accept() => {
                    let (stream, peer) = match accepted.context("accept Graphify label broker connection") {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            terminal_error = Some(error);
                            break 'serve;
                        }
                    };
                    if !peer.ip().is_loopback() {
                        drop(stream);
                        continue;
                    }
                    let state = Arc::clone(&self.state);
                    let request_gate = Arc::clone(&request_gate);
                    tasks.spawn(async move {
                        let _connection_permit = connection_permit;
                        serve_connection(state, request_gate, stream).await;
                    });
                }
            }
        }

        self.state.closed.store(true, Ordering::SeqCst);
        // Closing this tracker is serialized with admission. Any accepted HTTP
        // task either registered its provider work before this point, or sees
        // the closed tracker and cannot create orphaned WAL work afterwards.
        let mut provider_tasks = self.state.provider_tasks.stop_accepting_and_take();
        let connection_result =
            drain_connection_tasks(&mut tasks, self.state.config.shutdown_drain_timeout).await;
        let provider_result =
            drain_provider_tasks(&mut provider_tasks, &self.state.provider_tasks).await;

        match (terminal_error, connection_result, provider_result) {
            (Some(error), Err(connection_error), Err(provider_error)) => Err(error.context(
                format!(
                    "connection drain also failed: {connection_error}; provider drain also failed: {provider_error}"
                ),
            )),
            (Some(error), Err(connection_error), Ok(())) => Err(error.context(format!(
                "connection drain also failed: {connection_error}"
            ))),
            (Some(error), Ok(()), Err(provider_error)) => Err(error.context(format!(
                "provider drain also failed: {provider_error}"
            ))),
            (Some(error), Ok(()), Ok(())) => Err(error),
            (None, Err(connection_error), Err(provider_error)) => Err(connection_error.context(
                format!("provider drain also failed: {provider_error}"),
            )),
            (None, Err(connection_error), Ok(())) => Err(connection_error),
            (None, Ok(()), Err(provider_error)) => Err(provider_error),
            (None, Ok(()), Ok(())) => Ok(()),
        }
    }
}

/// A malformed or timed-out peer is local request noise, not a broker failure.
/// A Tokio task panic or cancellation is different: return it to the caller so
/// the parent operation cannot claim a successful Graphify run after the broker
/// lost an accepted connection task unexpectedly.
fn observe_connection_task(result: std::result::Result<(), tokio::task::JoinError>) -> Result<()> {
    result.map_err(|error| anyhow::anyhow!("Graphify label broker connection task failed: {error}"))
}

async fn drain_connection_tasks(
    tasks: &mut tokio::task::JoinSet<()>,
    drain_timeout: Duration,
) -> Result<()> {
    let drained = tokio::time::timeout(drain_timeout, async {
        while let Some(result) = tasks.join_next().await {
            observe_connection_task(result)?;
        }
        Ok(())
    })
    .await;
    match drained {
        Ok(result) => result,
        Err(_) => {
            // This affects only HTTP connection tasks. Provider calls were
            // registered separately before they started and are drained below.
            tasks.abort_all();
            while let Some(result) = tasks.join_next().await {
                if let Err(error) = result
                    && !error.is_cancelled()
                {
                    return Err(anyhow::anyhow!(
                        "Graphify label broker connection task failed while forcing shutdown: {error}"
                    ));
                }
            }
            tracing::warn!(
                "Graphify label broker connection drain timed out; aborted and joined HTTP tasks"
            );
            Ok(())
        }
    }
}

/// Wait without an internal deadline for the terminal result of every provider
/// task that crossed broker admission. The caller that owns this broker applies
/// any finite overall shutdown deadline and retains ownership if it expires;
/// claiming local quiescence sooner would permit WAL teardown races.
async fn drain_provider_tasks(
    tasks: &mut tokio::task::JoinSet<()>,
    tracker: &ProviderTaskTracker,
) -> Result<()> {
    let mut task_error = None;
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            let error = anyhow::anyhow!(
                "Graphify label broker provider task failed before terminal lifecycle: {error}"
            );
            if task_error.is_none() {
                task_error = Some(error);
            }
        }
    }
    tracker.wait_for_quiescence().await;
    if let Some(error) = task_error {
        Err(error)
    } else {
        Ok(())
    }
}

async fn serve_connection(
    state: Arc<BrokerState>,
    request_gate: Arc<Semaphore>,
    stream: tokio::net::TcpStream,
) {
    let mut builder = http1::Builder::new();
    builder
        .keep_alive(false)
        .max_headers(MAX_HEADERS)
        .timer(TokioTimer::new())
        .header_read_timeout(state.config.header_timeout);
    let service = BrokerService {
        state: Arc::clone(&state),
        request_gate,
    };
    let connection = builder.serve_connection(TokioIo::new(stream), service);
    match tokio::time::timeout(state.config.connection_timeout, connection).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            tracing::debug!(error = %error, "Graphify label broker connection ended with HTTP error");
        }
        Err(_) => {
            tracing::debug!("Graphify label broker connection lifetime exceeded limit");
        }
    }
}

#[derive(Clone)]
struct BrokerService {
    state: Arc<BrokerState>,
    request_gate: Arc<Semaphore>,
}

impl Service<HyperRequest<IncomingBody>> for BrokerService {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future =
        Pin<Box<dyn Future<Output = std::result::Result<Self::Response, Infallible>> + Send>>;

    fn call(&self, request: HyperRequest<IncomingBody>) -> Self::Future {
        let state = Arc::clone(&self.state);
        let request_gate = Arc::clone(&self.request_gate);
        Box::pin(async move {
            let response = match handle_request(state, request_gate, request).await {
                Ok(response) => response,
                Err(error) => error.response(),
            };
            Ok(response)
        })
    }
}

async fn handle_request(
    state: Arc<BrokerState>,
    request_gate: Arc<Semaphore>,
    request: HyperRequest<IncomingBody>,
) -> std::result::Result<Response<Full<Bytes>>, BrokerError> {
    // This deadline bounds the HTTP caller's wait across body receipt and the
    // provider response. It does not cancel an admitted AuthorizedProvider
    // call: the broker's shared tracker owns that call until its durable
    // authorization/completion lifecycle reaches a terminal state.
    let request_deadline = tokio::time::Instant::now() + state.config.request_timeout;
    if state.closed.load(Ordering::SeqCst) {
        return Err(BrokerError::Unavailable);
    }
    if request.method() != Method::POST
        || request.uri().path() != format!("{}{}", state.capability_path, CHAT_COMPLETIONS_SUFFIX)
        || request.uri().query().is_some()
    {
        return Err(BrokerError::NotFound);
    }
    if request
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        != Some(PLACEHOLDER_BEARER)
    {
        return Err(BrokerError::Unauthorized);
    }
    if !request
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
        })
    {
        return Err(BrokerError::BadRequest);
    }
    if request
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > state.config.max_body_bytes)
    {
        return Err(BrokerError::TooLarge);
    }
    let body = tokio::time::timeout_at(
        request_deadline,
        read_limited(request.into_body(), state.config.max_body_bytes),
    )
    .await
    .map_err(|_| BrokerError::Timeout)??;
    let chat: ChatCompletionRequest =
        serde_json::from_slice(&body).map_err(|_| BrokerError::BadRequest)?;
    let label_request = parse_chat_request(chat, &state)?;
    let permit = Arc::clone(&request_gate)
        .try_acquire_owned()
        .map_err(|_| BrokerError::Busy)?;
    claim_authorized_batch(&state, &label_request.community_ids)?;
    let provider_timeout = request_deadline
        .checked_duration_since(tokio::time::Instant::now())
        .ok_or(BrokerError::Timeout)?;
    let completion = dispatch_provider(
        Arc::clone(&state.provider_tasks),
        Arc::clone(&state.provider),
        label_request.request,
        permit,
        provider_timeout,
    )
    .await?;
    validate_label_completion(&completion.text, &label_request.community_ids)
        .map_err(|_| BrokerError::Upstream)?;
    Ok(chat_response(&state.expected_model, completion))
}

/// The connection task owns only the HTTP exchange. Once a request passed all
/// local validation and planned-batch checks, the provider call is admitted to
/// the broker-owned tracker before it starts. The timeout bounds only the HTTP
/// caller's wait; it never cancels admitted provider/WAL work.
async fn dispatch_provider(
    provider_tasks: Arc<ProviderTaskTracker>,
    provider: Arc<AuthorizedProvider>,
    request: Request,
    permit: tokio::sync::OwnedSemaphorePermit,
    response_timeout: Duration,
) -> std::result::Result<crate::providers::Completion, BrokerError> {
    let result_rx = provider_tasks.admit_and_spawn(provider, request, permit)?;
    match tokio::time::timeout(response_timeout, result_rx).await {
        Ok(result) => result.map_err(|_| {
            tracing::error!("Graphify label provider task terminated unexpectedly");
            BrokerError::Upstream
        })?,
        Err(_) => {
            // The result receiver is dropped, not the tracked provider task.
            // Its permit remains held until the provider reaches a terminal
            // outcome, which correctly applies backpressure to later calls.
            tracing::warn!(
                "Graphify label provider response timed out; broker retains provider task for WAL completion"
            );
            Err(BrokerError::Timeout)
        }
    }
}

async fn read_limited<B>(body: B, cap: usize) -> std::result::Result<Vec<u8>, BrokerError>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send + Sync + 'static,
{
    let mut limited = Limited::new(body, cap);
    let mut bytes = Vec::new();
    while let Some(frame) = limited.frame().await {
        let frame = frame.map_err(|_| BrokerError::TooLarge)?;
        if let Ok(data) = frame.into_data() {
            let projected = bytes
                .len()
                .checked_add(data.len())
                .ok_or(BrokerError::TooLarge)?;
            if projected > cap {
                return Err(BrokerError::TooLarge);
            }
            bytes
                .try_reserve(data.len())
                .map_err(|_| BrokerError::TooLarge)?;
            bytes.extend_from_slice(&data);
        }
    }
    Ok(bytes)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChatCompletionRequest {
    model: String,
    messages: Vec<ChatMessage>,
    #[serde(default)]
    max_completion_tokens: Option<u32>,
    #[serde(default)]
    stream: Option<bool>,
    #[serde(default)]
    temperature: Option<f32>,
    #[serde(default)]
    options: Option<LabelOptions>,
    #[serde(default)]
    keep_alive: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LabelOptions {
    num_ctx: u32,
}

struct LabelRequest {
    request: Request,
    community_ids: BTreeSet<String>,
}

fn parse_chat_request(
    chat: ChatCompletionRequest,
    state: &BrokerState,
) -> std::result::Result<LabelRequest, BrokerError> {
    if chat.model != state.expected_model || chat.stream == Some(true) {
        return Err(BrokerError::BadRequest);
    }
    // graphifyy 0.8.41 sends exactly one user string.  Keeping the shape this
    // narrow makes it impossible for a child to inject an assistant transcript,
    // tool transcript, or a system instruction into the NEOTH provider call.
    if chat.messages.len() != 1 || chat.messages.len() > state.config.max_messages {
        return Err(BrokerError::BadRequest);
    }
    if chat
        .temperature
        .is_some_and(|value| !value.is_finite() || value != 0.0)
        || chat
            .options
            .is_some_and(|options| !(8192..=131_072).contains(&options.num_ctx))
        || chat
            .keep_alive
            .as_deref()
            .is_some_and(|value| value != "30m")
    {
        return Err(BrokerError::BadRequest);
    }
    let message = chat
        .messages
        .into_iter()
        .next()
        .expect("one message checked above");
    if message.role != "user" || message.content.len() > state.config.max_message_bytes {
        return Err(BrokerError::BadRequest);
    }
    let community_ids = parse_label_prompt(&message.content)?;
    let expected_max_tokens =
        (64 + 24 * u32::try_from(community_ids.len()).unwrap_or(100)).min(8192);
    if message.content.len() > state.config.max_body_bytes
        || chat
            .max_completion_tokens
            .is_some_and(|value| value != expected_max_tokens)
    {
        return Err(BrokerError::BadRequest);
    }
    Ok(LabelRequest {
        request: Request {
            prompt: message.content,
            system: None,
            model: Some(state.expected_model.clone()),
            // The only child-controlled sampling value admitted by this protocol
            // is Graphify's pinned zero.  It remains part of the authorized NEOTH
            // request binding rather than becoming an untracked broker setting.
            temperature: chat.temperature,
            max_output_tokens: Some(expected_max_tokens),
            ..Request::default()
        },
        community_ids,
    })
}

fn parse_label_prompt(prompt: &str) -> std::result::Result<BTreeSet<String>, BrokerError> {
    if has_forbidden_control(prompt) {
        return Err(BrokerError::BadRequest);
    }
    let lines = prompt
        .strip_prefix(LABEL_PROMPT_PREFIX)
        .ok_or(BrokerError::BadRequest)?;
    let mut community_ids = BTreeSet::new();
    for line in lines.split('\n') {
        let rest = line
            .strip_prefix("Community ")
            .ok_or(BrokerError::BadRequest)?;
        let (id, representatives) = rest.split_once(": ").ok_or(BrokerError::BadRequest)?;
        if !valid_community_id(id)
            || representatives.is_empty()
            || has_forbidden_control(representatives)
            || !community_ids.insert(id.to_owned())
        {
            return Err(BrokerError::BadRequest);
        }
    }
    if !(1..=100).contains(&community_ids.len()) {
        return Err(BrokerError::BadRequest);
    }
    Ok(community_ids)
}

fn validate_label_completion(
    text: &str,
    requested_ids: &BTreeSet<String>,
) -> std::result::Result<(), ()> {
    let object = serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .ok_or(())?;
    let returned_ids = object.keys().cloned().collect::<BTreeSet<_>>();
    if &returned_ids != requested_ids {
        return Err(());
    }
    for label in object.values() {
        let label = label.as_str().ok_or(())?;
        if label.trim() != label
            || label.is_empty()
            || label.len() > 120
            || has_forbidden_control(label)
            || !(2..=5).contains(&label.split_whitespace().count())
        {
            return Err(());
        }
    }
    Ok(())
}

fn has_forbidden_control(value: &str) -> bool {
    value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
}

fn claim_authorized_batch(
    state: &BrokerState,
    community_ids: &BTreeSet<String>,
) -> std::result::Result<(), BrokerError> {
    let batch = community_ids.iter().cloned().collect::<Vec<_>>();
    let mut admission = state
        .batch_admission
        .lock()
        .map_err(|_| BrokerError::Unavailable)?;
    match &mut *admission {
        BatchAdmission::ExactPlannedBatches(remaining) => {
            if remaining.remove(&batch) {
                Ok(())
            } else {
                // A valid-looking request that is not in the caller's one-time
                // plan is still denied. This prevents Graphify from replaying
                // an expensive batch after any transient response or from
                // inventing another exact batch.
                Err(BrokerError::ReplayOrUnplanned)
            }
        }
        BatchAdmission::BudgetedBatches {
            max_batches,
            max_distinct_ids,
            admitted_batches,
            admitted_ids,
        } => {
            if community_ids.iter().any(|id| admitted_ids.contains(id)) {
                // The parser already rejects a duplicate within one request.
                // This branch rejects a duplicate across accepted requests.
                return Err(BrokerError::ReplayOrUnplanned);
            }
            if *admitted_batches >= *max_batches
                || community_ids.len() > (*max_distinct_ids).saturating_sub(admitted_ids.len())
            {
                return Err(BrokerError::BudgetExhausted);
            }
            admitted_ids.extend(community_ids.iter().cloned());
            *admitted_batches += 1;
            Ok(())
        }
    }
}

fn valid_community_id(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit())
}

fn validate_model(model: &str) -> Result<()> {
    if model.is_empty() || model.len() > 256 || has_forbidden_control(model) {
        bail!("Graphify label model must be non-empty printable text up to 256 bytes");
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum BrokerError {
    BadRequest,
    Unauthorized,
    NotFound,
    TooLarge,
    Busy,
    ReplayOrUnplanned,
    BudgetExhausted,
    Timeout,
    Upstream,
    Unavailable,
}

impl BrokerError {
    fn response(self) -> Response<Full<Bytes>> {
        let (status, code, message) = match self {
            Self::BadRequest => (
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "invalid label request",
            ),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "invalid_authorization",
                "invalid placeholder authorization",
            ),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", "route not found"),
            Self::TooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_too_large",
                "label request too large",
            ),
            Self::Busy => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limit_exceeded",
                "label broker busy",
            ),
            Self::ReplayOrUnplanned => (
                StatusCode::CONFLICT,
                "replay_or_unplanned",
                "label batch was not authorized for this broker run",
            ),
            Self::BudgetExhausted => (
                StatusCode::TOO_MANY_REQUESTS,
                "budget_exhausted",
                "label broker budget exhausted",
            ),
            Self::Timeout => (
                StatusCode::GATEWAY_TIMEOUT,
                "timeout",
                "label request timed out",
            ),
            Self::Upstream => (
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                "label provider unavailable",
            ),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "label broker unavailable",
            ),
        };
        #[derive(Serialize)]
        struct ErrorResponse<'a> {
            error: ErrorDetail<'a>,
        }
        #[derive(Serialize)]
        struct ErrorDetail<'a> {
            message: &'a str,
            #[serde(rename = "type")]
            kind: &'a str,
        }
        json_response(
            status,
            &ErrorResponse {
                error: ErrorDetail {
                    message,
                    kind: code,
                },
            },
        )
    }
}

fn chat_response(model: &str, completion: crate::providers::Completion) -> Response<Full<Bytes>> {
    #[derive(Serialize)]
    struct ChatResponse<'a> {
        id: String,
        object: &'static str,
        created: u64,
        model: &'a str,
        choices: [Choice<'a>; 1],
        usage: Usage,
    }
    #[derive(Serialize)]
    struct Choice<'a> {
        index: u8,
        message: AssistantMessage<'a>,
        finish_reason: &'static str,
    }
    #[derive(Serialize)]
    struct AssistantMessage<'a> {
        role: &'static str,
        content: &'a str,
    }
    #[derive(Serialize)]
    struct Usage {
        prompt_tokens: u32,
        completion_tokens: u32,
        total_tokens: u32,
    }
    let input_tokens = completion.input_tokens.unwrap_or(0);
    let output_tokens = completion.output_tokens.unwrap_or(0);
    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_secs());
    json_response(
        StatusCode::OK,
        &ChatResponse {
            id: format!("chatcmpl-neoth-{}", Uuid::new_v4()),
            object: "chat.completion",
            created,
            model,
            choices: [Choice {
                index: 0,
                message: AssistantMessage {
                    role: "assistant",
                    content: &completion.text,
                },
                finish_reason: "stop",
            }],
            usage: Usage {
                prompt_tokens: input_tokens,
                completion_tokens: output_tokens,
                total_tokens: input_tokens.saturating_add(output_tokens),
            },
        },
    )
}

fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| {
        br#"{"error":{"message":"response encoding failed","type":"internal_error"}}"#.to_vec()
    });
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(hyper::header::CACHE_CONTROL, "no-store")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::{Mutex, atomic::AtomicUsize};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Default)]
    struct RecordingProvider {
        requests: Mutex<Vec<Request>>,
    }

    struct BlockingProvider {
        started: tokio::sync::Notify,
        release: tokio::sync::Notify,
        completed: AtomicUsize,
    }

    #[async_trait]
    impl crate::providers::Provider for RecordingProvider {
        fn name(&self) -> &'static str {
            "local_ollama"
        }

        // `valid_label_body` deliberately carries Graphify's pinned
        // `temperature: 0` and a grammar-derived output cap. Model this test
        // leaf as sampling/output-capable so the authorized-provider boundary
        // validates the same accepted request shape that a real
        // Ollama-compatible backend does.
        fn request_controls(&self) -> crate::providers::ProviderRequestControls {
            crate::providers::ProviderRequestControls::SAMPLING.with_output_token_limit()
        }

        fn output_token_ceiling(&self, request: &Request) -> Option<u32> {
            request.max_output_tokens
        }

        fn default_model(&self) -> Option<&str> {
            Some("graphify-label-test")
        }
        async fn complete(&self, request: Request) -> Result<crate::providers::Completion> {
            let labels = match parse_label_prompt(&request.prompt) {
                Ok(labels) => labels,
                Err(_) => panic!("test broker only dispatches grammar-bound label prompts"),
            }
            .into_iter()
            .map(|id| (id, serde_json::Value::String("Graph Cluster".into())))
            .collect::<serde_json::Map<_, _>>();
            self.requests.lock().unwrap().push(request);
            Ok(crate::providers::Completion {
                text: serde_json::to_string(&labels).unwrap(),
                input_tokens: Some(3),
                output_tokens: Some(1),
                ..Default::default()
            })
        }
    }

    #[async_trait]
    impl crate::providers::Provider for BlockingProvider {
        fn name(&self) -> &'static str {
            "local_ollama"
        }

        fn request_controls(&self) -> crate::providers::ProviderRequestControls {
            crate::providers::ProviderRequestControls::SAMPLING.with_output_token_limit()
        }

        fn output_token_ceiling(&self, request: &Request) -> Option<u32> {
            request.max_output_tokens
        }

        fn default_model(&self) -> Option<&str> {
            Some("graphify-label-test")
        }

        async fn complete(&self, _request: Request) -> Result<crate::providers::Completion> {
            self.started.notify_waiters();
            self.release.notified().await;
            self.completed.fetch_add(1, Ordering::SeqCst);
            Ok(crate::providers::Completion {
                text: r#"{"7":"Graph Cluster"}"#.into(),
                ..Default::default()
            })
        }
    }

    fn planned_batch(id: &str) -> BTreeSet<String> {
        BTreeSet::from([id.to_owned()])
    }

    async fn broker(max_message_bytes: usize) -> (GraphifyLabelBroker, Arc<RecordingProvider>) {
        let raw = Arc::new(RecordingProvider::default());
        let provider = Arc::new(AuthorizedProvider::from_arc(
            raw.clone(),
            crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
                crate::permissions::AutonomyLevel::Full,
            ),
            Some("graphify-label-test".into()),
            "test.graphify_label_broker",
        ));
        let mut config =
            GraphifyLabelBrokerConfig::for_planned_batches(vec![planned_batch("7")]).unwrap();
        config.max_message_bytes = max_message_bytes;
        (
            GraphifyLabelBroker::bind(provider, "graphify-label-test", config)
                .await
                .unwrap(),
            raw,
        )
    }

    async fn broker_with_config(
        config: GraphifyLabelBrokerConfig,
    ) -> (GraphifyLabelBroker, Arc<RecordingProvider>) {
        let raw = Arc::new(RecordingProvider::default());
        let provider = Arc::new(AuthorizedProvider::from_arc(
            raw.clone(),
            crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
                crate::permissions::AutonomyLevel::Full,
            ),
            Some("graphify-label-test".into()),
            "test.graphify_label_broker",
        ));
        (
            GraphifyLabelBroker::bind(provider, "graphify-label-test", config)
                .await
                .unwrap(),
            raw,
        )
    }

    async fn blocking_broker(
        raw: Arc<BlockingProvider>,
        config: GraphifyLabelBrokerConfig,
    ) -> GraphifyLabelBroker {
        let provider = Arc::new(AuthorizedProvider::from_arc(
            raw,
            crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
                crate::permissions::AutonomyLevel::Full,
            ),
            Some("graphify-label-test".into()),
            "test.graphify_label_broker.blocking",
        ));
        GraphifyLabelBroker::bind(provider, "graphify-label-test", config)
            .await
            .unwrap()
    }

    async fn raw_post(addr: SocketAddr, request: String) -> (tokio::net::TcpStream, String) {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        (stream, response)
    }

    async fn post(addr: SocketAddr, path: &str, authorization: &str, json: &str) -> String {
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: {authorization}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
            json.len()
        );
        raw_post(addr, request).await.1
    }

    fn endpoint_path(connection: &GraphifyLabelBrokerConnection) -> String {
        let marker = "/graphify-";
        let (_, path) = connection.ollama_base_url.split_once(marker).unwrap();
        format!("{marker}{path}/chat/completions")
    }

    fn valid_label_body_for(id: &str) -> String {
        serde_json::json!({
            "model": "graphify-label-test",
            "messages": [{
                "role": "user",
                "content": format!("{LABEL_PROMPT_PREFIX}Community {id}: node")
            }],
            "stream": false,
            "temperature": 0,
            "max_completion_tokens": 88,
            "options": {"num_ctx": 8192},
            "keep_alive": "30m"
        })
        .to_string()
    }

    fn valid_label_body() -> String {
        valid_label_body_for("7")
    }

    #[tokio::test]
    async fn capability_model_and_credentialless_connection_are_strict() {
        let (broker, raw) = broker(DEFAULT_MAX_MESSAGE_BYTES).await;
        let connection = broker.connection().clone();
        assert_eq!(connection.backend, "ollama");
        assert_eq!(
            connection.authorization_mode,
            GraphifyLabelBrokerAuthorizationMode::ExactPlannedBatches
        );
        assert!(
            !format!("{connection:?}")
                .to_ascii_lowercase()
                .contains("key")
        );
        let path = endpoint_path(&connection);
        let address = broker.listen_addr();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(broker.serve(async move {
            let _ = stop_rx.await;
        }));
        let body = valid_label_body();
        let response = post(address, &path, PLACEHOLDER_BEARER, &body).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        {
            let requests = raw.requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].model.as_deref(), Some("graphify-label-test"));
            assert_eq!(requests[0].system.as_deref(), None);
            assert_eq!(requests[0].max_output_tokens, Some(88));
            assert_eq!(
                requests[0].prompt,
                format!("{LABEL_PROMPT_PREFIX}Community 7: node")
            );
        }
        assert!(
            post(
                address,
                "/wrong/v1/chat/completions",
                PLACEHOLDER_BEARER,
                &valid_label_body()
            )
            .await
            .starts_with("HTTP/1.1 404")
        );
        assert!(
            post(
                address,
                &path,
                "Bearer real-provider-secret",
                &valid_label_body()
            )
            .await
            .starts_with("HTTP/1.1 401")
        );
        stop_tx.send(()).unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn rejects_model_controls_and_limits_before_provider() {
        let (broker, raw) = broker(4).await;
        let connection = broker.connection().clone();
        let path = endpoint_path(&connection);
        let address = broker.listen_addr();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(broker.serve(async move {
            let _ = stop_rx.await;
        }));
        for request in [
            r#"{"model":"other","messages":[{"role":"user","content":"x"}]}"#,
            r#"{"model":"graphify-label-test","messages":[{"role":"user","content":"x"}],"stream":true}"#,
            r#"{"model":"graphify-label-test","messages":[{"role":"user","content":"x"}],"tools":[]}"#,
            r#"{"model":"graphify-label-test","messages":[{"role":"user","content":"too long"}]}"#,
        ] {
            assert!(
                post(address, &path, PLACEHOLDER_BEARER, request)
                    .await
                    .starts_with("HTTP/1.1 400")
            );
        }
        assert!(raw.requests.lock().unwrap().is_empty());
        stop_tx.send(()).unwrap();
        task.await.unwrap().unwrap();
    }

    #[test]
    fn label_prompt_and_completion_are_bound_to_exact_community_ids() {
        let prompt =
            format!("{LABEL_PROMPT_PREFIX}Community 7: Parser, AST\nCommunity 12: WAL, Consent");
        let requested = match parse_label_prompt(&prompt) {
            Ok(requested) => requested,
            Err(_) => panic!("valid label prompt must parse"),
        };
        assert_eq!(requested, BTreeSet::from(["12".into(), "7".into()]));
        assert!(
            validate_label_completion(
                r#"{"7":"Parser Analysis","12":"Consent Audit"}"#,
                &requested,
            )
            .is_ok()
        );
        assert!(
            parse_label_prompt(&format!(
                "{LABEL_PROMPT_PREFIX}Community 7: Parser\ninjected text"
            ))
            .is_err()
        );
        assert!(validate_label_completion(r#"{"7":"One Word"}"#, &requested).is_err());
        assert!(
            validate_label_completion(
                r#"{"7":"Too many words in this label now","12":"Consent Audit"}"#,
                &requested,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn dropping_connection_waiter_does_not_cancel_admitted_provider_call() {
        let raw = Arc::new(BlockingProvider {
            started: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
            completed: AtomicUsize::new(0),
        });
        let provider = Arc::new(AuthorizedProvider::from_arc(
            raw.clone(),
            crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
                crate::permissions::AutonomyLevel::Full,
            ),
            Some("graphify-label-test".into()),
            "test.graphify_label_broker.detach",
        ));
        let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let provider_tasks = ProviderTaskTracker::new();
        let started = raw.started.notified();
        let waiter = tokio::spawn(dispatch_provider(
            Arc::clone(&provider_tasks),
            provider,
            Request {
                model: Some("graphify-label-test".into()),
                prompt: format!("{LABEL_PROMPT_PREFIX}Community 7: node"),
                max_output_tokens: Some(88),
                ..Request::default()
            },
            permit,
            Duration::from_secs(1),
        ));
        started.await;
        waiter.abort();
        let _ = waiter.await;
        raw.release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), async {
            while raw.completed.load(Ordering::SeqCst) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached provider task reaches its terminal completion");
        let mut tasks = provider_tasks.stop_accepting_and_take();
        drain_provider_tasks(&mut tasks, &provider_tasks)
            .await
            .expect("tracker reaches terminal quiescence");
    }

    #[tokio::test]
    async fn duplicate_or_unplanned_batches_never_reach_the_provider() {
        let (broker, raw) = broker(DEFAULT_MAX_MESSAGE_BYTES).await;
        let path = endpoint_path(broker.connection());
        let address = broker.listen_addr();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(broker.serve(async move {
            let _ = stop_rx.await;
        }));
        let body = valid_label_body();
        assert!(
            post(address, &path, PLACEHOLDER_BEARER, &body)
                .await
                .starts_with("HTTP/1.1 200")
        );
        assert!(
            post(address, &path, PLACEHOLDER_BEARER, &body)
                .await
                .starts_with("HTTP/1.1 409")
        );
        assert!(
            post(
                address,
                &path,
                PLACEHOLDER_BEARER,
                &valid_label_body_for("8"),
            )
            .await
            .starts_with("HTTP/1.1 409")
        );
        assert_eq!(raw.requests.lock().unwrap().len(), 1);
        stop_tx.send(()).unwrap();
        task.await.unwrap().unwrap();
        assert!(tokio::net::TcpStream::connect(address).await.is_err());
    }

    #[tokio::test]
    async fn budgeted_mode_is_serial_one_time_and_explicitly_not_exact() {
        let config = GraphifyLabelBrokerConfig::for_budgeted_batches(3, 2).unwrap();
        assert_eq!(
            config.authorization_mode(),
            GraphifyLabelBrokerAuthorizationMode::BudgetedBatches
        );
        assert_eq!(config.max_concurrent_requests, 1);
        let (broker, raw) = broker_with_config(config).await;
        assert_eq!(
            broker.connection().authorization_mode,
            GraphifyLabelBrokerAuthorizationMode::BudgetedBatches
        );
        let path = endpoint_path(broker.connection());
        let address = broker.listen_addr();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(broker.serve(async move {
            let _ = stop_rx.await;
        }));

        assert!(
            post(
                address,
                &path,
                PLACEHOLDER_BEARER,
                &valid_label_body_for("7"),
            )
            .await
            .starts_with("HTTP/1.1 200")
        );
        assert!(
            post(
                address,
                &path,
                PLACEHOLDER_BEARER,
                &valid_label_body_for("8"),
            )
            .await
            .starts_with("HTTP/1.1 200")
        );
        assert!(
            post(
                address,
                &path,
                PLACEHOLDER_BEARER,
                &valid_label_body_for("7"),
            )
            .await
            .starts_with("HTTP/1.1 409")
        );
        assert!(
            post(
                address,
                &path,
                PLACEHOLDER_BEARER,
                &valid_label_body_for("9"),
            )
            .await
            .starts_with("HTTP/1.1 429")
        );
        assert_eq!(raw.requests.lock().unwrap().len(), 2);
        stop_tx.send(()).unwrap();
        task.await.unwrap().unwrap();
    }

    #[test]
    fn budgeted_mode_has_small_hard_limits_and_no_in_request_id_replay() {
        assert!(GraphifyLabelBrokerConfig::for_budgeted_batches(0, 1).is_err());
        assert!(GraphifyLabelBrokerConfig::for_budgeted_batches(17, 1).is_err());
        assert!(GraphifyLabelBrokerConfig::for_budgeted_batches(1, 1601).is_err());

        let mut config = GraphifyLabelBrokerConfig::for_budgeted_batches(1, 1).unwrap();
        config.max_concurrent_requests = 2;
        assert!(config.validate().is_err());
        assert!(
            parse_label_prompt(&format!(
                "{LABEL_PROMPT_PREFIX}Community 7: node\nCommunity 7: replay"
            ))
            .is_err()
        );
    }

    #[tokio::test]
    async fn stalled_connections_are_bounded_and_apply_accept_backpressure() {
        let mut config =
            GraphifyLabelBrokerConfig::for_planned_batches(vec![planned_batch("7")]).unwrap();
        config.max_connections = 1;
        config.header_timeout = Duration::from_millis(25);
        config.connection_timeout = Duration::from_millis(250);
        config.request_timeout = Duration::from_millis(200);
        let (broker, _raw) = broker_with_config(config).await;
        let path = endpoint_path(broker.connection());
        let address = broker.listen_addr();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(broker.serve(async move {
            let _ = stop_rx.await;
        }));

        let stalled = tokio::net::TcpStream::connect(address).await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        let response = tokio::time::timeout(
            Duration::from_secs(1),
            post(address, &path, PLACEHOLDER_BEARER, &valid_label_body()),
        )
        .await
        .expect("second connection is accepted after the bounded stalled header");
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        drop(stalled);
        stop_tx.send(()).unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn provider_response_timeout_keeps_authorized_completion_broker_owned() {
        let raw = Arc::new(BlockingProvider {
            started: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
            completed: AtomicUsize::new(0),
        });
        let mut config =
            GraphifyLabelBrokerConfig::for_planned_batches(vec![planned_batch("7")]).unwrap();
        config.request_timeout = Duration::from_millis(25);
        config.connection_timeout = Duration::from_secs(1);
        let broker = blocking_broker(raw.clone(), config).await;
        let path = endpoint_path(broker.connection());
        let address = broker.listen_addr();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let mut task = tokio::spawn(broker.serve(async move {
            let _ = stop_rx.await;
        }));

        let started = raw.started.notified();
        let body = valid_label_body();
        let caller =
            tokio::spawn(async move { post(address, &path, PLACEHOLDER_BEARER, &body).await });
        started.await;
        let response = tokio::time::timeout(Duration::from_secs(1), caller)
            .await
            .expect("HTTP caller receives its bounded provider timeout")
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 504"), "{response}");
        assert_eq!(raw.completed.load(Ordering::SeqCst), 0);

        // The HTTP timeout is bounded, but `serve` cannot claim broker/WAL
        // quiescence while the admitted provider call is still blocked.
        stop_tx.send(()).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut task)
                .await
                .is_err(),
            "broker shutdown must retain ownership of the admitted provider call"
        );
        raw.release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), async {
            while raw.completed.load(Ordering::SeqCst) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("tracked provider call reaches its terminal completion");
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn shutdown_waits_for_a_hung_provider_call_to_reach_a_terminal_state() {
        let raw = Arc::new(BlockingProvider {
            started: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
            completed: AtomicUsize::new(0),
        });
        let mut config =
            GraphifyLabelBrokerConfig::for_planned_batches(vec![planned_batch("7")]).unwrap();
        config.request_timeout = Duration::from_secs(1);
        config.connection_timeout = Duration::from_secs(2);
        config.shutdown_drain_timeout = Duration::from_millis(25);
        let broker = blocking_broker(raw.clone(), config).await;
        let path = endpoint_path(broker.connection());
        let address = broker.listen_addr();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let mut task = tokio::spawn(broker.serve(async move {
            let _ = stop_rx.await;
        }));

        let started = raw.started.notified();
        let body = valid_label_body();
        let caller =
            tokio::spawn(async move { post(address, &path, PLACEHOLDER_BEARER, &body).await });
        started.await;
        stop_tx.send(()).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut task)
                .await
                .is_err(),
            "broker must not report shutdown before admitted provider/WAL work terminates"
        );
        raw.release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), &mut task)
            .await
            .expect("shutdown completes after the provider is released")
            .unwrap()
            .unwrap();
        caller.abort();
        tokio::time::timeout(Duration::from_secs(1), async {
            while raw.completed.load(Ordering::SeqCst) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the admitted provider call reaches its terminal completion before shutdown");
    }

    #[tokio::test]
    async fn panicked_connection_task_is_a_terminal_broker_error() {
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async {
            panic!("test connection task panic");
        });
        let result = tasks.join_next().await.expect("one task result");
        let error = observe_connection_task(result).expect_err("panic must be surfaced");
        assert!(error.to_string().contains("connection task failed"));
    }
}
