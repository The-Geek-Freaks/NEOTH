//! Generation-bound owner for the complete live cluster runtime.
//!
//! Carrier, outbound gossip, mDNS, delegated-task execution and the iroh
//! foreign-event writer are one lifecycle unit. A generation switch always
//! stops and awaits that unit before starting its replacement. This prevents
//! duplicate gossip/request consumers. A failed candidate remains fully
//! stopped and retries only that desired generation; revoked auth/privacy
//! generations are never restored.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use tracing::{info, warn};

use crate::cluster::discovery::ClusterKey;
use crate::config::credentials::Credentials;
use crate::config::{
    ClusterAnnouncePolicy, ClusterConfig, ClusterMdnsConfig, ClusterTransport, FreedomConfig,
};
use crate::providers::Provider;
use crate::wal::writer::WalWriterHandle;

const CREDENTIAL_POLL_INTERVAL: Duration = Duration::from_secs(2);
const FAILED_SWITCH_RETRY_INTERVAL: Duration = Duration::from_secs(30);
const RUNTIME_START_TIMEOUT: Duration = Duration::from_secs(45);
const RUNTIME_STOP_TIMEOUT: Duration = Duration::from_secs(20);
const SUPERVISOR_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(25);

#[derive(Clone, Debug, PartialEq, Eq)]
struct RuntimeIdentitySpec {
    name: String,
    key: ClusterKey,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct NetworkFingerprint {
    ssid: Option<String>,
    primary_ip: Option<IpAddr>,
}

impl NetworkFingerprint {
    fn observe() -> Self {
        Self {
            ssid: crate::cluster::policy::current_ssid(),
            primary_ip: crate::cluster::mdns::primary_local_ip(),
        }
    }
}

/// Only fields that own live cluster resources belong here. Gossip policy is
/// deliberately absent: both carriers resolve it from ReloadController at each
/// operation and therefore do not need a restart for policy-only generations.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RuntimeSpec {
    enabled: bool,
    identity: Option<RuntimeIdentitySpec>,
    transport: ClusterTransport,
    peers: Vec<String>,
    mdns: ClusterMdnsConfig,
    announce_policy: ClusterAnnouncePolicy,
    listen_port: u16,
    network: NetworkFingerprint,
}

impl RuntimeSpec {
    fn from_inputs(
        config: &FreedomConfig,
        credentials: &Credentials,
        network: NetworkFingerprint,
    ) -> Self {
        let identity = crate::cluster::identity::resolve_cluster_identity(config, credentials).map(
            |identity| RuntimeIdentitySpec {
                name: identity.name,
                key: identity.key,
            },
        );
        let (peers, mdns, announce_policy, listen_port, network) = match config.cluster.transport {
            ClusterTransport::Peeroxide => (
                Vec::new(),
                config.cluster.mdns,
                config.cluster.policy.clone(),
                config.cluster.listen_port,
                network,
            ),
            ClusterTransport::Iroh => {
                let mut peers: Vec<String> = config
                    .cluster
                    .peers
                    .iter()
                    .map(|peer| peer.trim().to_string())
                    .collect();
                peers.sort_unstable();
                peers.dedup();
                (
                    peers,
                    ClusterMdnsConfig { enabled: false },
                    ClusterAnnouncePolicy::default(),
                    0,
                    NetworkFingerprint::default(),
                )
            }
        };
        Self {
            enabled: config.cluster.enabled,
            identity,
            transport: config.cluster.transport,
            peers,
            mdns,
            announce_policy,
            listen_port,
            network,
        }
    }

    fn active_identity(&self) -> Option<&RuntimeIdentitySpec> {
        self.enabled.then_some(())?;
        self.identity.as_ref()
    }

    fn mdns_expected(&self) -> bool {
        self.transport == ClusterTransport::Peeroxide
            && self.active_identity().is_some()
            && self.network.primary_ip.is_some()
            && matches!(
                crate::cluster::policy::gate_discover(
                    self.mdns.enabled,
                    &self.announce_policy,
                    self.network.ssid.as_deref(),
                ),
                crate::cluster::policy::DiscoverGate::Proceed
            )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ObservedInputs {
    runtime: RuntimeSpec,
    cluster: ClusterConfig,
}

impl ObservedInputs {
    fn new(config: &FreedomConfig, credentials: &Credentials, network: NetworkFingerprint) -> Self {
        Self {
            runtime: RuntimeSpec::from_inputs(config, credentials, network),
            cluster: config.cluster.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RuntimeHealth {
    carrier_active: bool,
    mdns_active: bool,
}

#[async_trait]
trait RuntimeUnit: Send {
    fn health(&self) -> RuntimeHealth;
    async fn shutdown(self) -> Result<()>;
}

#[async_trait]
trait RuntimeFactory: Send + Sync {
    type Runtime: RuntimeUnit;

    async fn start(&self, spec: &RuntimeSpec) -> Result<Self::Runtime>;
}

struct ActiveGeneration<R> {
    spec: RuntimeSpec,
    runtime: R,
}

enum ReconcileOutcome {
    Unchanged,
    Applied,
    /// The prior generation was proven stopped and the replacement did not
    /// start. Retrying this exact desired generation is safe.
    StartFailedClean {
        error: anyhow::Error,
    },
    /// Teardown (including cancellation of a partially-started candidate) was
    /// not proven. The process must never start another generation.
    TeardownUncertain {
        error: anyhow::Error,
    },
}

/// Generic stop/start state machine. Production supplies the real carrier
/// factory; tests supply counted runtimes and prove the ownership invariants.
struct SupervisorCore<F: RuntimeFactory> {
    factory: F,
    active: Option<ActiveGeneration<F::Runtime>>,
    teardown_uncertain: Option<String>,
}

impl<F: RuntimeFactory> SupervisorCore<F> {
    async fn start(factory: F, spec: RuntimeSpec) -> Result<Self> {
        let runtime = tokio::time::timeout(RUNTIME_START_TIMEOUT, factory.start(&spec))
            .await
            .context("initial cluster runtime generation start timed out")??;
        Ok(Self {
            factory,
            active: Some(ActiveGeneration { spec, runtime }),
            teardown_uncertain: None,
        })
    }

    fn active_status(&self) -> (bool, bool) {
        self.active
            .as_ref()
            .map(|active| {
                let health = active.runtime.health();
                (health.carrier_active, health.mdns_active)
            })
            .unwrap_or((false, false))
    }

    fn is_poisoned(&self) -> bool {
        self.teardown_uncertain.is_some()
    }

    fn active_is_degraded_for(&self, desired: &RuntimeSpec) -> bool {
        let Some(active) = self.active.as_ref() else {
            return desired.active_identity().is_some();
        };
        let health = active.runtime.health();
        desired.active_identity().is_some() != health.carrier_active
            || desired.mdns_expected() != health.mdns_active
    }

    fn mark_teardown_uncertain(&mut self, error: anyhow::Error) -> ReconcileOutcome {
        let detail = format!("{error:#}");
        self.teardown_uncertain = Some(detail.clone());
        ReconcileOutcome::TeardownUncertain {
            error: anyhow::anyhow!(detail),
        }
    }

    async fn stop_active(&mut self) -> Result<()> {
        let Some(active) = self.active.take() else {
            return Ok(());
        };
        match tokio::time::timeout(RUNTIME_STOP_TIMEOUT, active.runtime.shutdown()).await {
            Ok(result) => result.context("stop cluster runtime generation"),
            Err(_) => anyhow::bail!(
                "cluster runtime generation did not stop within {} seconds",
                RUNTIME_STOP_TIMEOUT.as_secs()
            ),
        }
    }

    /// Stop the active generation before recovering from an ACK/input failure.
    /// A candidate is not committed until its durable ACK succeeds, and a
    /// credential-read failure cannot safely retain the previously keyed unit.
    async fn stop_active_fail_closed(&mut self, cause: anyhow::Error) -> ReconcileOutcome {
        if let Some(error) = self.teardown_uncertain.as_ref() {
            return ReconcileOutcome::TeardownUncertain {
                error: anyhow::anyhow!(error.clone()),
            };
        }
        match self.stop_active().await {
            Ok(()) => ReconcileOutcome::StartFailedClean { error: cause },
            Err(stop_error) => self.mark_teardown_uncertain(anyhow::anyhow!(
                "uncommitted cluster runtime could not be stopped after {cause:#}: {stop_error:#}"
            )),
        }
    }

    async fn reconcile(&mut self, desired: RuntimeSpec) -> ReconcileOutcome {
        if let Some(error) = self.teardown_uncertain.as_ref() {
            return ReconcileOutcome::TeardownUncertain {
                error: anyhow::anyhow!(error.clone()),
            };
        }
        if self
            .active
            .as_ref()
            .is_some_and(|active| active.spec == desired)
            && !self.active_is_degraded_for(&desired)
        {
            return ReconcileOutcome::Unchanged;
        }

        if let Err(error) = self.stop_active().await {
            // A failed/expired stop consumed the old handle without proving
            // teardown. Poison this supervisor permanently: retrying could
            // overlap the old carrier or one of its request consumers.
            return self.mark_teardown_uncertain(
                error.context("stop previous cluster runtime generation"),
            );
        }

        match tokio::time::timeout(RUNTIME_START_TIMEOUT, self.factory.start(&desired)).await {
            Ok(Ok(runtime)) => {
                self.active = Some(ActiveGeneration {
                    spec: desired,
                    runtime,
                });
                ReconcileOutcome::Applied
            }
            // RuntimeFactory::start has a strict contract: an ordinary Err is
            // returned only after every partially-started resource was awaited.
            Ok(Err(error)) => {
                if crate::cluster::hyperswarm::start_error_has_uncertain_teardown(&error) {
                    self.mark_teardown_uncertain(error)
                } else {
                    ReconcileOutcome::StartFailedClean { error }
                }
            }
            // Cancelling a start future at its deadline cannot prove teardown
            // for arbitrary carrier internals. Never retry in this process.
            Err(_) => self.mark_teardown_uncertain(anyhow::anyhow!(
                "cluster runtime generation start timed out after {} seconds",
                RUNTIME_START_TIMEOUT.as_secs()
            )),
        }
    }

    async fn shutdown(&mut self) -> Result<()> {
        self.stop_active().await
    }
}

struct RuntimeDeps {
    home: PathBuf,
    segment_path: PathBuf,
    writer: WalWriterHandle,
    reload_controller: Arc<crate::config::reload::ReloadController>,
    shared_provider: Option<Arc<dyn Provider>>,
    ack_in_flight: Arc<std::sync::atomic::AtomicBool>,
    ack_permitted: Arc<std::sync::atomic::AtomicBool>,
}

struct ProductionFactory {
    deps: Arc<RuntimeDeps>,
}

#[async_trait]
impl RuntimeFactory for ProductionFactory {
    type Runtime = LiveClusterRuntime;

    async fn start(&self, spec: &RuntimeSpec) -> Result<Self::Runtime> {
        LiveClusterRuntime::start(spec, &self.deps).await
    }
}

struct LiveClusterRuntime {
    carrier: Option<CarrierRuntime>,
    mdns: Option<mdns_sd::ServiceDaemon>,
}

impl LiveClusterRuntime {
    async fn start(spec: &RuntimeSpec, deps: &RuntimeDeps) -> Result<Self> {
        let Some(identity) = spec.active_identity() else {
            return Ok(Self {
                carrier: None,
                mdns: None,
            });
        };

        let carrier = match spec.transport {
            ClusterTransport::Peeroxide => {
                CarrierRuntime::start_peeroxide(spec, identity, deps).await?
            }
            ClusterTransport::Iroh => {
                #[cfg(feature = "cluster-iroh")]
                {
                    CarrierRuntime::start_iroh(spec, identity, deps).await?
                }
                #[cfg(not(feature = "cluster-iroh"))]
                {
                    anyhow::bail!(
                        "cluster.transport is iroh, but this binary lacks the cluster-iroh feature"
                    );
                }
            }
        };

        // The fixed mDNS listen port describes the peeroxide listener. Iroh is
        // dial-by-endpoint-id and must not publish a misleading UDP endpoint.
        let mdns = if spec.transport == ClusterTransport::Peeroxide {
            spawn_mdns(spec, identity, &deps.home)
        } else {
            None
        };
        Ok(Self {
            carrier: Some(carrier),
            mdns,
        })
    }
}

#[async_trait]
impl RuntimeUnit for LiveClusterRuntime {
    fn health(&self) -> RuntimeHealth {
        RuntimeHealth {
            carrier_active: self
                .carrier
                .as_ref()
                .is_some_and(CarrierRuntime::is_healthy),
            mdns_active: self.mdns.as_ref().is_some_and(mdns_is_healthy),
        }
    }

    async fn shutdown(mut self) -> Result<()> {
        // Stop LAN advertisement before any slower carrier/session teardown.
        // A privacy-policy or network downgrade must become undiscoverable
        // first, even if a carrier worker later needs its full timeout.
        let mdns_result = match self.mdns.take() {
            Some(mdns) => shutdown_mdns(mdns).await,
            None => Ok(()),
        };
        let carrier_result = match self.carrier.take() {
            Some(carrier) => carrier.shutdown().await,
            None => Ok(()),
        };
        mdns_result.and(carrier_result)
    }
}

impl Drop for LiveClusterRuntime {
    fn drop(&mut self) {
        if let Some(mdns) = self.mdns.take() {
            let _ = mdns.shutdown();
        }
    }
}

enum CarrierRuntime {
    Peeroxide {
        gossip: Option<tokio::task::JoinHandle<()>>,
        swarm: Option<crate::cluster::hyperswarm::SwarmHandle>,
        executor: Option<crate::cluster::executor::ClusterExecutorHandle>,
    },
    #[cfg(feature = "cluster-iroh")]
    Iroh {
        gossip: Option<tokio::task::JoinHandle<()>>,
        transport: Option<Arc<crate::cluster::iroh_transport::IrohTransport>>,
        foreign_persist: Option<tokio::task::JoinHandle<()>>,
    },
}

impl CarrierRuntime {
    fn is_healthy(&self) -> bool {
        match self {
            Self::Peeroxide {
                gossip,
                swarm,
                executor,
            } => {
                gossip.as_ref().is_some_and(|task| !task.is_finished())
                    && swarm
                        .as_ref()
                        .is_some_and(crate::cluster::hyperswarm::SwarmHandle::is_healthy)
                    && executor
                        .as_ref()
                        .is_some_and(crate::cluster::executor::ClusterExecutorHandle::is_healthy)
            }
            #[cfg(feature = "cluster-iroh")]
            Self::Iroh {
                gossip,
                transport,
                foreign_persist,
            } => {
                gossip.as_ref().is_some_and(|task| !task.is_finished())
                    && transport
                        .as_ref()
                        .is_some_and(|transport| transport.is_healthy())
                    && foreign_persist
                        .as_ref()
                        .is_some_and(|task| !task.is_finished())
            }
        }
    }

    async fn start_peeroxide(
        _spec: &RuntimeSpec,
        identity: &RuntimeIdentitySpec,
        deps: &RuntimeDeps,
    ) -> Result<Self> {
        let registry = Arc::new(std::sync::Mutex::new(
            crate::cluster::PeerLoadRegistry::new(),
        ));
        let cluster_wal = Some(Arc::new(deps.writer.clone()));
        let peer_streams = Arc::new(crate::cluster::peer_streams::PeerStreamRegistry::new());
        let gossip_state = Arc::new(std::sync::Mutex::new(
            crate::cluster::wal_sync::GossipState::new(),
        ));
        let cluster_provider = deps.shared_provider.clone().map(|provider| {
            Arc::new(
                crate::providers::cost_authorization::AuthorizedProvider::from_arc(
                    provider,
                    crate::providers::cost_authorization::ProviderCallAuthorizer::fail_closed_reload(
                        Arc::clone(&deps.reload_controller),
                        Some(deps.writer.clone()),
                        deps.home.clone(),
                    ),
                    None,
                    "cluster.delegated_task",
                ),
            )
        });
        let executor = crate::cluster::executor::spawn_cluster_executor(
            cluster_provider,
            Arc::clone(&peer_streams),
            crate::cluster::executor::ClusterExecutionContext::new(
                Arc::clone(&deps.reload_controller),
                deps.home.clone(),
            ),
        );
        let dispatch_tx = executor.dispatch_sender();
        let swarm = match crate::cluster::hyperswarm::spawn_discovery_with_wal(
            &identity.name,
            Arc::new(identity.key.clone()),
            registry,
            cluster_wal,
            Arc::clone(&peer_streams),
            Arc::clone(&gossip_state),
            Arc::clone(&deps.reload_controller),
            deps.home.clone(),
            Some(dispatch_tx),
        )
        .await
        {
            Ok(swarm) => swarm,
            Err(error) => {
                executor.shutdown().await;
                return Err(error).context("start configured peeroxide cluster transport");
            }
        };
        let own_peer_id = crate::cluster::PeerPubkey::new(swarm.own_peer_id().to_string());
        let gossip = crate::cluster::wal_sync::spawn_gossip_tick(
            peer_streams,
            deps.segment_path.clone(),
            Arc::new(deps.writer.clone()),
            gossip_state,
            own_peer_id,
            Arc::clone(&deps.reload_controller),
        );
        info!(cluster = %identity.name, "cluster runtime: peeroxide generation active");
        Ok(Self::Peeroxide {
            gossip: Some(gossip),
            swarm: Some(swarm),
            executor: Some(executor),
        })
    }

    #[cfg(feature = "cluster-iroh")]
    async fn start_iroh(
        spec: &RuntimeSpec,
        identity: &RuntimeIdentitySpec,
        deps: &RuntimeDeps,
    ) -> Result<Self> {
        let cluster_wal = Some(Arc::new(deps.writer.clone()));
        let gossip_state = Arc::new(std::sync::Mutex::new(
            crate::cluster::wal_sync::GossipState::new(),
        ));
        let (foreign_persist_tx, foreign_persist) =
            crate::cluster::wal_sync::spawn_foreign_persist_writer(deps.home.join("views.db"));
        let endpoint_secret = load_or_create_iroh_endpoint_secret(&deps.home, &identity.key)
            .context("load persistent iroh endpoint identity")?;
        let transport = match crate::cluster::iroh_transport::IrohTransport::bind_with_secret(
            crate::cluster::iroh_transport::gossip_handler(
                Arc::clone(&gossip_state),
                Some(foreign_persist_tx),
                cluster_wal.clone(),
                Arc::clone(&deps.reload_controller),
            ),
            Arc::new(identity.key.clone()),
            cluster_wal.clone(),
            endpoint_secret,
        )
        .await
        {
            Ok(transport) => Arc::new(transport),
            Err(error) => {
                // The failed bind drops its handler and therefore the sender.
                // Await the writer so a retry cannot create a second consumer.
                let _ = foreign_persist.await;
                return Err(error).context("start configured iroh cluster transport");
            }
        };
        let mut seeded_peers = 0usize;
        for peer in &spec.peers {
            if transport.add_peer_id(peer) {
                seeded_peers += 1;
            }
        }
        let self_id = crate::cluster::PeerPubkey::new(transport.node_id());
        let gossip = crate::cluster::iroh_transport::spawn_gossip_broadcast(
            Arc::clone(&transport),
            deps.segment_path.clone(),
            gossip_state,
            self_id,
            cluster_wal,
            Arc::clone(&deps.reload_controller),
        );
        info!(
            node = %transport.node_id(),
            seeded_peers,
            delegated_task_executor = false,
            "cluster runtime: iroh gossip generation active; delegated task frames remain fail-closed until the task wire protocol has an authenticated iroh dispatcher"
        );
        Ok(Self::Iroh {
            gossip: Some(gossip),
            transport: Some(transport),
            foreign_persist: Some(foreign_persist),
        })
    }

    async fn shutdown(mut self) -> Result<()> {
        match &mut self {
            Self::Peeroxide {
                gossip,
                swarm,
                executor,
            } => {
                abort_and_await(gossip.take()).await;
                let swarm_result = match swarm.take() {
                    Some(swarm) => swarm.shutdown().await,
                    None => Ok(()),
                };
                if let Some(executor) = executor.take() {
                    executor.shutdown().await;
                }
                swarm_result
            }
            #[cfg(feature = "cluster-iroh")]
            Self::Iroh {
                gossip,
                transport,
                foreign_persist,
            } => {
                abort_and_await(gossip.take()).await;
                let transport_result = match transport.take() {
                    Some(transport) => {
                        let result = transport.shutdown().await;
                        drop(transport);
                        result
                    }
                    None => Ok(()),
                };
                if let Some(foreign_persist) = foreign_persist.take() {
                    let _ = foreign_persist.await;
                }
                transport_result
            }
        }
    }
}

impl Drop for CarrierRuntime {
    fn drop(&mut self) {
        match self {
            Self::Peeroxide { gossip, .. } => {
                if let Some(gossip) = gossip.take() {
                    gossip.abort();
                }
            }
            #[cfg(feature = "cluster-iroh")]
            Self::Iroh { gossip, .. } => {
                if let Some(gossip) = gossip.take() {
                    gossip.abort();
                }
            }
        }
    }
}

fn spawn_mdns(
    spec: &RuntimeSpec,
    identity: &RuntimeIdentitySpec,
    home: &std::path::Path,
) -> Option<mdns_sd::ServiceDaemon> {
    match crate::cluster::policy::gate_discover(
        spec.mdns.enabled,
        &spec.announce_policy,
        spec.network.ssid.as_deref(),
    ) {
        crate::cluster::policy::DiscoverGate::Proceed => {}
        crate::cluster::policy::DiscoverGate::SkipWith(reason) => {
            info!(?reason, "cluster runtime: mDNS generation gated off");
            return None;
        }
    }
    let Some(ip) = spec.network.primary_ip else {
        warn!("cluster runtime: mDNS skipped because no non-loopback local IP exists");
        return None;
    };
    let node_label = crate::cluster::mdns::node_label(home);
    let mdns_identity = crate::cluster::mdns::build_announce_identity(
        &identity.key,
        &node_label,
        ip,
        spec.listen_port,
    );
    match crate::cluster::mdns::spawn_announcer(&mdns_identity) {
        Ok(daemon) => {
            info!(label = %node_label, %ip, port = spec.listen_port, "cluster runtime: mDNS generation active");
            Some(daemon)
        }
        Err(error) => {
            warn!(%error, "cluster runtime: mDNS generation failed to start; carrier remains active");
            None
        }
    }
}

fn mdns_is_healthy(daemon: &mdns_sd::ServiceDaemon) -> bool {
    let Ok(status) = daemon.status() else {
        return false;
    };
    matches!(
        status.recv_timeout(Duration::from_millis(100)),
        Ok(mdns_sd::DaemonStatus::Running)
    )
}

#[cfg(feature = "cluster-iroh")]
const IROH_ENDPOINT_IDENTITY_NAME: &str = ".cluster-iroh-endpoint.json";
#[cfg(feature = "cluster-iroh")]
const IROH_ENDPOINT_IDENTITY_LOCK_NAME: &str = ".cluster-iroh-endpoint.lock";
#[cfg(feature = "cluster-iroh")]
const IROH_ENDPOINT_IDENTITY_VERSION: u8 = 1;
#[cfg(feature = "cluster-iroh")]
const IROH_ENDPOINT_BINDING_INFO: &[u8] = b"neoth-cluster-iroh-endpoint-binding-v1";

#[cfg(feature = "cluster-iroh")]
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct PersistentIrohEndpointIdentity {
    version: u8,
    generation_binding: [u8; 32],
    secret_key: [u8; 32],
}

#[cfg(feature = "cluster-iroh")]
impl Drop for PersistentIrohEndpointIdentity {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.generation_binding.zeroize();
        self.secret_key.zeroize();
    }
}

#[cfg(feature = "cluster-iroh")]
fn iroh_endpoint_generation_binding(
    home: &std::path::Path,
    cluster_key: &ClusterKey,
) -> Result<[u8; 32]> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    use zeroize::Zeroizing;

    let master_subkey = crate::wal::master_key::writer_segment_key_at(home)
        .ok_or_else(|| anyhow::anyhow!("create/load protected NEOTH master key"))?;
    let hkdf = Hkdf::<Sha256>::new(None, master_subkey.expose());
    let mut binding_key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(IROH_ENDPOINT_BINDING_INFO, &mut *binding_key)
        .map_err(|_| anyhow::anyhow!("derive iroh endpoint binding key"))?;
    let mut input = Zeroizing::new(Vec::with_capacity(
        IROH_ENDPOINT_BINDING_INFO.len() + cluster_key.0.len(),
    ));
    input.extend_from_slice(IROH_ENDPOINT_BINDING_INFO);
    input.extend_from_slice(&cluster_key.0);
    Ok(crate::util::hmac::sha256(&*binding_key, input.as_slice()))
}

#[cfg(feature = "cluster-iroh")]
fn load_or_create_iroh_endpoint_secret(
    home: &std::path::Path,
    cluster_key: &ClusterKey,
) -> Result<iroh::SecretKey> {
    use subtle::ConstantTimeEq as _;
    use zeroize::Zeroizing;

    let path = home.join(IROH_ENDPOINT_IDENTITY_NAME);
    let _lock = crate::util::locked_file::lock_file_blocking(
        &home.join(IROH_ENDPOINT_IDENTITY_LOCK_NAME),
        "iroh endpoint identity",
    )?;
    let generation_binding = Zeroizing::new(iroh_endpoint_generation_binding(home, cluster_key)?);
    match std::fs::read(&path) {
        Ok(body) => {
            let body = Zeroizing::new(body);
            let record: PersistentIrohEndpointIdentity = serde_json::from_slice(body.as_slice())
                .with_context(|| format!("parse iroh endpoint identity {}", path.display()))?;
            anyhow::ensure!(
                record.version == IROH_ENDPOINT_IDENTITY_VERSION,
                "unsupported iroh endpoint identity version {} at {}",
                record.version,
                path.display()
            );
            if bool::from(record.generation_binding.ct_eq(&*generation_binding)) {
                return Ok(iroh::SecretKey::from_bytes(&record.secret_key));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("read iroh endpoint identity {}", path.display()));
        }
    }

    let mut secret_key = Zeroizing::new([0_u8; 32]);
    getrandom::getrandom(&mut *secret_key).context("mint iroh endpoint secret from OS RNG")?;
    let record = PersistentIrohEndpointIdentity {
        version: IROH_ENDPOINT_IDENTITY_VERSION,
        generation_binding: *generation_binding,
        secret_key: *secret_key,
    };
    let body =
        Zeroizing::new(serde_json::to_vec(&record).context("serialize iroh endpoint identity")?);
    crate::util::atomic_write::atomic_write_private(&path, body.as_slice())
        .with_context(|| format!("persist private iroh endpoint identity {}", path.display()))?;
    Ok(iroh::SecretKey::from_bytes(&record.secret_key))
}

async fn shutdown_mdns(daemon: mdns_sd::ServiceDaemon) -> Result<()> {
    let completion = daemon.shutdown().context("request mDNS daemon shutdown")?;
    tokio::task::spawn_blocking(move || {
        completion
            .recv_timeout(Duration::from_secs(5))
            .context("wait for mDNS daemon shutdown")
    })
    .await
    .context("join mDNS shutdown wait")??;
    drop(daemon);
    Ok(())
}

async fn abort_and_await(handle: Option<tokio::task::JoinHandle<()>>) {
    if let Some(handle) = handle {
        handle.abort();
        let _ = handle.await;
    }
}

async fn load_runtime_inputs(
    home: &std::path::Path,
    reload_controller: &crate::config::reload::ReloadController,
) -> Result<(FreedomConfig, Credentials, ObservedInputs)> {
    let freedom_path = home.join("freedom.yaml");
    let (config, credentials, network) = tokio::task::spawn_blocking(move || {
        let pair = crate::config::load_runtime_config_pair_from_path(&freedom_path)?;
        let network = match pair.config.cluster.transport {
            ClusterTransport::Peeroxide => NetworkFingerprint::observe(),
            ClusterTransport::Iroh => NetworkFingerprint::default(),
        };
        Ok::<_, anyhow::Error>((pair.config, pair.credentials, network))
    })
    .await
    .context("join coherent cluster runtime-input load")??;

    // The dual-file reader prevents a config-A/credentials-B snapshot. Do not
    // start external carrier/announce side effects until that disk generation
    // is also the generation published to long-lived runtime consumers.
    let published = reload_controller.latest();
    anyhow::ensure!(
        published.cluster == config.cluster && published.secrets_backend == config.secrets_backend,
        "coherent cluster runtime inputs are newer than the published reload generation"
    );
    let observed = ObservedInputs::new(&config, &credentials, network);
    Ok((config, credentials, observed))
}

struct AckInFlightGuard {
    flag: Arc<std::sync::atomic::AtomicBool>,
}

impl AckInFlightGuard {
    fn acquire(flag: Arc<std::sync::atomic::AtomicBool>) -> Self {
        flag.store(true, std::sync::atomic::Ordering::Release);
        Self { flag }
    }
}

impl Drop for AckInFlightGuard {
    fn drop(&mut self) {
        self.flag.store(false, std::sync::atomic::Ordering::Release);
    }
}

async fn acknowledge_runtime(
    deps: &RuntimeDeps,
    config: &FreedomConfig,
    credentials: &Credentials,
    status: (bool, bool),
) -> Result<crate::cli::cluster::ClusterRuntimeAckOutcome> {
    anyhow::ensure!(
        deps.ack_permitted
            .load(std::sync::atomic::Ordering::Acquire),
        "cluster runtime acknowledgement cancelled by supervisor shutdown"
    );
    let home = deps.home.clone();
    let config = config.clone();
    let credentials = credentials.clone();
    let guard = AckInFlightGuard::acquire(Arc::clone(&deps.ack_in_flight));
    let ack_permitted = Arc::clone(&deps.ack_permitted);
    tokio::task::spawn_blocking(move || {
        let _guard = guard;
        anyhow::ensure!(
            ack_permitted.load(std::sync::atomic::Ordering::Acquire),
            "cluster runtime acknowledgement cancelled before marker commit"
        );
        let result = crate::cli::cluster::acknowledge_cluster_runtime_at(
            &home,
            &config,
            &credentials,
            status.0,
            status.1,
        )?;
        if !ack_permitted.load(std::sync::atomic::Ordering::Acquire) {
            // `spawn_blocking` cannot interrupt a kernel filesystem operation.
            // If shutdown raced the commit, revoke the just-written evidence
            // in this same non-detachable worker before it may return.
            let revoke = crate::cli::cluster::invalidate_cluster_runtime_at(
                &home,
                &config,
                &credentials,
            );
            return match revoke {
                Ok(_) => anyhow::bail!(
                    "cluster runtime acknowledgement completed after cancellation and was revoked"
                ),
                Err(error) => Err(error).context(
                    "cluster runtime acknowledgement completed after cancellation and could not be revoked",
                ),
            };
        }
        Ok(result)
    })
    .await
    .context("join cluster runtime acknowledgement")?
}

async fn invalidate_runtime(
    deps: &RuntimeDeps,
    config: &FreedomConfig,
    credentials: &Credentials,
) -> Result<crate::cli::cluster::ClusterRuntimeAckOutcome> {
    let home = deps.home.clone();
    let config = config.clone();
    let credentials = credentials.clone();
    let guard = AckInFlightGuard::acquire(Arc::clone(&deps.ack_in_flight));
    tokio::task::spawn_blocking(move || {
        let _guard = guard;
        crate::cli::cluster::invalidate_cluster_runtime_at(&home, &config, &credentials)
    })
    .await
    .context("join cluster runtime invalidation")?
}

/// Owns the supervisor task and provides ordered daemon teardown. Dropping is
/// a crash-path fallback: it signals shutdown and aborts the task, whose owned
/// runtime guards then abort their consumers and release carrier resources.
pub(crate) struct ClusterRuntimeSupervisorHandle {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
    ack_in_flight: Arc<std::sync::atomic::AtomicBool>,
    ack_permitted: Arc<std::sync::atomic::AtomicBool>,
}

impl ClusterRuntimeSupervisorHandle {
    pub async fn shutdown(mut self) {
        self.ack_permitted
            .store(false, std::sync::atomic::Ordering::Release);
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(mut task) = self.task.take() {
            match tokio::time::timeout(SUPERVISOR_SHUTDOWN_TIMEOUT, &mut task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) if !error.is_cancelled() => {
                    warn!(%error, "cluster runtime supervisor join failed");
                }
                Ok(Err(_)) => {}
                Err(_) => {
                    if self
                        .ack_in_flight
                        .load(std::sync::atomic::Ordering::Acquire)
                    {
                        warn!(
                            "cluster runtime supervisor shutdown timed out during a non-detachable filesystem marker operation; cancellation is latched and any completed acknowledgement will be revoked"
                        );
                    }
                    // Tokio cannot cancel an already-running spawn_blocking OS
                    // call. Bound the async owner anyway; the cancellation
                    // latch is checked before and after ACK commit. A kernel
                    // filesystem call that never returns remains an OS-level
                    // process-exit boundary, not a safe in-process retry.
                    task.abort();
                    let _ = task.await;
                    warn!("cluster runtime supervisor exceeded shutdown deadline and was aborted");
                }
            }
        }
    }
}

impl Drop for ClusterRuntimeSupervisorHandle {
    fn drop(&mut self) {
        self.ack_permitted
            .store(false, std::sync::atomic::Ordering::Release);
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Start the initial generation, then reconcile freedom.yaml generations and
/// credential-key rotations through one serialized owner.
pub(crate) async fn spawn_runtime_supervisor(
    home: PathBuf,
    segment_path: PathBuf,
    writer: WalWriterHandle,
    reload_controller: Arc<crate::config::reload::ReloadController>,
    shared_provider: Option<Arc<dyn Provider>>,
) -> Result<ClusterRuntimeSupervisorHandle> {
    let mut generation = reload_controller.subscribe_generation();
    let (mut initial_config, mut initial_credentials, mut initial_observed) =
        load_runtime_inputs(&home, &reload_controller)
            .await
            .context("load initial coherent cluster runtime inputs")?;
    let ack_in_flight = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ack_permitted = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let deps = Arc::new(RuntimeDeps {
        home,
        segment_path,
        writer,
        reload_controller,
        shared_provider,
        ack_in_flight: Arc::clone(&ack_in_flight),
        ack_permitted: Arc::clone(&ack_permitted),
    });
    let factory = ProductionFactory {
        deps: Arc::clone(&deps),
    };
    let mut core = SupervisorCore::start(factory, initial_observed.runtime.clone())
        .await
        .context("start initial cluster runtime generation")?;
    loop {
        match acknowledge_runtime(
            &deps,
            &initial_config,
            &initial_credentials,
            core.active_status(),
        )
        .await
        {
            Ok(crate::cli::cluster::ClusterRuntimeAckOutcome::Committed) => break,
            Ok(crate::cli::cluster::ClusterRuntimeAckOutcome::Superseded) => {
                if let Err(error) =
                    invalidate_runtime(&deps, &initial_config, &initial_credentials).await
                {
                    return match core
                        .stop_active_fail_closed(
                            error.context(
                                "invalidate superseded initial cluster runtime generation",
                            ),
                        )
                        .await
                    {
                        ReconcileOutcome::StartFailedClean { error }
                        | ReconcileOutcome::TeardownUncertain { error } => Err(error),
                        ReconcileOutcome::Unchanged | ReconcileOutcome::Applied => unreachable!(),
                    };
                }
                match core
                    .stop_active_fail_closed(anyhow::anyhow!(
                        "initial cluster runtime acknowledgement was superseded"
                    ))
                    .await
                {
                    ReconcileOutcome::StartFailedClean { .. } => {}
                    ReconcileOutcome::TeardownUncertain { error } => return Err(error),
                    ReconcileOutcome::Unchanged | ReconcileOutcome::Applied => unreachable!(),
                }

                // Coalesce immediately when the reload controller already has
                // the newer generation. If the disk marker advanced just
                // before the controller, give its bounded poll one chance.
                tokio::task::yield_now().await;
                let (mut next_config, mut next_credentials, mut next_observed) =
                    load_runtime_inputs(&deps.home, &deps.reload_controller)
                        .await
                        .context("load superseding coherent cluster runtime inputs")?;
                if next_observed == initial_observed {
                    let _ =
                        tokio::time::timeout(CREDENTIAL_POLL_INTERVAL, generation.changed()).await;
                    (next_config, next_credentials, next_observed) =
                        load_runtime_inputs(&deps.home, &deps.reload_controller)
                            .await
                            .context("reload superseding coherent cluster runtime inputs")?;
                }
                anyhow::ensure!(
                    next_observed != initial_observed,
                    "cluster runtime acknowledgement was superseded, but no newer runtime inputs were published"
                );
                initial_config = next_config;
                initial_credentials = next_credentials;
                initial_observed = next_observed.clone();
                match core.reconcile(next_observed.runtime).await {
                    ReconcileOutcome::Applied | ReconcileOutcome::Unchanged => {}
                    ReconcileOutcome::StartFailedClean { error }
                    | ReconcileOutcome::TeardownUncertain { error } => return Err(error),
                }
            }
            Err(error) => {
                let invalidation_error =
                    invalidate_runtime(&deps, &initial_config, &initial_credentials)
                        .await
                        .err();
                let cause = match invalidation_error {
                    Some(invalidation_error) => anyhow::anyhow!(
                        "initial cluster runtime ACK failed ({error:#}); marker invalidation also failed: {invalidation_error:#}"
                    ),
                    None => error.context("acknowledge initial cluster runtime generation"),
                };
                return match core.stop_active_fail_closed(cause).await {
                    ReconcileOutcome::StartFailedClean { error }
                    | ReconcileOutcome::TeardownUncertain { error } => Err(error),
                    ReconcileOutcome::Unchanged | ReconcileOutcome::Applied => unreachable!(),
                };
            }
        }
    }

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let mut observed = initial_observed;
        let mut credential_tick = tokio::time::interval(CREDENTIAL_POLL_INTERVAL);
        credential_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut retry_after: Option<tokio::time::Instant> = None;
        let mut reconcile_immediately = false;
        let mut last_superseded: Option<ObservedInputs> = None;
        let mut stopped_for_credential_error = false;
        let mut last_config = initial_config;
        let mut last_credentials = initial_credentials;

        loop {
            let forced_reconcile = std::mem::take(&mut reconcile_immediately);
            if forced_reconcile {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => break,
                    _ = tokio::task::yield_now() => {}
                }
            } else {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => break,
                    changed = generation.changed() => {
                        if changed.is_err() {
                            break;
                        }
                    }
                    _ = credential_tick.tick() => {}
                }
            }

            let (config, credentials, desired) = match load_runtime_inputs(
                &deps.home,
                &deps.reload_controller,
            )
            .await
            {
                Ok(inputs) => inputs,
                Err(error) => {
                    let invalidation_error =
                        invalidate_runtime(&deps, &last_config, &last_credentials)
                            .await
                            .err();
                    if !stopped_for_credential_error {
                        let marker_invalidation_failed = invalidation_error.is_some();
                        let cause = match invalidation_error {
                            Some(invalidation_error) => anyhow::anyhow!(
                                "cluster runtime input reload failed ({error:#}); marker invalidation also failed: {invalidation_error:#}"
                            ),
                            None => error.context("reload effective cluster credentials"),
                        };
                        match core.stop_active_fail_closed(cause).await {
                            ReconcileOutcome::StartFailedClean { error } => {
                                stopped_for_credential_error = true;
                                retry_after = None;
                                warn!(%error, "cluster runtime: credential reload failed; active generation stopped fail closed");
                                if marker_invalidation_failed
                                    && let Err(retry_error) =
                                        invalidate_runtime(&deps, &last_config, &last_credentials)
                                            .await
                                {
                                    warn!(%retry_error, "cluster runtime marker remained active after the immediate post-stop credential-error retry");
                                }
                            }
                            ReconcileOutcome::TeardownUncertain { error } => {
                                stopped_for_credential_error = true;
                                retry_after = None;
                                warn!(%error, "cluster runtime: credential reload failed and teardown is uncertain; supervisor poisoned");
                            }
                            ReconcileOutcome::Unchanged | ReconcileOutcome::Applied => {
                                unreachable!()
                            }
                        }
                    } else if let Some(invalidation_error) = invalidation_error {
                        warn!(%invalidation_error, %error, "cluster runtime inputs remain unreadable and the stopped generation marker still could not be invalidated; retrying on the next poll");
                    }
                    continue;
                }
            };
            let recovering_credential_error = std::mem::take(&mut stopped_for_credential_error);
            let retry_due =
                retry_after.is_some_and(|deadline| deadline <= tokio::time::Instant::now());
            let retry_pending =
                retry_after.is_some_and(|deadline| deadline > tokio::time::Instant::now());
            let runtime_degraded = core.active_is_degraded_for(&desired.runtime);
            if core.is_poisoned() && desired == observed {
                continue;
            }
            if desired == observed
                && !retry_due
                && !forced_reconcile
                && !recovering_credential_error
                && (!runtime_degraded || retry_pending)
            {
                continue;
            }
            let invalidation_error = if runtime_degraded || desired != observed {
                invalidate_runtime(&deps, &config, &credentials).await.err()
            } else {
                None
            };
            if let Some(error) = invalidation_error {
                let cause =
                    error.context("invalidate active marker before cluster runtime reconciliation");
                let outcome = core.stop_active_fail_closed(cause).await;
                last_config = config;
                last_credentials = credentials;
                observed = desired;
                retry_after = Some(tokio::time::Instant::now() + FAILED_SWITCH_RETRY_INTERVAL);
                match outcome {
                    ReconcileOutcome::StartFailedClean { error } => {
                        warn!(%error, "cluster runtime marker invalidation failed; active generation stopped fail closed and no replacement will start before retry");
                        if let Err(retry_error) =
                            invalidate_runtime(&deps, &last_config, &last_credentials).await
                        {
                            warn!(%retry_error, "cluster runtime marker remained active after the immediate post-stop invalidation retry");
                        }
                    }
                    ReconcileOutcome::TeardownUncertain { error } => {
                        retry_after = None;
                        warn!(%error, "cluster runtime marker invalidation failed and teardown is uncertain; supervisor poisoned");
                    }
                    ReconcileOutcome::Unchanged | ReconcileOutcome::Applied => unreachable!(),
                }
                continue;
            }
            last_config = config.clone();
            last_credentials = credentials.clone();
            observed = desired.clone();

            // Keep the observed input snapshot intact for the post-start
            // health/ACK decision below. `reconcile` owns its candidate spec
            // so the active generation cannot borrow reload-loop state.
            match core.reconcile(desired.runtime.clone()).await {
                ReconcileOutcome::Unchanged | ReconcileOutcome::Applied => {
                    match acknowledge_runtime(&deps, &config, &credentials, core.active_status())
                        .await
                    {
                        Ok(crate::cli::cluster::ClusterRuntimeAckOutcome::Committed) => {
                            retry_after =
                                core.active_is_degraded_for(&desired.runtime).then(|| {
                                    tokio::time::Instant::now() + FAILED_SWITCH_RETRY_INTERVAL
                                });
                            last_superseded = None;
                        }
                        Ok(crate::cli::cluster::ClusterRuntimeAckOutcome::Superseded) => {
                            let repeated = last_superseded
                                .as_ref()
                                .is_some_and(|prior| prior == &observed);
                            last_superseded = Some(observed.clone());
                            let invalidation_error =
                                invalidate_runtime(&deps, &config, &credentials).await.err();
                            let cause = match invalidation_error {
                                Some(error) => anyhow::anyhow!(
                                    "cluster runtime acknowledgement was superseded and marker invalidation failed: {error:#}"
                                ),
                                None => anyhow::anyhow!(
                                    "cluster runtime acknowledgement was superseded"
                                ),
                            };
                            match core.stop_active_fail_closed(cause).await {
                                ReconcileOutcome::StartFailedClean { .. } if !repeated => {
                                    retry_after = None;
                                    reconcile_immediately = true;
                                    warn!(
                                        "cluster runtime acknowledgement superseded; coalescing latest generation immediately"
                                    );
                                }
                                ReconcileOutcome::StartFailedClean { .. } => {
                                    retry_after = Some(
                                        tokio::time::Instant::now() + FAILED_SWITCH_RETRY_INTERVAL,
                                    );
                                    warn!(
                                        "cluster runtime acknowledgement remained superseded without newer inputs; waiting before retry"
                                    );
                                }
                                ReconcileOutcome::TeardownUncertain { error } => {
                                    retry_after = None;
                                    warn!(%error, "uncommitted superseded cluster runtime could not be stopped; supervisor poisoned");
                                }
                                ReconcileOutcome::Unchanged | ReconcileOutcome::Applied => {
                                    unreachable!()
                                }
                            }
                        }
                        Err(error) => {
                            let invalidation_error =
                                invalidate_runtime(&deps, &config, &credentials).await.err();
                            let marker_invalidation_failed = invalidation_error.is_some();
                            let cause = match invalidation_error {
                                Some(invalidation_error) => anyhow::anyhow!(
                                    "cluster runtime ACK failed ({error:#}); marker invalidation also failed: {invalidation_error:#}"
                                ),
                                None => error.context("commit cluster runtime acknowledgement"),
                            };
                            match core.stop_active_fail_closed(cause).await {
                                ReconcileOutcome::StartFailedClean { error } => {
                                    warn!(%error, "cluster runtime acknowledgement failed; uncommitted candidate stopped");
                                    if marker_invalidation_failed
                                        && let Err(retry_error) =
                                            invalidate_runtime(&deps, &config, &credentials).await
                                    {
                                        warn!(%retry_error, "cluster runtime ACK marker remained active after the immediate post-stop invalidation retry");
                                    }
                                    retry_after = Some(
                                        tokio::time::Instant::now() + FAILED_SWITCH_RETRY_INTERVAL,
                                    );
                                }
                                ReconcileOutcome::TeardownUncertain { error } => {
                                    retry_after = None;
                                    warn!(%error, "cluster runtime acknowledgement failed and candidate teardown is uncertain; supervisor poisoned");
                                }
                                ReconcileOutcome::Unchanged | ReconcileOutcome::Applied => {
                                    unreachable!()
                                }
                            }
                        }
                    }
                }
                ReconcileOutcome::StartFailedClean { error } => {
                    warn!(%error, "cluster runtime candidate failed after clean teardown; no previous generation restored");
                    retry_after = Some(tokio::time::Instant::now() + FAILED_SWITCH_RETRY_INTERVAL);
                }
                ReconcileOutcome::TeardownUncertain { error } => {
                    retry_after = None;
                    warn!(%error, "cluster runtime teardown is uncertain; supervisor poisoned and will never start another generation");
                }
            }
        }

        let first_invalidation = invalidate_runtime(&deps, &last_config, &last_credentials).await;
        if let Err(error) = first_invalidation.as_ref() {
            warn!(%error, "cluster runtime: failed to invalidate active marker before shutdown; stopping fail closed before one final invalidation attempt");
        }
        if let Err(error) = core.shutdown().await {
            warn!(%error, "cluster runtime supervisor teardown reported an error");
        } else {
            info!("cluster runtime supervisor stopped");
        }
        if first_invalidation.is_err()
            && let Err(error) = invalidate_runtime(&deps, &last_config, &last_credentials).await
        {
            warn!(%error, "cluster runtime: final marker invalidation failed after fail-closed shutdown");
        }
    });

    Ok(ClusterRuntimeSupervisorHandle {
        shutdown: Some(shutdown_tx),
        task: Some(task),
        ack_in_flight,
        ack_permitted,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct Counters {
        active: usize,
        gossip: usize,
        requests: usize,
        mdns: usize,
        max_active: usize,
        max_gossip: usize,
        max_requests: usize,
        max_mdns: usize,
        starts: Vec<String>,
        start_attempt_keys: Vec<u8>,
        stops: Vec<String>,
        fail_start: HashMap<String, usize>,
        fail_start_key: HashMap<u8, usize>,
        uncertain_start_key: HashSet<u8>,
        fail_stop: HashSet<String>,
        unhealthy_carrier: HashSet<String>,
        unhealthy_mdns: HashSet<String>,
    }

    #[derive(Clone, Default)]
    struct FakeFactory {
        counters: Arc<Mutex<Counters>>,
    }

    struct FakeRuntime {
        name: String,
        counters: Arc<Mutex<Counters>>,
        live: bool,
    }

    impl FakeRuntime {
        fn release_consumers(&mut self) {
            if !self.live {
                return;
            }
            let mut counters = self.counters.lock().unwrap();
            counters.active -= 1;
            counters.gossip -= 1;
            counters.requests -= 1;
            counters.mdns -= 1;
            counters.stops.push(self.name.clone());
            self.live = false;
        }
    }

    #[async_trait]
    impl RuntimeFactory for FakeFactory {
        type Runtime = FakeRuntime;

        async fn start(&self, spec: &RuntimeSpec) -> Result<Self::Runtime> {
            let name = spec
                .identity
                .as_ref()
                .map(|identity| identity.name.clone())
                .unwrap_or_else(|| "disabled".to_string());
            let key_tag = spec
                .identity
                .as_ref()
                .map(|identity| identity.key.0[0])
                .unwrap_or_default();
            let mut counters = self.counters.lock().unwrap();
            counters.start_attempt_keys.push(key_tag);
            if let Some(remaining) = counters.fail_start.get_mut(&name)
                && *remaining > 0
            {
                *remaining -= 1;
                anyhow::bail!("scripted start failure for {name}");
            }
            if let Some(remaining) = counters.fail_start_key.get_mut(&key_tag)
                && *remaining > 0
            {
                *remaining -= 1;
                anyhow::bail!("scripted start failure for key generation");
            }
            if counters.uncertain_start_key.contains(&key_tag) {
                return Err(crate::cluster::hyperswarm::test_uncertain_start_error(
                    "scripted partially-started carrier cleanup uncertainty",
                ));
            }
            counters.active += 1;
            counters.gossip += 1;
            counters.requests += 1;
            counters.mdns += 1;
            counters.max_active = counters.max_active.max(counters.active);
            counters.max_gossip = counters.max_gossip.max(counters.gossip);
            counters.max_requests = counters.max_requests.max(counters.requests);
            counters.max_mdns = counters.max_mdns.max(counters.mdns);
            counters.starts.push(name.clone());
            drop(counters);
            Ok(FakeRuntime {
                name,
                counters: Arc::clone(&self.counters),
                live: true,
            })
        }
    }

    #[async_trait]
    impl RuntimeUnit for FakeRuntime {
        fn health(&self) -> RuntimeHealth {
            let counters = self.counters.lock().unwrap();
            RuntimeHealth {
                carrier_active: self.live && !counters.unhealthy_carrier.contains(&self.name),
                mdns_active: self.live && !counters.unhealthy_mdns.contains(&self.name),
            }
        }

        async fn shutdown(mut self) -> Result<()> {
            self.release_consumers();
            if self.counters.lock().unwrap().fail_stop.contains(&self.name) {
                anyhow::bail!("scripted stop failure for {}", self.name);
            }
            Ok(())
        }
    }

    impl Drop for FakeRuntime {
        fn drop(&mut self) {
            self.release_consumers();
        }
    }

    fn spec(name: &str) -> RuntimeSpec {
        spec_with_key(name, name.as_bytes()[0])
    }

    fn spec_with_key(name: &str, key_byte: u8) -> RuntimeSpec {
        RuntimeSpec {
            enabled: true,
            identity: Some(RuntimeIdentitySpec {
                name: name.to_string(),
                key: ClusterKey([key_byte; 32]),
            }),
            transport: ClusterTransport::Peeroxide,
            peers: Vec::new(),
            mdns: ClusterMdnsConfig::default(),
            announce_policy: ClusterAnnouncePolicy {
                announce_on_untrusted_wifi: true,
                trusted_ssids: Vec::new(),
            },
            listen_port: crate::config::DEFAULT_CLUSTER_LISTEN_PORT,
            network: NetworkFingerprint {
                ssid: Some("test-network".to_string()),
                primary_ip: Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            },
        }
    }

    #[test]
    fn iroh_runtime_spec_ignores_peeroxide_only_network_and_mdns_inputs() {
        let mut config = FreedomConfig::default();
        config.cluster.transport = ClusterTransport::Iroh;
        config.cluster.peers = vec!["peer-a".to_string()];
        let credentials = Credentials::default();
        let first = RuntimeSpec::from_inputs(
            &config,
            &credentials,
            NetworkFingerprint {
                ssid: Some("wifi-a".to_string()),
                primary_ip: Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10))),
            },
        );

        config.cluster.mdns.enabled = !config.cluster.mdns.enabled;
        config.cluster.policy.announce_on_untrusted_wifi = true;
        config.cluster.policy.trusted_ssids = vec!["wifi-b".to_string()];
        config.cluster.listen_port = config.cluster.listen_port.saturating_add(1);
        let second = RuntimeSpec::from_inputs(
            &config,
            &credentials,
            NetworkFingerprint {
                ssid: Some("wifi-b".to_string()),
                primary_ip: Some(IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 20))),
            },
        );

        assert_eq!(first, second);
        assert!(first.network == NetworkFingerprint::default());
        assert!(!first.mdns.enabled);
        assert_eq!(first.listen_port, 0);
    }

    #[test]
    fn iroh_runtime_spec_rotates_when_seed_peers_change() {
        let mut config = FreedomConfig::default();
        config.cluster.transport = ClusterTransport::Iroh;
        config.cluster.peers = vec!["peer-a".to_string()];
        let credentials = Credentials::default();
        let first = RuntimeSpec::from_inputs(&config, &credentials, NetworkFingerprint::default());
        config.cluster.peers.push("peer-b".to_string());
        let second = RuntimeSpec::from_inputs(&config, &credentials, NetworkFingerprint::default());

        assert_ne!(first, second);
    }

    #[cfg(feature = "cluster-iroh")]
    #[test]
    fn iroh_endpoint_identity_is_stable_per_key_generation_and_rotates_on_key_change() {
        let home = tempfile::tempdir().unwrap();
        let generation_a = ClusterKey([b'a'; 32]);
        let generation_b = ClusterKey([b'b'; 32]);

        let first = load_or_create_iroh_endpoint_secret(home.path(), &generation_a).unwrap();
        let same = load_or_create_iroh_endpoint_secret(home.path(), &generation_a).unwrap();
        let rotated = load_or_create_iroh_endpoint_secret(home.path(), &generation_b).unwrap();

        assert_eq!(first.public(), same.public());
        assert_ne!(first.public(), rotated.public());
        let record = home.path().join(IROH_ENDPOINT_IDENTITY_NAME);
        assert!(record.exists());
        #[cfg(windows)]
        crate::wal::win_native::verify_private_dacl(&record).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(record).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn ack_in_flight_guard_clears_during_unwind() {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let unwind = std::panic::catch_unwind({
            let flag = Arc::clone(&flag);
            move || {
                let _guard = AckInFlightGuard::acquire(flag);
                panic!("scripted marker worker panic");
            }
        });

        assert!(unwind.is_err());
        assert!(!flag.load(std::sync::atomic::Ordering::Acquire));
    }

    #[tokio::test]
    async fn switch_keeps_exactly_one_runtime_mdns_gossip_and_request_consumer() {
        let factory = FakeFactory::default();
        let counters = Arc::clone(&factory.counters);
        let mut core = SupervisorCore::start(factory, spec("alpha")).await.unwrap();

        assert!(matches!(
            core.reconcile(spec("beta")).await,
            ReconcileOutcome::Applied
        ));
        core.shutdown().await.unwrap();

        let counters = counters.lock().unwrap();
        assert_eq!(counters.max_active, 1);
        assert_eq!(counters.max_gossip, 1);
        assert_eq!(counters.max_requests, 1);
        assert_eq!(counters.max_mdns, 1);
        assert_eq!(
            (
                counters.active,
                counters.gossip,
                counters.requests,
                counters.mdns
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(counters.starts, ["alpha", "beta"]);
        assert_eq!(counters.stops, ["alpha", "beta"]);
    }

    #[tokio::test]
    async fn network_fingerprint_change_rebuilds_the_owned_generation() {
        let factory = FakeFactory::default();
        let counters = Arc::clone(&factory.counters);
        let original = spec("alpha");
        let mut changed = original.clone();
        changed.network.primary_ip = Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10)));
        let mut core = SupervisorCore::start(factory, original).await.unwrap();

        assert!(matches!(
            core.reconcile(changed).await,
            ReconcileOutcome::Applied
        ));
        core.shutdown().await.unwrap();

        let counters = counters.lock().unwrap();
        assert_eq!(counters.starts, ["alpha", "alpha"]);
        assert_eq!(counters.stops, ["alpha", "alpha"]);
        assert_eq!(counters.max_active, 1);
    }

    #[tokio::test]
    async fn finished_critical_worker_forces_rebuild_for_the_same_spec() {
        let factory = FakeFactory::default();
        let counters = Arc::clone(&factory.counters);
        let desired = spec("alpha");
        let mut core = SupervisorCore::start(factory, desired.clone())
            .await
            .unwrap();
        counters
            .lock()
            .unwrap()
            .unhealthy_carrier
            .insert("alpha".to_string());

        assert!(core.active_is_degraded_for(&desired));
        assert!(matches!(
            core.reconcile(desired).await,
            ReconcileOutcome::Applied
        ));
        counters.lock().unwrap().unhealthy_carrier.clear();
        core.shutdown().await.unwrap();
        assert_eq!(counters.lock().unwrap().starts, ["alpha", "alpha"]);
    }

    #[tokio::test]
    async fn mdns_degradation_is_detected_for_retry() {
        let factory = FakeFactory::default();
        let counters = Arc::clone(&factory.counters);
        let desired = spec("alpha");
        let core = SupervisorCore::start(factory, desired.clone())
            .await
            .unwrap();
        counters
            .lock()
            .unwrap()
            .unhealthy_mdns
            .insert("alpha".to_string());

        assert!(core.active_is_degraded_for(&desired));
    }

    #[tokio::test]
    async fn failed_candidate_stays_stopped_without_restoring_previous_generation() {
        let factory = FakeFactory::default();
        let counters = Arc::clone(&factory.counters);
        counters
            .lock()
            .unwrap()
            .fail_start
            .insert("beta".to_string(), 1);
        let mut core = SupervisorCore::start(factory, spec("alpha")).await.unwrap();

        assert!(matches!(
            core.reconcile(spec("beta")).await,
            ReconcileOutcome::StartFailedClean { .. }
        ));
        assert!(core.active.is_none());
        core.shutdown().await.unwrap();

        let counters = counters.lock().unwrap();
        assert_eq!(counters.max_active, 1);
        assert_eq!(counters.max_gossip, 1);
        assert_eq!(counters.max_requests, 1);
        assert_eq!(counters.max_mdns, 1);
        assert_eq!(counters.starts, ["alpha"]);
        assert_eq!(counters.stops, ["alpha"]);
        assert_eq!(counters.active, 0);
    }

    #[tokio::test]
    async fn auth_rotation_start_failure_never_restarts_revoked_key_generation() {
        let factory = FakeFactory::default();
        let counters = Arc::clone(&factory.counters);
        counters.lock().unwrap().fail_start_key.insert(b'b', 2);
        let mut core = SupervisorCore::start(factory, spec_with_key("mesh", b'a'))
            .await
            .unwrap();

        assert!(matches!(
            core.reconcile(spec_with_key("mesh", b'b')).await,
            ReconcileOutcome::StartFailedClean { .. }
        ));
        assert!(matches!(
            core.reconcile(spec_with_key("mesh", b'b')).await,
            ReconcileOutcome::StartFailedClean { .. }
        ));
        assert!(core.active.is_none());
        let counters = counters.lock().unwrap();
        assert_eq!(
            (
                counters.active,
                counters.gossip,
                counters.requests,
                counters.mdns
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(counters.max_active, 1);
        assert_eq!(counters.start_attempt_keys, [b'a', b'b', b'b']);
        assert_eq!(counters.starts, ["mesh"]);
        assert_eq!(counters.stops, ["mesh"]);
    }

    #[tokio::test]
    async fn acknowledgement_error_stops_uncommitted_candidate() {
        let factory = FakeFactory::default();
        let counters = Arc::clone(&factory.counters);
        let mut core = SupervisorCore::start(factory, spec("alpha")).await.unwrap();
        assert!(matches!(
            core.reconcile(spec("beta")).await,
            ReconcileOutcome::Applied
        ));

        assert!(matches!(
            core.stop_active_fail_closed(anyhow::anyhow!("ack write failed"))
                .await,
            ReconcileOutcome::StartFailedClean { .. }
        ));
        assert!(core.active.is_none());

        let counters = counters.lock().unwrap();
        assert_eq!(counters.starts, ["alpha", "beta"]);
        assert_eq!(counters.stops, ["alpha", "beta"]);
        assert_eq!(
            (counters.active, counters.gossip, counters.requests),
            (0, 0, 0)
        );
    }

    #[tokio::test]
    async fn dropping_supervisor_core_cancels_and_releases_all_consumers() {
        let factory = FakeFactory::default();
        let counters = Arc::clone(&factory.counters);
        let core = SupervisorCore::start(factory, spec("alpha")).await.unwrap();

        drop(core);

        let counters = counters.lock().unwrap();
        assert_eq!(
            (
                counters.active,
                counters.gossip,
                counters.requests,
                counters.mdns
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(counters.stops, ["alpha"]);
    }

    #[tokio::test]
    async fn teardown_uncertainty_terminally_poisoned_never_retries() {
        let factory = FakeFactory::default();
        let counters = Arc::clone(&factory.counters);
        counters
            .lock()
            .unwrap()
            .fail_stop
            .insert("alpha".to_string());
        let mut core = SupervisorCore::start(factory, spec("alpha")).await.unwrap();

        assert!(matches!(
            core.reconcile(spec("beta")).await,
            ReconcileOutcome::TeardownUncertain { .. }
        ));
        assert!(matches!(
            core.reconcile(spec("beta")).await,
            ReconcileOutcome::TeardownUncertain { .. }
        ));
        let counters = counters.lock().unwrap();
        assert_eq!(counters.starts, ["alpha"]);
        assert_eq!(
            (
                counters.active,
                counters.gossip,
                counters.requests,
                counters.mdns
            ),
            (0, 0, 0, 0)
        );
    }

    #[tokio::test]
    async fn start_cleanup_uncertainty_terminally_poisoned_never_retries() {
        let factory = FakeFactory::default();
        let counters = Arc::clone(&factory.counters);
        counters.lock().unwrap().uncertain_start_key.insert(b'b');
        let mut core = SupervisorCore::start(factory, spec_with_key("mesh", b'a'))
            .await
            .unwrap();

        assert!(matches!(
            core.reconcile(spec_with_key("mesh", b'b')).await,
            ReconcileOutcome::TeardownUncertain { .. }
        ));
        assert!(matches!(
            core.reconcile(spec_with_key("mesh", b'b')).await,
            ReconcileOutcome::TeardownUncertain { .. }
        ));

        let counters = counters.lock().unwrap();
        assert_eq!(counters.start_attempt_keys, [b'a', b'b']);
        assert_eq!(counters.starts, ["mesh"]);
        assert_eq!(counters.stops, ["mesh"]);
        assert_eq!(counters.active, 0);
    }
}
