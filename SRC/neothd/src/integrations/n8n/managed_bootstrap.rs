//! Isolated first-owner bootstrap for a NEOTH-managed n8n volume.
//!
//! The temporary container has no Docker network and no published port.  The
//! only HTTP client is the reviewed in-image Node program below; request bodies
//! travel on `docker exec -i` stdin and are never command arguments, receipts,
//! or custody JSON.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use anyhow::{Context, Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{config::keychain::SecretStore, installers::n8n::N8N_OCI_REFERENCE, secret::SecretString};

use super::managed_runtime::{self, ManagedN8nRequest};
use super::bootstrap_transport::{BootstrapDockerRunner, LocalBootstrapDockerRunner};

const CUSTODY_FILE: &str = "n8n-managed-bootstrap.v2.json";
const RUNTIME_BINDING_FILE: &str = "n8n-managed-runtime.v2.json";
const BOOTSTRAP_SCHEMA: &str = "v2";
const MOUNT: &str = "/home/node/.n8n";

// This program is deliberately constant.  It accepts one strict JSON envelope
// from stdin and only talks to loopback in its own network namespace.
const NODE_CLIENT: &str = r#"const fs=require('fs');(async()=>{const x=JSON.parse(fs.readFileSync(0,'utf8'));if(!['settings','setup','login','mint'].includes(x.op))throw Error('op');let p=x.op==='settings'?'/rest/settings':x.op==='setup'?'/rest/owner/setup':x.op==='login'?'/rest/login':'/rest/api-keys';let h={'content-type':'application/json','browser-id':x.browserId};if(x.cookie)h.cookie=x.cookie;let o={method:x.op==='settings'?'GET':'POST',headers:h};if(x.op==='setup')o.body=JSON.stringify({email:x.email,password:x.password,firstName:'NEOTH',lastName:'Owner'});if(x.op==='login')o.body=JSON.stringify({emailOrLdapLoginId:x.email,password:x.password});if(x.op==='mint')o.body=JSON.stringify({label:x.label,scopes:['workflow:list'],expiresAt:null});let ac=new AbortController(),t=setTimeout(()=>ac.abort(),5000),r=await fetch('http://127.0.0.1:5678'+p,{...o,signal:ac.signal}),rd=r.body.getReader(),a=[],n=0;for(;;){let q=await rd.read();if(q.done)break;n+=q.value.length;if(n>32768)throw Error('body');a.push(q.value)}clearTimeout(t);let b=Buffer.concat(a).toString('utf8');process.stdout.write(JSON.stringify({status:r.status,cookie:r.headers.get('set-cookie')||'',body:JSON.parse(b)}));})().catch(()=>process.exit(23));"#;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum BootstrapPhase { VolumeIntent, VolumeBound, BootstrapContainerBound, OwnerSetupInFlight, OwnerEstablished, KeyMintInFlight, KeyMintUnknown, KeyCaptured, BootstrapStopped, BootstrapRemoved, RuntimeContainerBound, Ready }

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapCustody {
    schema_version: u8,
    phase: BootstrapPhase,
    job_id: String,
    manifest_sha256: String,
    volume_name: String,
    bootstrap_container_id: Option<String>,
    runtime_container_id: Option<String>,
    pinned_image: String,
    host_port: u16,
    api_key_label: String,
}

fn custody_path(home: &Path) -> PathBuf { home.join(CUSTODY_FILE) }
fn read_custody(home: &Path) -> Result<Option<BootstrapCustody>> {
    let path=custody_path(home);
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|_| anyhow!("n8n_bootstrap_custody_invalid")),
        Err(error) if error.kind()==std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(anyhow!("n8n_bootstrap_custody_read_failed")),
    }
}
/// A bootstrap sidecar is authoritative before ordinary runtime recovery.  A
/// malformed sidecar deliberately holds the capability instead of allowing a
/// queued/running bootstrap to be misclassified as process-free.
pub(crate) fn recovery_requires_hold(home: &Path, _job: &super::IntegrationJob) -> bool {
    match read_custody(home) {
        // A foreign record may be a stale or tampered capability owner.  Do
        // not let another active n8n job reclaim the shared instance while it
        // remains unresolved.
        Ok(Some(_custody)) => true,
        Err(_) => custody_path(home).exists(),
        Ok(None) => false,
    }
}
pub(crate) fn recovery_decision(
    home: &Path,
    job: &super::IntegrationJob,
) -> Option<super::RestartDecision> {
    let store = crate::config::keychain::open_store().ok()?;
    recovery_decision_with(home, job, LocalBootstrapDockerRunner::default(), &*store)
}

fn recovery_decision_with<R: BootstrapDockerRunner + 'static>(
    home: &Path,
    job: &super::IntegrationJob,
    runner: R,
    store: &dyn SecretStore,
) -> Option<super::RestartDecision> {
    let custody = read_custody(home).ok()??;
    if !recovery_custody_matches(&custody, job)
        || custody.phase == BootstrapPhase::KeyMintUnknown
        || recovery_runtime_binding_may_exist(home, &custody)
        || !recovery_secrets_exist(&custody, store)
    {
        return None;
    }
    let proof = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .ok()?
                    .block_on(recovery_proof_with(runner, &custody))
                    .ok()
            })
            .join()
            .ok()
            .flatten()
    })?;
    let contract = job.evidence_contract.as_ref()?;
    Some(super::RestartDecision::Resume {
        evidence: super::ResumeEvidence::verified(
            job.job_id.clone(),
            job.manifest_sha256.clone(),
            contract.step_plan_sha256().clone(),
            proof.clone(),
        ),
        disposition: super::RecoveryDispositionEvidence::verified(
            job.job_id.clone(),
            job.manifest_sha256.clone(),
            contract.step_plan_sha256().clone(),
            job.state_revision,
            sha256_parts(&["n8n-bootstrap-recovery-process", proof.as_str()]),
            sha256_parts(&["n8n-bootstrap-recovery-custody", proof.as_str()]),
        ),
    })
}

/// The runtime binding is written during the same handoff that follows a
/// removed bootstrap container.  A restart observed between that write and
/// the bootstrap phase update has two custody candidates, so recovery must
/// retain the active lease without attempting any Docker proof.
fn recovery_runtime_binding_may_exist(home: &Path, custody: &BootstrapCustody) -> bool {
    custody.phase == BootstrapPhase::BootstrapRemoved
        && !matches!(
            std::fs::symlink_metadata(home.join(RUNTIME_BINDING_FILE)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        )
}

fn recovery_custody_matches(custody: &BootstrapCustody, job: &super::IntegrationJob) -> bool {
    custody.schema_version == 2
        && custody.job_id == job.job_id.as_str()
        && custody.manifest_sha256 == job.manifest_sha256.as_str()
        && custody.pinned_image == N8N_OCI_REFERENCE
        && managed_runtime::valid_volume_name(&custody.volume_name)
        && custody.host_port != 0
        && matches!(
            custody.phase,
            BootstrapPhase::OwnerSetupInFlight
                | BootstrapPhase::OwnerEstablished
                | BootstrapPhase::KeyCaptured
                | BootstrapPhase::BootstrapStopped
                | BootstrapPhase::BootstrapRemoved
        )
}

fn recovery_secrets_exist(custody: &BootstrapCustody, store: &dyn SecretStore) -> bool {
    let owner = matches!(
        custody.phase,
        BootstrapPhase::OwnerSetupInFlight | BootstrapPhase::OwnerEstablished
    );
    let captured = matches!(
        custody.phase,
        BootstrapPhase::KeyCaptured
            | BootstrapPhase::BootstrapStopped
            | BootstrapPhase::BootstrapRemoved
    );
    (!owner || (store.get(&secret_key(&custody.job_id, "owner-password")).ok().flatten().is_some()
        && store.get(&secret_key(&custody.job_id, "browser-id")).ok().flatten().is_some()
        && store.get(&secret_key(&custody.job_id, "api-key-label")).ok().flatten().is_some()))
        && (!captured
            || store
                .get(&secret_key(&custody.job_id, "captured-api-key"))
                .ok()
                .flatten()
                .is_some())
}
fn write_custody(home: &Path, custody: &BootstrapCustody) -> Result<()> {
    crate::util::atomic_write::atomic_write_private(&custody_path(home), &serde_json::to_vec(custody)?)
        .map_err(|_| anyhow!("n8n_bootstrap_custody_write_failed"))
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn random_hex(len: usize) -> Result<String> { let mut bytes=vec![0;len]; getrandom::getrandom(&mut bytes).map_err(|_| anyhow!("n8n_bootstrap_rng_failed"))?; Ok(hex(&bytes)) }
fn bootstrap_password() -> Result<String> { Ok(format!("N9{}", random_hex(30)?)) }
fn owner_email(job_id: &str) -> String { format!("owner-{}@invalid.test", job_id.chars().take(8).collect::<String>()) }
fn secret_key(job: &str, kind: &str) -> String { format!("n8n-bootstrap.{kind}.{job}") }

async fn docker<R: BootstrapDockerRunner>(runner: &mut R, argv: &[String], stdin: Option<Zeroizing<Vec<u8>>>, cancel: &mut tokio::sync::oneshot::Receiver<()>) -> Result<Zeroizing<Vec<u8>>> {
    let output=runner.run(argv,stdin,cancel).await.map_err(|_| anyhow!("n8n_bootstrap_docker_unavailable"))?;
    ensure!(output.succeeded, "n8n_bootstrap_docker_failed");
    Ok(output.stdout)
}
async fn docker_secret_exec<R: BootstrapDockerRunner>(runner: &mut R, id: &str, payload: Zeroizing<Vec<u8>>, cancel: &mut tokio::sync::oneshot::Receiver<()>) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(managed_runtime::valid_container_id(id), "n8n_bootstrap_container_id_invalid");
    let argv=vec!["docker".into(),"exec".into(),"-i".into(),"-u".into(),"node".into(),id.into(),"node".into(),"-e".into(),NODE_CLIENT.into()];
    let output=runner.run(&argv,Some(payload),cancel).await.map_err(|_| anyhow!("n8n_bootstrap_http_unknown"))?;
    ensure!(output.succeeded, "n8n_bootstrap_http_unknown");
    Ok(output.stdout)
}

#[derive(Deserialize)]
struct NodeReply { status: u16, cookie: String, body: Value }
fn node_reply(bytes: &[u8]) -> Result<NodeReply> {
    let reply: NodeReply=serde_json::from_slice(bytes).map_err(|_| anyhow!("n8n_bootstrap_http_invalid"))?;
    ensure!(reply.status >= 200 && reply.status < 300 && reply.body.get("data").is_some(), "n8n_bootstrap_http_rejected");
    Ok(reply)
}
fn cookie(reply: &NodeReply) -> Result<String> {
    let value=reply.cookie.split(';').next().unwrap_or_default();
    ensure!(value.starts_with("n8n-auth=") && value.len() <= 8192, "n8n_bootstrap_session_invalid"); Ok(value.into())
}
fn data_bool(reply: &NodeReply, path: &[&str]) -> Option<bool> { path.iter().try_fold(reply.body.get("data")?, |v,k| v.get(*k)).and_then(Value::as_bool) }

fn bootstrap_argv(c: &BootstrapCustody) -> Vec<String> { vec![
    "docker".into(),"run".into(),"-d".into(),"--name".into(),format!("neoth-n8n-bootstrap-{}",c.job_id),
    "--network".into(),"none".into(),"--label".into(),"io.neoth.managed=n8n".into(),"--label".into(),format!("io.neoth.n8n-job={}",c.job_id),"--label".into(),format!("io.neoth.n8n-bootstrap={BOOTSTRAP_SCHEMA}"),
    "-v".into(),format!("{}:{MOUNT}",c.volume_name),"-e".into(),"N8N_LISTEN_ADDRESS=127.0.0.1".into(),c.pinned_image.clone()]
}
fn volume_argv(c: &BootstrapCustody) -> Vec<String> { vec!["docker".into(),"volume".into(),"create".into(),"--label".into(),"io.neoth.managed=n8n".into(),"--label".into(),format!("io.neoth.n8n-job={}",c.job_id),"--label".into(),format!("io.neoth.n8n-bootstrap={BOOTSTRAP_SCHEMA}"),c.volume_name.clone()] }

async fn inspect_volume<R: BootstrapDockerRunner>(runner: &mut R, c: &BootstrapCustody, cancel: &mut tokio::sync::oneshot::Receiver<()>) -> Result<String> {
    let bytes=docker(runner,&["docker".into(),"volume".into(),"inspect".into(),c.volume_name.clone()],None,cancel).await?;
    let rows: Vec<Value>=serde_json::from_slice(&bytes).map_err(|_| anyhow!("n8n_bootstrap_volume_inspect_invalid"))?;
    let row=rows.first().ok_or_else(|| anyhow!("n8n_bootstrap_volume_inspect_invalid"))?;
    ensure!(rows.len()==1 && row.get("Name").and_then(Value::as_str)==Some(c.volume_name.as_str()), "n8n_bootstrap_volume_inspect_invalid");
    let labels=row.get("Labels").and_then(Value::as_object).ok_or_else(|| anyhow!("n8n_bootstrap_volume_inspect_invalid"))?;
    ensure!(labels.get("io.neoth.managed").and_then(Value::as_str)==Some("n8n") && labels.get("io.neoth.n8n-job").and_then(Value::as_str)==Some(c.job_id.as_str()) && labels.get("io.neoth.n8n-bootstrap").and_then(Value::as_str)==Some(BOOTSTRAP_SCHEMA), "n8n_bootstrap_volume_mismatch");
    Ok(format!("{:x}", Sha256::digest(&*bytes)))
}
fn validate_bootstrap_inspect(bytes: &[u8], c: &BootstrapCustody, require_running: bool) -> Result<()> {
    let rows: Vec<Value>=serde_json::from_slice(bytes).map_err(|_| anyhow!("n8n_bootstrap_inspect_invalid"))?;
    let row=rows.first().ok_or_else(|| anyhow!("n8n_bootstrap_inspect_invalid"))?;
    let labels=row.pointer("/Config/Labels").and_then(Value::as_object).ok_or_else(|| anyhow!("n8n_bootstrap_inspect_invalid"))?;
    let mount=row.get("Mounts").and_then(Value::as_array).filter(|m|m.len()==1).and_then(|m|m.first()).ok_or_else(|| anyhow!("n8n_bootstrap_inspect_invalid"))?;
    ensure!(rows.len()==1
        && row.get("Id").and_then(Value::as_str)==c.bootstrap_container_id.as_deref()
        && row.pointer("/Config/Image").and_then(Value::as_str)==Some(c.pinned_image.as_str())
        && labels.get("io.neoth.managed").and_then(Value::as_str)==Some("n8n")
        && labels.get("io.neoth.n8n-job").and_then(Value::as_str)==Some(c.job_id.as_str())
        && labels.get("io.neoth.n8n-bootstrap").and_then(Value::as_str)==Some(BOOTSTRAP_SCHEMA)
        && row.pointer("/HostConfig/NetworkMode").and_then(Value::as_str)==Some("none")
        && row.pointer("/HostConfig/PortBindings").and_then(Value::as_object).is_some_and(|p|p.is_empty())
        && mount.get("Type").and_then(Value::as_str)==Some("volume")
        && mount.get("Name").and_then(Value::as_str)==Some(c.volume_name.as_str())
        && mount.get("Destination").and_then(Value::as_str)==Some(MOUNT)
        && row.pointer("/State/Running").and_then(Value::as_bool)==Some(require_running), "n8n_bootstrap_identity_mismatch");
    Ok(())
}
async fn inspect_bootstrap<R: BootstrapDockerRunner>(runner: &mut R, c: &BootstrapCustody, running: bool, cancel: &mut tokio::sync::oneshot::Receiver<()>) -> Result<()> {
    let id=c.bootstrap_container_id.as_deref().ok_or_else(|| anyhow!("n8n_bootstrap_custody_missing"))?;
    validate_bootstrap_inspect(&docker(runner,&["docker".into(),"container".into(),"inspect".into(),id.into()],None,cancel).await?,c,running)
}

async fn exact_absent<R: BootstrapDockerRunner>(runner: &mut R, id: &str, cancel: &mut tokio::sync::oneshot::Receiver<()>) -> Result<bool> {
    let output=docker(runner,&["docker".into(),"container".into(),"ls".into(),"-a".into(),"--no-trunc".into(),"--filter".into(),format!("id={id}"),"--format".into(),"{{.ID}}".into()],None,cancel).await?;
    Ok(String::from_utf8_lossy(&output).trim().is_empty())
}

async fn recovery_proof_with<R: BootstrapDockerRunner>(
    mut runner: R,
    custody: &BootstrapCustody,
) -> Result<super::Sha256Digest> {
    let (_send, mut cancel) = tokio::sync::oneshot::channel();
    let volume_receipt = inspect_volume(&mut runner, custody, &mut cancel).await?;
    match custody.phase {
        BootstrapPhase::OwnerSetupInFlight
        | BootstrapPhase::OwnerEstablished
        | BootstrapPhase::KeyCaptured => {
            let receipt = recovery_bootstrap_receipt(&mut runner, custody, true, &mut cancel).await?;
            Ok(recovery_digest(custody, "bootstrap-running", &volume_receipt, &receipt))
        }
        BootstrapPhase::BootstrapStopped => {
            let receipt = recovery_bootstrap_receipt(&mut runner, custody, false, &mut cancel).await?;
            Ok(recovery_digest(custody, "bootstrap-stopped", &volume_receipt, &receipt))
        }
        BootstrapPhase::BootstrapRemoved => {
            let id = custody.bootstrap_container_id.as_deref().ok_or_else(|| {
                anyhow!("n8n_bootstrap_recovery_custody_missing")
            })?;
            ensure!(managed_runtime::valid_container_id(id), "n8n_bootstrap_container_id_invalid");
            ensure!(exact_absent(&mut runner, id, &mut cancel).await?, "n8n_bootstrap_recovery_absence_unproven");
            Ok(recovery_digest(custody, "bootstrap-absent", &volume_receipt, id))
        }
        _ => Err(anyhow!("n8n_bootstrap_recovery_phase_unproven")),
    }
}

async fn recovery_bootstrap_receipt<R: BootstrapDockerRunner>(
    runner: &mut R,
    custody: &BootstrapCustody,
    running: bool,
    cancel: &mut tokio::sync::oneshot::Receiver<()>,
) -> Result<String> {
    let id = custody
        .bootstrap_container_id
        .as_deref()
        .ok_or_else(|| anyhow!("n8n_bootstrap_recovery_custody_missing"))?;
    let bytes = docker(
        runner,
        &["docker".into(), "container".into(), "inspect".into(), id.into()],
        None,
        cancel,
    )
    .await?;
    validate_bootstrap_inspect(&bytes, custody, running)?;
    Ok(format!("{:x}", Sha256::digest(&*bytes)))
}

fn recovery_digest(
    custody: &BootstrapCustody,
    state: &str,
    observed_volume_receipt_sha256: &str,
    observed_bootstrap_receipt_sha256: &str,
) -> super::Sha256Digest {
    let fingerprint = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        custody.job_id,
        custody.manifest_sha256,
        custody.volume_name,
        custody.bootstrap_container_id.as_deref().unwrap_or("missing"),
        state,
        observed_volume_receipt_sha256,
        observed_bootstrap_receipt_sha256,
    );
    sha256_parts(&["n8n-bootstrap-recovery-v1", &fingerprint])
}

fn finalize_bootstrap_ready_with<R, B, W>(
    home: &Path,
    custody: &mut BootstrapCustody,
    job: &super::IntegrationJob,
    reconcile_ready: R,
    bound_container_id: B,
    mut write: W,
) -> Result<()>
where
    R: FnOnce(&Path, &super::IntegrationJob) -> std::result::Result<(), &'static str>,
    B: FnOnce(&Path) -> std::result::Result<Option<String>, &'static str>,
    W: FnMut(&Path, &BootstrapCustody) -> Result<()>,
{
    ensure!(
        job.job_id.as_str() == custody.job_id.as_str()
            && job.manifest_sha256.as_str() == custody.manifest_sha256.as_str()
            && job.state == super::JobState::Ready,
        "n8n_bootstrap_runtime_finalize_unproven"
    );
    reconcile_ready(home, job).map_err(anyhow::Error::msg)?;
    let runtime_id = bound_container_id(home).map_err(anyhow::Error::msg)?;
    ensure!(
        runtime_id.as_deref().is_some_and(managed_runtime::valid_container_id),
        "n8n_bootstrap_runtime_custody_missing"
    );
    custody.runtime_container_id = runtime_id;
    custody.phase = BootstrapPhase::RuntimeContainerBound;
    write(home, custody)?;
    custody.phase = BootstrapPhase::Ready;
    write(home, custody)
}

fn finalize_bootstrap_ready(
    home: &Path,
    custody: &mut BootstrapCustody,
    job: &super::IntegrationJob,
) -> Result<()> {
    finalize_bootstrap_ready_with(
        home,
        custody,
        job,
        managed_runtime::reconcile_ready_custody,
        managed_runtime::bound_container_id,
        write_custody,
    )
}

fn repair_ready_bootstrap_with<L, F>(
    custody: &mut BootstrapCustody,
    expected_port: u16,
    load_job: L,
    finalize: F,
) -> Result<Option<super::IntegrationJob>>
where
    L: FnOnce(&str) -> Result<Option<super::IntegrationJob>>,
    F: FnOnce(&mut BootstrapCustody, &super::IntegrationJob) -> Result<()>,
{
    if !matches!(
        custody.phase,
        BootstrapPhase::BootstrapRemoved
            | BootstrapPhase::RuntimeContainerBound
            | BootstrapPhase::Ready
    ) {
        return Ok(None);
    }
    ensure!(
        custody.host_port == expected_port,
        "n8n_bootstrap_ready_custody_mismatch"
    );
    let Some(job) = load_job(&custody.job_id)? else {
        return Ok(None);
    };
    if job.state != super::JobState::Ready {
        return Ok(None);
    }
    ensure!(
        job.job_id.as_str() == custody.job_id.as_str()
            && job.manifest_sha256.as_str() == custody.manifest_sha256.as_str(),
        "n8n_bootstrap_ready_custody_mismatch"
    );
    finalize(custody, &job)?;
    Ok(Some(job))
}

fn repair_ready_bootstrap(home: &Path, custody: &mut BootstrapCustody, expected_port: u16) -> Result<Option<super::IntegrationJob>> {
    repair_ready_bootstrap_with(
        custody,
        expected_port,
        |job_id| {
            let job_id = super::JobId::parse(job_id.to_owned())
                .map_err(|_| anyhow!("n8n_bootstrap_ready_custody_mismatch"))?;
            Ok(super::IntegrationJobService::read_only_snapshot(home)?
                .into_iter()
                .find(|candidate| candidate.job_id == job_id))
        },
        |custody, job| finalize_bootstrap_ready(home, custody, job),
    )
}
/// Implements the owner-only mode.  The final process and API-key publication
/// remain delegated to the existing managed runtime/publisher transaction.
pub(crate) async fn install_bootstrap_at(home: &Path, port: u16, cancel: &mut tokio::sync::oneshot::Receiver<()>) -> Result<super::IntegrationJob> {
    install_bootstrap_at_with(home,port,&mut LocalBootstrapDockerRunner::default(),cancel).await
}
async fn install_bootstrap_at_with<R: BootstrapDockerRunner>(home: &Path, port: u16, runner: &mut R, cancel: &mut tokio::sync::oneshot::Receiver<()>) -> Result<super::IntegrationJob> {
    if let Some(mut custody)=read_custody(home)? {
        if let Some(job) = repair_ready_bootstrap(home, &mut custody, port)? {
            return Ok(job);
        }
        return resume_bootstrap_at_with(home,port,runner,cancel,custody).await;
    }
    ensure!(!custody_path(home).exists() && !home.join("n8n-managed-runtime.v2.json").exists(), "n8n_managed_instance_already_owned");
    // The integration job is durable before any Docker/volume mutation.  Its
    // ID is the only correlation label used by both containers and the volume.
    let nonce=uuid::Uuid::now_v7().to_string();
    let volume=format!("neoth_n8n_{}", nonce.replace('-', "").to_lowercase());
    let request=ManagedN8nRequest::new_with_volume(port,N8N_OCI_REFERENCE,volume.clone()).map_err(anyhow::Error::msg)?;
    let service=super::open_n8n_job_service(home)?;
    let queued=managed_runtime::enqueue_prepared(&service,&request)?;
    // Persist Running before the first possible Docker effect.  A restart must
    // therefore see an active owned job and bootstrap custody together.
    let prepared=service.start(&queued.job_id,queued.state_revision,"bootstrap-owner-isolation")?;
    let job_id=prepared.job_id.as_str().to_owned();
    let label=format!("neoth-bootstrap-{}", random_hex(16)?);
    let mut custody=BootstrapCustody { schema_version:2, phase:BootstrapPhase::VolumeIntent, job_id:job_id.clone(), manifest_sha256: prepared.manifest_sha256.as_str().into(), volume_name:volume.clone(), bootstrap_container_id:None, runtime_container_id:None,pinned_image:N8N_OCI_REFERENCE.into(),host_port:port,api_key_label:label.clone() };
    write_custody(home,&custody)?;
    let store=crate::config::keychain::open_store().context("n8n bootstrap requires the private OS secret store")?;
    let password=SecretString::from(bootstrap_password()?); let browser=SecretString::from(random_hex(16)?);
    store.set(&secret_key(&job_id,"owner-password"),&password)?; store.set(&secret_key(&job_id,"browser-id"),&browser)?; store.set(&secret_key(&job_id,"api-key-label"),&SecretString::from(label.clone()))?;
    docker(runner,&volume_argv(&custody),None,cancel).await?; inspect_volume(runner,&custody,cancel).await?; custody.phase=BootstrapPhase::VolumeBound; write_custody(home,&custody)?;
    let created=docker(runner,&bootstrap_argv(&custody),None,cancel).await?;
    let id=String::from_utf8(created.to_vec()).map_err(|_| anyhow!("n8n_bootstrap_docker_invalid"))?.trim().to_owned(); ensure!(managed_runtime::valid_container_id(&id),"n8n_bootstrap_container_id_invalid");
    custody.bootstrap_container_id=Some(id.clone()); custody.phase=BootstrapPhase::BootstrapContainerBound; write_custody(home,&custody)?;
    inspect_bootstrap(runner,&custody,true,cancel).await?;
    let email=owner_email(&job_id);
    let base=json!({"browserId":browser.expose(),"email":email,"password":password.expose()});
    // Settings is deliberately read before the one setup dispatch.
    let settings_deadline=std::time::Instant::now()+std::time::Duration::from_secs(45);
    let settings=loop {
        let payload=Zeroizing::new(serde_json::to_vec(&json!({"op":"settings","browserId":browser.expose()}))?);
        if let Ok(reply)=docker_secret_exec(runner,&id,payload,cancel).await.and_then(|bytes|node_reply(&bytes)) { break reply; }
        if std::time::Instant::now()>=settings_deadline { return Err(anyhow!("n8n_bootstrap_settings_timeout")); }
        if !matches!(cancel.try_recv(),Err(tokio::sync::oneshot::error::TryRecvError::Empty)) { return Err(anyhow!("n8n_bootstrap_cancelled_custody_retained")); }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    };
    ensure!(data_bool(&settings,&["userManagement","showSetupOnFirstLoad"]) == Some(true), "n8n_existing_owner_requires_api_key");
    custody.phase=BootstrapPhase::OwnerSetupInFlight; write_custody(home,&custody)?;
    let mut setup=base.clone(); setup["op"]=Value::String("setup".into()); let _setup=node_reply(&docker_secret_exec(runner,&id,Zeroizing::new(serde_json::to_vec(&setup)?),cancel).await?)?;
    custody.phase=BootstrapPhase::OwnerEstablished; write_custody(home,&custody)?;
    let mut login=base; login["op"]=Value::String("login".into()); let login=node_reply(&docker_secret_exec(runner,&id,Zeroizing::new(serde_json::to_vec(&login)?),cancel).await?)?; let session=cookie(&login)?;
    custody.phase=BootstrapPhase::KeyMintInFlight; write_custody(home,&custody)?;
    let mint=json!({"op":"mint","browserId":browser.expose(),"cookie":session,"label":label});
    let minted=match docker_secret_exec(runner,&id,Zeroizing::new(serde_json::to_vec(&mint)?),cancel).await.and_then(|b| node_reply(&b)) { Ok(v)=>v, Err(_) => { custody.phase=BootstrapPhase::KeyMintUnknown; write_custody(home,&custody)?; return Err(anyhow!("n8n_bootstrap_key_mint_unknown")); } };
    let raw=minted.body.get("data").and_then(|v|v.get("rawApiKey")).and_then(Value::as_str).filter(|v|!v.is_empty()).ok_or_else(|| anyhow!("n8n_bootstrap_key_mint_unknown"))?;
    let api_key=SecretString::from(raw.to_owned()); store.set(&secret_key(&job_id,"captured-api-key"),&api_key)?; custody.phase=BootstrapPhase::KeyCaptured; write_custody(home,&custody)?;
    inspect_bootstrap(runner,&custody,true,cancel).await?; docker(runner,&["docker".into(),"stop".into(),id.clone()],None,cancel).await?; inspect_bootstrap(runner,&custody,false,cancel).await?; custody.phase=BootstrapPhase::BootstrapStopped; write_custody(home,&custody)?;
    docker(runner,&["docker".into(),"rm".into(),id.clone()],None,cancel).await?; ensure!(exact_absent(runner,&id,cancel).await?,"n8n_bootstrap_remove_unproven"); custody.phase=BootstrapPhase::BootstrapRemoved; write_custody(home,&custody)?;
    if !matches!(cancel.try_recv(),Err(tokio::sync::oneshot::error::TryRecvError::Empty)) { return Err(anyhow!("n8n_bootstrap_cancelled_custody_retained")); }
    let job=managed_runtime::install_prepared_managed_in_service(&service,home,request.with_prepared_job(prepared),api_key,cancel).await?;
    finalize_bootstrap_ready(home,&mut custody,&job)?;
    Ok(job)
}

async fn resume_bootstrap_at_with<R: BootstrapDockerRunner>(home: &Path, port: u16, runner: &mut R, cancel: &mut tokio::sync::oneshot::Receiver<()>, mut custody: BootstrapCustody) -> Result<super::IntegrationJob> {
    ensure!(custody.schema_version==2 && custody.host_port==port && custody.pinned_image==N8N_OCI_REFERENCE && managed_runtime::valid_volume_name(&custody.volume_name),"n8n_bootstrap_resume_custody_mismatch");
    ensure!(matches!(custody.phase,BootstrapPhase::OwnerSetupInFlight|BootstrapPhase::OwnerEstablished|BootstrapPhase::KeyCaptured|BootstrapPhase::BootstrapStopped|BootstrapPhase::BootstrapRemoved),"n8n_bootstrap_resume_requires_manual_repair");
    let service=super::open_n8n_job_service(home)?;
    let job_id=super::JobId::parse(custody.job_id.clone()).map_err(|_| anyhow!("n8n_bootstrap_resume_custody_mismatch"))?;
    let queued=service.get(&job_id)?.ok_or_else(|| anyhow!("n8n_bootstrap_resume_job_missing"))?;
    ensure!(queued.manifest_sha256.as_str()==custody.manifest_sha256 && queued.state==super::JobState::Queued,"n8n_bootstrap_resume_job_not_queued");
    let prepared=service.start(&queued.job_id,queued.state_revision,"bootstrap-owner-resume")?;
    let store=crate::config::keychain::open_store().context("n8n bootstrap resume requires the private OS secret store")?;
    let id=custody.bootstrap_container_id.clone().ok_or_else(|| anyhow!("n8n_bootstrap_resume_custody_mismatch"))?;
    // A response lost after owner/setup is reconciled by one login with the
    // already staged credentials.  It never repeats owner/setup.
    if matches!(custody.phase,BootstrapPhase::OwnerSetupInFlight|BootstrapPhase::OwnerEstablished) {
        inspect_bootstrap(runner,&custody,true,cancel).await?;
        let password=store.get(&secret_key(&custody.job_id,"owner-password"))?.ok_or_else(|| anyhow!("n8n_bootstrap_resume_owner_secret_missing"))?;
        let browser=store.get(&secret_key(&custody.job_id,"browser-id"))?.ok_or_else(|| anyhow!("n8n_bootstrap_resume_owner_secret_missing"))?;
        let email=owner_email(&custody.job_id);
        let login=json!({"op":"login","browserId":browser.expose(),"email":email,"password":password.expose()});
        let reply=node_reply(&docker_secret_exec(runner,&id,Zeroizing::new(serde_json::to_vec(&login)?),cancel).await?).map_err(|_| anyhow!("n8n_bootstrap_owner_login_unproven"))?;
        let session=cookie(&reply).map_err(|_| anyhow!("n8n_bootstrap_owner_login_unproven"))?;
        custody.phase=BootstrapPhase::OwnerEstablished; write_custody(home,&custody)?;
        custody.phase=BootstrapPhase::KeyMintInFlight; write_custody(home,&custody)?;
        let label=store.get(&secret_key(&custody.job_id,"api-key-label"))?.ok_or_else(|| anyhow!("n8n_bootstrap_resume_owner_secret_missing"))?;
        let mint=json!({"op":"mint","browserId":browser.expose(),"cookie":session,"label":label.expose()});
        let minted=match docker_secret_exec(runner,&id,Zeroizing::new(serde_json::to_vec(&mint)?),cancel).await.and_then(|b|node_reply(&b)) { Ok(reply)=>reply, Err(_)=>{ custody.phase=BootstrapPhase::KeyMintUnknown; write_custody(home,&custody)?; return Err(anyhow!("n8n_bootstrap_key_mint_unknown")); } };
        let raw=minted.body.get("data").and_then(|value|value.get("rawApiKey")).and_then(Value::as_str).filter(|value|!value.is_empty()).ok_or_else(|| anyhow!("n8n_bootstrap_key_mint_unknown"))?;
        store.set(&secret_key(&custody.job_id,"captured-api-key"),&SecretString::from(raw.to_owned()))?;
        custody.phase=BootstrapPhase::KeyCaptured; write_custody(home,&custody)?;
    }
    let api_key=store.get(&secret_key(&custody.job_id,"captured-api-key"))?.ok_or_else(|| anyhow!("n8n_bootstrap_resume_key_missing"))?;
    if custody.phase==BootstrapPhase::KeyCaptured { inspect_bootstrap(runner,&custody,true,cancel).await?; docker(runner,&["docker".into(),"stop".into(),id.clone()],None,cancel).await?; inspect_bootstrap(runner,&custody,false,cancel).await?; custody.phase=BootstrapPhase::BootstrapStopped; write_custody(home,&custody)?; }
    if custody.phase==BootstrapPhase::BootstrapStopped { inspect_bootstrap(runner,&custody,false,cancel).await?; docker(runner,&["docker".into(),"rm".into(),id.clone()],None,cancel).await?; ensure!(exact_absent(runner,&id,cancel).await?,"n8n_bootstrap_remove_unproven"); custody.phase=BootstrapPhase::BootstrapRemoved; write_custody(home,&custody)?; }
    let request=ManagedN8nRequest::new_with_volume(port,N8N_OCI_REFERENCE,custody.volume_name.clone()).map_err(anyhow::Error::msg)?;
    let job=managed_runtime::install_prepared_managed_in_service(&service,home,request.with_prepared_job(prepared),api_key,cancel).await?;
    finalize_bootstrap_ready(home,&mut custody,&job)?;
    Ok(job)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };
    #[test] fn bootstrap_command_is_networkless_unpublished_and_secret_free() { let c=BootstrapCustody {schema_version:2,phase:BootstrapPhase::VolumeIntent,job_id:"a".repeat(8),manifest_sha256:"b".repeat(64),volume_name:"neoth_n8n_a".into(),bootstrap_container_id:None,runtime_container_id:None,pinned_image:N8N_OCI_REFERENCE.into(),host_port:5678,api_key_label:"private".into()}; let argv=bootstrap_argv(&c); assert!(argv.windows(2).any(|x|x[0]=="--network" && x[1]=="none")); assert!(!argv.iter().any(|x|x=="-p")); assert!(!argv.iter().any(|x|x.contains("private"))); }
    #[test] fn node_response_requires_data_envelope_and_success() { assert!(node_reply(br#"{"status":200,"cookie":"","body":{"data":{}}}"#).is_ok()); assert!(node_reply(br#"{"status":200,"cookie":"","body":{}}"#).is_err()); assert!(node_reply(br#"{"status":500,"cookie":"","body":{"data":{}}}"#).is_err()); }
    #[test]
    fn bootstrap_password_meets_pinned_n8n_schema() {
        let password = bootstrap_password().unwrap();
        assert_eq!(password.len(), 62);
        assert!(password.chars().any(|character| character.is_ascii_uppercase()));
        assert!(password.chars().any(|character| character.is_ascii_digit()));
    }
    #[test]
    fn owner_email_uses_a_valid_non_loopback_domain() {
        assert_eq!(owner_email("01234567-89ab-cdef"), "owner-01234567@invalid.test");
    }
    #[test]
    fn node_client_uses_setup_email_and_login_email_or_ldap_login_id() {
        assert!(NODE_CLIENT.contains("if(x.op==='setup')o.body=JSON.stringify({email:x.email,password:x.password"));
        assert!(NODE_CLIENT.contains("if(x.op==='login')o.body=JSON.stringify({emailOrLdapLoginId:x.email,password:x.password"));
        assert!(!NODE_CLIENT.contains("if(x.op==='login')o.body=JSON.stringify({email:x.email,password:x.password"));
    }
    #[test] fn generated_volume_is_accepted_by_the_final_runtime_boundary() {
        assert!(managed_runtime::valid_volume_name("neoth_n8n_018f4f64700070008000000000000001"));
        assert!(!managed_runtime::valid_volume_name("bad/name"));
    }
    struct PanicRunner;
    #[async_trait::async_trait]
    impl BootstrapDockerRunner for PanicRunner {
        async fn run(
            &mut self,
            _: &[String],
            _: Option<Zeroizing<Vec<u8>>>,
            _: &mut tokio::sync::oneshot::Receiver<()>,
        ) -> std::result::Result<super::super::bootstrap_transport::BootstrapCommandOutput, super::super::bootstrap_transport::BootstrapCommandFailure> {
            panic!("recovery must not call Docker")
        }
    }

    fn recovery_job(home: &Path) -> crate::integrations::IntegrationJob {
        std::fs::write(home.join("freedom.yaml"), serde_yaml::to_string(&crate::config::FreedomConfig::default()).unwrap()).unwrap();
        let service = super::super::open_n8n_job_service(home).unwrap();
        let request = ManagedN8nRequest::new_with_volume(5678, N8N_OCI_REFERENCE, "neoth_n8n_recovery".into()).unwrap();
        let queued = managed_runtime::enqueue_prepared(&service, &request).unwrap();
        service.start(&queued.job_id, queued.state_revision, "bootstrap-owner-isolation").unwrap()
    }

    fn custody_for(job: &crate::integrations::IntegrationJob, phase: BootstrapPhase) -> BootstrapCustody {
        BootstrapCustody { schema_version: 2, phase, job_id: job.job_id.as_str().into(), manifest_sha256: job.manifest_sha256.as_str().into(), volume_name: "neoth_n8n_recovery".into(), bootstrap_container_id: Some("c".repeat(64)), runtime_container_id: None, pinned_image: N8N_OCI_REFERENCE.into(), host_port: 5678, api_key_label: "private".into() }
    }

    #[derive(Clone)]
    struct RecordingRunner {
        replies: Arc<Mutex<VecDeque<Vec<u8>>>>,
        argv: Arc<Mutex<Vec<Vec<String>>>>,
    }

    #[async_trait::async_trait]
    impl BootstrapDockerRunner for RecordingRunner {
        async fn run(
            &mut self,
            argv: &[String],
            stdin: Option<Zeroizing<Vec<u8>>>,
            _: &mut tokio::sync::oneshot::Receiver<()>,
        ) -> std::result::Result<super::super::bootstrap_transport::BootstrapCommandOutput, super::super::bootstrap_transport::BootstrapCommandFailure> {
            assert!(stdin.is_none(), "recovery must not submit bootstrap requests");
            self.argv.lock().unwrap().push(argv.to_vec());
            let stdout = self.replies.lock().unwrap().pop_front()
                .expect("recovery issued an unplanned Docker command");
            Ok(super::super::bootstrap_transport::BootstrapCommandOutput {
                succeeded: true,
                exit_code: Some(0),
                stdout: Zeroizing::new(stdout),
                stderr: Zeroizing::new(Vec::new()),
            })
        }
    }

    fn recording_runner(replies: Vec<Vec<u8>>) -> (RecordingRunner, Arc<Mutex<Vec<Vec<String>>>>) {
        let argv = Arc::new(Mutex::new(Vec::new()));
        (
            RecordingRunner { replies: Arc::new(Mutex::new(replies.into())), argv: argv.clone() },
            argv,
        )
    }

    fn volume_receipt(custody: &BootstrapCustody) -> Vec<u8> {
        volume_receipt_with_marker(custody, "standard")
    }

    fn volume_receipt_with_marker(custody: &BootstrapCustody, marker: &str) -> Vec<u8> {
        serde_json::to_vec(&json!([{
            "Name": custody.volume_name,
            "Labels": {
                "io.neoth.managed": "n8n",
                "io.neoth.n8n-job": custody.job_id,
                "io.neoth.n8n-bootstrap": BOOTSTRAP_SCHEMA,
                "io.neoth.recovery-test": marker,
            },
        }])).unwrap()
    }

    fn bootstrap_receipt(custody: &BootstrapCustody, running: bool, marker: &str) -> Vec<u8> {
        serde_json::to_vec(&json!([{
            "Id": custody.bootstrap_container_id,
            "Config": {
                "Image": custody.pinned_image,
                "Labels": {
                    "io.neoth.managed": "n8n",
                    "io.neoth.n8n-job": custody.job_id,
                    "io.neoth.n8n-bootstrap": BOOTSTRAP_SCHEMA,
                    "io.neoth.recovery-test": marker,
                },
            },
            "HostConfig": { "NetworkMode": "none", "PortBindings": {} },
            "Mounts": [{ "Type": "volume", "Name": custody.volume_name, "Destination": MOUNT }],
            "State": { "Running": running },
        }])).unwrap()
    }

    fn captured_store(custody: &BootstrapCustody) -> crate::config::keychain::InMemorySecretStore {
        let store = crate::config::keychain::InMemorySecretStore::default();
        store.set(&secret_key(&custody.job_id, "captured-api-key"), &SecretString::from("captured-for-recovery-test")).unwrap();
        store
    }

    fn assert_recovery_proof_only(argv: &Arc<Mutex<Vec<Vec<String>>>>, expected: usize) {
        let argv = argv.lock().unwrap();
        assert_eq!(argv.len(), expected);
        for command in argv.iter() {
            assert!(command.windows(2).any(|pair| pair[0] == "docker" && pair[1] == "volume") || command.windows(2).any(|pair| pair[0] == "docker" && pair[1] == "container"));
            assert!(!command.iter().any(|arg| matches!(arg.as_str(), "exec" | "setup" | "login" | "mint" | "create" | "stop" | "rm")));
        }
    }

    fn assert_job_still_running(home: &Path, job: &crate::integrations::IntegrationJob) {
        let persisted = crate::integrations::IntegrationJobService::read_only_snapshot(home).unwrap()
            .into_iter().find(|candidate| candidate.job_id == job.job_id).unwrap();
        assert_eq!(persisted.state, crate::integrations::JobState::Running);
    }

    fn assert_resume(decision: Option<crate::integrations::RestartDecision>) -> crate::integrations::RestartDecision {
        let decision = decision.expect("proved custody must resume");
        assert!(matches!(decision, crate::integrations::RestartDecision::Resume { .. }));
        decision
    }

    #[test]
    fn injected_finalizer_records_exact_runtime_id_only_for_the_returned_ready_job() {
        let home = tempfile::tempdir().unwrap();
        let job = recovery_job(home.path());
        let mut ready = job.clone();
        ready.state = crate::integrations::JobState::Ready;
        let mut custody = custody_for(&job, BootstrapPhase::BootstrapRemoved);
        let runtime_id = "d".repeat(64);
        finalize_bootstrap_ready_with(
            home.path(),
            &mut custody,
            &ready,
            |_, observed| {
                assert_eq!(observed.job_id, job.job_id);
                assert_eq!(observed.state, crate::integrations::JobState::Ready);
                Ok(())
            },
            |_| Ok(Some(runtime_id.clone())),
            write_custody,
        ).unwrap();
        assert_eq!(custody.phase, BootstrapPhase::Ready);
        assert_eq!(custody.runtime_container_id.as_deref(), Some(runtime_id.as_str()));
        assert_eq!(read_custody(home.path()).unwrap().unwrap().phase, BootstrapPhase::Ready);

        let mut unready = custody_for(&job, BootstrapPhase::BootstrapRemoved);
        assert!(finalize_bootstrap_ready_with(
            home.path(),
            &mut unready,
            &job,
            |_, _| panic!("unready job must not reconcile runtime custody"),
            |_| panic!("unready job must not read a runtime ID"),
            |_, _| panic!("unready job must not write bootstrap custody"),
        ).is_err());
        assert_eq!(unready.phase, BootstrapPhase::BootstrapRemoved);

        let mut foreign = ready.clone();
        foreign.job_id = crate::integrations::JobId::parse(uuid::Uuid::now_v7().to_string()).unwrap();
        let mut foreign_custody = custody_for(&job, BootstrapPhase::BootstrapRemoved);
        assert!(finalize_bootstrap_ready_with(
            home.path(),
            &mut foreign_custody,
            &foreign,
            |_, _| panic!("foreign job must not reconcile runtime custody"),
            |_| panic!("foreign job must not read a runtime ID"),
            |_, _| panic!("foreign job must not write bootstrap custody"),
        ).is_err());
        assert_eq!(foreign_custody.phase, BootstrapPhase::BootstrapRemoved);
    }

    #[test]
    fn ready_metadata_repair_retries_each_final_custody_write_without_publishing() {
        let home = tempfile::tempdir().unwrap();
        let job = recovery_job(home.path());
        let mut ready = job.clone();
        ready.state = crate::integrations::JobState::Ready;
        let runtime_id = "e".repeat(64);
        for fail_at in 1..=2 {
            let original = custody_for(&job, BootstrapPhase::BootstrapRemoved);
            let mut interrupted = original.clone();
            let mut writes = 0;
            assert!(repair_ready_bootstrap_with(
                &mut interrupted,
                5678,
                |_| Ok(Some(ready.clone())),
                |custody, returned| finalize_bootstrap_ready_with(
                    home.path(),
                    custody,
                    returned,
                    |_, _| Ok(()),
                    |_| Ok(Some(runtime_id.clone())),
                    |_, _| {
                        writes += 1;
                        if writes == fail_at {
                            Err(anyhow!("fixture custody write failure"))
                        } else {
                            Ok(())
                        }
                    },
                ),
            ).is_err());
            assert_eq!(writes, fail_at);

            let mut retained = original;
            if fail_at == 2 {
                retained.runtime_container_id = Some(runtime_id.clone());
                retained.phase = BootstrapPhase::RuntimeContainerBound;
            }
            let mut repaired_writes = Vec::new();
            let repaired = repair_ready_bootstrap_with(
                &mut retained,
                5678,
                |_| Ok(Some(ready.clone())),
                |custody, returned| finalize_bootstrap_ready_with(
                    home.path(),
                    custody,
                    returned,
                    |_, _| Ok(()),
                    |_| Ok(Some(runtime_id.clone())),
                    |_, observed| {
                        repaired_writes.push(observed.phase.clone());
                        Ok(())
                    },
                ),
            ).unwrap().expect("durable Ready job repairs bootstrap metadata");
            assert_eq!(repaired.job_id, job.job_id);
            assert_eq!(retained.phase, BootstrapPhase::Ready);
            assert_eq!(retained.runtime_container_id.as_deref(), Some(runtime_id.as_str()));
            assert_eq!(repaired_writes, vec![BootstrapPhase::RuntimeContainerBound, BootstrapPhase::Ready]);
        }

        let mut foreign = ready.clone();
        foreign.job_id = crate::integrations::JobId::parse(uuid::Uuid::now_v7().to_string()).unwrap();
        let mut mismatch = custody_for(&job, BootstrapPhase::BootstrapRemoved);
        assert!(repair_ready_bootstrap_with(
            &mut mismatch,
            5678,
            |_| Ok(Some(foreign)),
            |_, _| panic!("mismatched Ready job must not finalize custody"),
        ).is_err());
        assert_eq!(mismatch.phase, BootstrapPhase::BootstrapRemoved);

        let mut wrong_port = custody_for(&job, BootstrapPhase::BootstrapRemoved);
        let mut finalizer_calls = 0;
        assert!(repair_ready_bootstrap_with(
            &mut wrong_port,
            9999,
            |_| panic!("wrong port must not load or reopen the Ready job"),
            |_, _| {
                finalizer_calls += 1;
                Ok(())
            },
        ).is_err());
        assert_eq!(finalizer_calls, 0);
        assert_eq!(wrong_port.phase, BootstrapPhase::BootstrapRemoved);
    }

    #[test]
    fn key_mint_unknown_holds_without_docker() {
        let home = tempfile::tempdir().unwrap();
        let job = recovery_job(home.path());
        write_custody(home.path(), &custody_for(&job, BootstrapPhase::KeyMintUnknown)).unwrap();
        let store = crate::config::keychain::InMemorySecretStore::default();
        assert!(recovery_decision_with(home.path(), &job, PanicRunner, &store).is_none());
    }

    #[test]
    fn foreign_custody_holds_without_docker() {
        let home = tempfile::tempdir().unwrap();
        let job = recovery_job(home.path());
        let mut custody = custody_for(&job, BootstrapPhase::KeyCaptured);
        custody.job_id = uuid::Uuid::now_v7().to_string();
        write_custody(home.path(), &custody).unwrap();
        let store = crate::config::keychain::InMemorySecretStore::default();
        assert!(recovery_decision_with(home.path(), &job, PanicRunner, &store).is_none());
    }

    #[test]
    fn captured_bootstrap_recovery_resumes_same_job_with_inspect_only_proof() {
        let home = tempfile::tempdir().unwrap();
        let job = recovery_job(home.path());
        let custody = custody_for(&job, BootstrapPhase::KeyCaptured);
        write_custody(home.path(), &custody).unwrap();
        let store = captured_store(&custody);
        let (runner, argv) = recording_runner(vec![volume_receipt(&custody), bootstrap_receipt(&custody, true, "captured")]);
        let decision = assert_resume(recovery_decision_with(home.path(), &job, runner, &store));
        assert!(format!("{decision:?}").contains(job.job_id.as_str()));
        assert_recovery_proof_only(&argv, 2);
    }

    #[test]
    fn stopped_bootstrap_recovery_resumes_same_job_with_stopped_receipt() {
        let home = tempfile::tempdir().unwrap();
        let job = recovery_job(home.path());
        let custody = custody_for(&job, BootstrapPhase::BootstrapStopped);
        write_custody(home.path(), &custody).unwrap();
        let store = captured_store(&custody);
        let (runner, argv) = recording_runner(vec![volume_receipt(&custody), bootstrap_receipt(&custody, false, "stopped")]);
        let decision = assert_resume(recovery_decision_with(home.path(), &job, runner, &store));
        assert!(format!("{decision:?}").contains(job.manifest_sha256.as_str()));
        assert_recovery_proof_only(&argv, 2);
    }

    #[test]
    fn removed_bootstrap_recovery_resumes_same_job_with_exact_absence_proof() {
        let home = tempfile::tempdir().unwrap();
        let job = recovery_job(home.path());
        let custody = custody_for(&job, BootstrapPhase::BootstrapRemoved);
        write_custody(home.path(), &custody).unwrap();
        let store = captured_store(&custody);
        let (runner, argv) = recording_runner(vec![volume_receipt(&custody), Vec::new()]);
        let decision = assert_resume(recovery_decision_with(home.path(), &job, runner, &store));
        assert!(format!("{decision:?}").contains(job.job_id.as_str()));
        assert_recovery_proof_only(&argv, 2);
        let commands = argv.lock().unwrap();
        assert!(commands[1].windows(2).any(|pair| pair[0] == "container" && pair[1] == "ls"));
        assert!(commands[1].iter().any(|arg| arg == &format!("id={}", custody.bootstrap_container_id.as_ref().unwrap())));
    }

    #[test]
    fn recovery_proof_digest_changes_with_exact_inspect_receipt() {
        let home = tempfile::tempdir().unwrap();
        let job = recovery_job(home.path());
        let custody = custody_for(&job, BootstrapPhase::KeyCaptured);
        write_custody(home.path(), &custody).unwrap();
        let store = captured_store(&custody);
        let (first, _) = recording_runner(vec![volume_receipt(&custody), bootstrap_receipt(&custody, true, "first")]);
        let first = assert_resume(recovery_decision_with(home.path(), &job, first, &store));
        let (second, _) = recording_runner(vec![volume_receipt(&custody), bootstrap_receipt(&custody, true, "second")]);
        let second = assert_resume(recovery_decision_with(home.path(), &job, second, &store));
        assert_ne!(format!("{first:?}"), format!("{second:?}"));
    }

    #[test]
    fn recovery_proof_digest_changes_with_exact_volume_receipt() {
        let home = tempfile::tempdir().unwrap();
        let job = recovery_job(home.path());
        let custody = custody_for(&job, BootstrapPhase::KeyCaptured);
        write_custody(home.path(), &custody).unwrap();
        let store = captured_store(&custody);
        let (first, _) = recording_runner(vec![volume_receipt_with_marker(&custody, "first"), bootstrap_receipt(&custody, true, "same")]);
        let first = assert_resume(recovery_decision_with(home.path(), &job, first, &store));
        let (second, _) = recording_runner(vec![volume_receipt_with_marker(&custody, "second"), bootstrap_receipt(&custody, true, "same")]);
        let second = assert_resume(recovery_decision_with(home.path(), &job, second, &store));
        assert_ne!(format!("{first:?}"), format!("{second:?}"));
    }

    #[test]
    fn image_network_mount_and_volume_mismatches_hold_the_lease() {
        for mismatch in ["image", "network", "mount", "volume"] {
            let home = tempfile::tempdir().unwrap();
            let job = recovery_job(home.path());
            let custody = custody_for(&job, BootstrapPhase::KeyCaptured);
            write_custody(home.path(), &custody).unwrap();
            let store = captured_store(&custody);
            let mut receipt: Value = serde_json::from_slice(&bootstrap_receipt(&custody, true, "mismatch")).unwrap();
            let row = receipt[0].as_object_mut().unwrap();
            match mismatch {
                "image" => { row.get_mut("Config").unwrap()["Image"] = json!("foreign/image:latest"); }
                "network" => { row.get_mut("HostConfig").unwrap()["NetworkMode"] = json!("bridge"); }
                "mount" => { row.get_mut("Mounts").unwrap()[0]["Destination"] = json!("/foreign"); }
                "volume" => { row.get_mut("Mounts").unwrap()[0]["Name"] = json!("foreign_volume"); }
                _ => unreachable!(),
            }
            let (runner, argv) = recording_runner(vec![volume_receipt(&custody), serde_json::to_vec(&receipt).unwrap()]);
            assert!(recovery_decision_with(home.path(), &job, runner, &store).is_none(), "{mismatch} mismatch must hold");
            assert_recovery_proof_only(&argv, 2);
            assert_job_still_running(home.path(), &job);
        }
    }

    #[test]
    fn unknown_bootstrap_absence_holds_the_running_job_lease() {
        let home = tempfile::tempdir().unwrap();
        let job = recovery_job(home.path());
        let custody = custody_for(&job, BootstrapPhase::BootstrapRemoved);
        write_custody(home.path(), &custody).unwrap();
        let store = captured_store(&custody);
        let (runner, argv) = recording_runner(vec![volume_receipt(&custody), b"unexpected-container-id\n".to_vec()]);
        assert!(recovery_decision_with(home.path(), &job, runner, &store).is_none());
        assert_recovery_proof_only(&argv, 2);
        assert_job_still_running(home.path(), &job);
    }

    #[test]
    fn removed_bootstrap_with_runtime_binding_holds_before_docker_proof() {
        let home = tempfile::tempdir().unwrap();
        let job = recovery_job(home.path());
        let custody = custody_for(&job, BootstrapPhase::BootstrapRemoved);
        write_custody(home.path(), &custody).unwrap();
        std::fs::write(home.path().join(RUNTIME_BINDING_FILE), serde_json::to_vec(&json!({
            "schema_version": 2,
            "phase": "Bound",
            "job_id": custody.job_id,
            "manifest_sha256": custody.manifest_sha256,
            "container_name": "neoth-n8n",
            "container_id": "d".repeat(64),
            "image": N8N_OCI_REFERENCE,
            "host_port": custody.host_port,
            "volume": custody.volume_name,
        })).unwrap()).unwrap();
        let store = captured_store(&custody);
        assert!(recovery_decision_with(home.path(), &job, PanicRunner, &store).is_none());
        assert_job_still_running(home.path(), &job);
    }

    #[test]
    fn runtime_bound_and_ready_custody_hold_without_recovery_commands() {
        for phase in [BootstrapPhase::RuntimeContainerBound, BootstrapPhase::Ready] {
            let home = tempfile::tempdir().unwrap();
            let job = recovery_job(home.path());
            let custody = custody_for(&job, phase);
            write_custody(home.path(), &custody).unwrap();
            let store = captured_store(&custody);
            assert!(recovery_decision_with(home.path(), &job, PanicRunner, &store).is_none());
            assert_job_still_running(home.path(), &job);
        }
    }
    #[test] fn cookie_requires_the_exact_n8n_auth_name() {
        let ok=NodeReply { status: 200, cookie: "n8n-auth=opaque; Path=/".into(), body: json!({"data":{}}) };
        let wrong=NodeReply { status: 200, cookie: "session=opaque".into(), body: json!({"data":{}}) };
        assert!(cookie(&ok).is_ok()); assert!(cookie(&wrong).is_err());
    }
}
