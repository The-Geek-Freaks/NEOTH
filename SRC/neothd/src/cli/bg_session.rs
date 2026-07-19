//! HERMES-02 — `/background` + `/btw` parallel ephemeral sessions.
//!
//! Entry points: [`spawn_background_process`] for one-shot CLI runtimes and
//! [`spawn_background_session`] for the long-lived channel runtime.
//!
//! Design:
//! - CLI queues the exact finalized/budgeted [`Request`] in a private file and
//!   starts a detached child so the call survives the launcher's shutdown.
//! - A per-job HMAC key authenticates a request/config/job/expiry-bound
//!   capability recording the explicit `/background` action. The key travels
//!   only through the detached child's inherited anonymous stdin pipe: never
//!   the job, argv, env, or filesystem. The child claims the job once,
//!   verifies the MAC, re-checks live consent, and upgrades only permission
//!   `Confirm` decisions (never `Deny`).
//! - Every concrete leaf retains the normal token, cost, permission and WAL
//!   authorization boundary; fallback hops keep their own lifecycle audit.
//! - Writes the result atomically to `~/.neoth/bgjobs/<id>.result`.
//!   A sibling `<id>.exit` marker is written after the result lands.
//! - [`maybe_deliver_bg_result`] scans `bgjobs/` at next-idle (called
//!   from `run_chat_with` at the top of each interactive turn) and
//!   delivers any pending results.  A `<id>.delivered` marker prevents
//!   re-delivery.
//! - WAL bytes 0x87 `BG_SESSION_STARTED` and 0x88 `BG_SESSION_DONE`
//!   audit both ends of the lifecycle.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::warn;
use zeroize::Zeroize as _;

use crate::config::FreedomConfig;
use crate::providers::{Provider, Request};
use crate::wal::events::{EVENT_TYPE_BG_SESSION_DONE, EVENT_TYPE_BG_SESSION_STARTED};

const BG_JOB_SCHEMA_VERSION: u8 = 4;
const BG_JOB_MAX_BYTES: usize = 16 * 1024 * 1024;
const BG_RESULT_MAX_BYTES: usize = 16 * 1024 * 1024;
const BG_CONTROL_MAX_BYTES: usize = 32 * 1024;
const BG_APPROVAL_VALID_SECS: i64 = 15 * 60;
const BG_APPROVAL_KEY_BYTES: usize = 32;
const BG_STARTUP_ACK_TIMEOUT: Duration = Duration::from_secs(10);
const BG_STARTUP_POLL_INTERVAL: Duration = Duration::from_millis(20);
const BG_UNCLAIMED_RECOVERY_SECS: i64 = 30;
const BG_DELIVERY_CLAIM_RECOVERY_SECS: i64 = 5 * 60;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BgWorkerSpec {
    schema_version: u8,
    label: String,
    request: Request,
    config: FreedomConfig,
    config_path: PathBuf,
    queued_unix: i64,
    launcher: BgLauncherIdentity,
    approval: BgApprovalCapability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BgLauncherRole {
    Chat,
    Serve,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BgLauncherIdentity {
    pid: u32,
    process_start_unix: u64,
    executable_sha256: String,
    role: BgLauncherRole,
}

#[derive(Serialize)]
struct BgSignedSpec<'a> {
    schema_version: u8,
    label: &'a str,
    request: &'a Request,
    config: &'a FreedomConfig,
    config_path: &'a Path,
    queued_unix: i64,
    launcher: &'a BgLauncherIdentity,
}

/// Private, one-shot proof that the operator explicitly requested this exact
/// detached job. The job carries only this MAC, never the per-job key;
/// the child consumes it by durably claiming the job before parsing it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BgApprovalCapability {
    expires_unix: i64,
    nonce_hex: String,
    spec_sha256: String,
    mac_sha256: String,
}

#[derive(Debug, Clone)]
struct VerifiedBgApproval {
    expires_unix: i64,
    spec_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BgClaimRecord {
    schema_version: u8,
    job_id: String,
    spec_sha256: String,
    worker_pid: u32,
    worker_start_unix: u64,
    worker_executable_sha256: String,
    claimed_unix: i64,
    mac_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BgStartRecord {
    schema_version: u8,
    job_id: String,
    spec_sha256: String,
    claim_mac_sha256: String,
    mac_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BgDeliveryClaim {
    schema_version: u8,
    job_id: String,
    process_pid: u32,
    process_start_unix: u64,
    claimed_unix: i64,
}

/// One result exclusively claimed for display by this process. The caller
/// acknowledges only after stdout/channel delivery succeeded; dropping the
/// value leaves a recoverable `.delivering` claim rather than losing output.
pub struct PendingBgDelivery {
    text: String,
    delivering_path: PathBuf,
    delivered_path: PathBuf,
}

impl PendingBgDelivery {
    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn acknowledge(self) -> Result<()> {
        match crate::util::atomic_write::write_private_create_new_durable(
            &self.delivered_path,
            b"delivered\n",
        ) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "commit background delivery {}",
                        self.delivered_path.display()
                    )
                });
            }
        }
        crate::util::atomic_write::durable_remove_file(&self.delivering_path).with_context(|| {
            format!(
                "remove background delivery claim {}",
                self.delivering_path.display()
            )
        })
    }
}

/// Opaque background-job identifier. A 16-char hex prefix of a random
/// u64 — short enough to display, unique enough for the bgjobs dir.
#[derive(Debug, Clone)]
pub struct BgJobId(String);

impl BgJobId {
    fn new() -> Result<Self> {
        let mut random = [0_u8; 8];
        getrandom::getrandom(&mut random)
            .map_err(|error| anyhow::anyhow!("background job id RNG unavailable: {error}"))?;
        Ok(Self(hex::encode(random)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn lexical_absolute(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("resolve current directory for background instance home")?
            .join(path)
    };
    let mut clean = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                anyhow::ensure!(
                    clean.pop(),
                    "background instance home escapes its filesystem root"
                );
            }
            other => clean.push(other.as_os_str()),
        }
    }
    anyhow::ensure!(
        clean.is_absolute(),
        "background instance home is not absolute"
    );
    Ok(clean)
}

fn ensure_non_link_directory(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect background job directory {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "background job directory must be a real directory, not a link: {}",
        path.display()
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        anyhow::ensure!(
            metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "background job directory must not be a reparse point: {}",
            path.display()
        );
    }
    Ok(())
}

fn ensure_background_job_directory(instance_home: &Path, bgjobs_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(bgjobs_dir)
        .with_context(|| format!("create background job directory {}", bgjobs_dir.display()))?;
    ensure_non_link_directory(bgjobs_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(bgjobs_dir, std::fs::Permissions::from_mode(0o700)).with_context(
            || format!("restrict background job directory {}", bgjobs_dir.display()),
        )?;
        // `create_dir_all` does not commit the new `bgjobs` name. Sync the
        // instance root before any create-new job/tombstone relies on it.
        std::fs::File::open(instance_home)
            .and_then(|directory| directory.sync_all())
            .with_context(|| {
                format!(
                    "sync background job parent directory {}",
                    instance_home.display()
                )
            })?;
    }
    #[cfg(not(unix))]
    let _ = instance_home;
    Ok(())
}

fn canonical_json_sha256(value: &impl Serialize, label: &str) -> Result<String> {
    // `FreedomConfig` contains HashMaps. Serializing the typed value directly
    // would preserve randomized iteration order across launcher and worker
    // processes. serde_json::Value's default map is ordered, giving the MAC a
    // deterministic representation on every process.
    let mut canonical = serde_json::to_value(value)
        .with_context(|| format!("serialize {label} to canonical JSON value"))?;
    let encoded = serde_json::to_vec(&canonical);
    zeroize_json_strings(&mut canonical);
    let bytes = zeroize::Zeroizing::new(
        encoded.with_context(|| format!("serialize canonical {label} binding"))?,
    );
    Ok(hex::encode(Sha256::digest(bytes.as_slice())))
}

fn executable_sha256(path: &Path) -> Result<String> {
    use std::io::Read as _;

    let mut file = std::fs::File::open(path)
        .with_context(|| format!("open process executable {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect process executable {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file(),
        "process executable is not a regular file: {}",
        path.display()
    );
    const MAX_EXECUTABLE_BYTES: u64 = 1024 * 1024 * 1024;
    anyhow::ensure!(
        metadata.len() <= MAX_EXECUTABLE_BYTES,
        "process executable exceeds the 1 GiB attestation cap: {}",
        path.display()
    );
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("hash process executable {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[derive(Debug)]
struct LiveProcessSnapshot {
    pid: u32,
    parent_pid: Option<u32>,
    process_start_unix: u64,
    executable_sha256: String,
    command: Vec<OsString>,
}

fn live_process_snapshot(pid: u32) -> Result<LiveProcessSnapshot> {
    let system = sysinfo::System::new_all();
    let process = system
        .process(sysinfo::Pid::from_u32(pid))
        .with_context(|| format!("process {pid} is not live"))?;
    let executable = process
        .exe()
        .with_context(|| format!("process {pid} executable is unavailable"))?;
    Ok(LiveProcessSnapshot {
        pid,
        parent_pid: process.parent().map(sysinfo::Pid::as_u32),
        process_start_unix: process.start_time(),
        executable_sha256: executable_sha256(executable)?,
        command: process.cmd().to_vec(),
    })
}

fn first_process_subcommand(args: &[OsString]) -> Option<&OsStr> {
    let mut index = 1;
    while index < args.len() {
        let arg = args[index].as_os_str();
        if arg == OsStr::new("--stream") {
            index += 1;
            continue;
        }
        if arg == OsStr::new("--output") {
            index = index.saturating_add(2);
            continue;
        }
        if arg.to_string_lossy().starts_with("--output=") {
            index += 1;
            continue;
        }
        return Some(arg);
    }
    None
}

fn classify_launcher_role(args: &[OsString]) -> Result<BgLauncherRole> {
    match first_process_subcommand(args).and_then(OsStr::to_str) {
        Some("chat") => Ok(BgLauncherRole::Chat),
        Some("serve") => Ok(BgLauncherRole::Serve),
        Some(other) => anyhow::bail!(
            "background worker launch is restricted to the trusted `chat` or `serve` command path; current subcommand is `{other}`"
        ),
        None => anyhow::bail!(
            "background worker launch is restricted to an explicit `chat` or `serve` command path"
        ),
    }
}

fn current_launcher_identity() -> Result<BgLauncherIdentity> {
    let snapshot = live_process_snapshot(std::process::id())?;
    let role = classify_launcher_role(&std::env::args_os().collect::<Vec<_>>())?;
    Ok(BgLauncherIdentity {
        pid: snapshot.pid,
        process_start_unix: snapshot.process_start_unix,
        executable_sha256: snapshot.executable_sha256,
        role,
    })
}

fn verify_live_launcher(expected: &BgLauncherIdentity) -> Result<()> {
    let worker = live_process_snapshot(std::process::id())?;
    anyhow::ensure!(
        worker.parent_pid == Some(expected.pid),
        "background worker parent PID does not match the authenticated launcher"
    );
    let parent = live_process_snapshot(expected.pid)?;
    anyhow::ensure!(
        parent.process_start_unix == expected.process_start_unix,
        "background worker launcher process identity changed"
    );
    anyhow::ensure!(
        digest_hex_eq(&parent.executable_sha256, &expected.executable_sha256)
            && digest_hex_eq(&worker.executable_sha256, &expected.executable_sha256),
        "background worker executable does not match the authenticated live launcher"
    );
    anyhow::ensure!(
        classify_launcher_role(&parent.command)? == expected.role,
        "background worker launcher subcommand does not match the signed job"
    );
    Ok(())
}

fn zeroize_json_strings(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(value) => value.zeroize(),
        serde_json::Value::Array(values) => values.iter_mut().for_each(zeroize_json_strings),
        serde_json::Value::Object(values) => {
            values.values_mut().for_each(zeroize_json_strings);
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

fn append_binding_field(binding: &mut Vec<u8>, value: &[u8]) {
    binding.extend_from_slice(&(value.len() as u64).to_be_bytes());
    binding.extend_from_slice(value);
}

fn capability_binding_bytes(
    schema_version: u8,
    job_id: &str,
    expires_unix: i64,
    nonce_hex: &str,
    spec_sha256: &str,
) -> zeroize::Zeroizing<Vec<u8>> {
    let mut binding = zeroize::Zeroizing::new(Vec::with_capacity(320));
    append_binding_field(&mut binding, b"neoth.background-explicit-request.v3");
    append_binding_field(&mut binding, &[schema_version]);
    append_binding_field(&mut binding, job_id.as_bytes());
    append_binding_field(&mut binding, &expires_unix.to_be_bytes());
    append_binding_field(&mut binding, nonce_hex.as_bytes());
    append_binding_field(&mut binding, spec_sha256.as_bytes());
    binding
}

fn capability_mac(
    key: &[u8],
    schema_version: u8,
    job_id: &str,
    expires_unix: i64,
    nonce_hex: &str,
    spec_sha256: &str,
) -> String {
    let binding =
        capability_binding_bytes(schema_version, job_id, expires_unix, nonce_hex, spec_sha256);
    hex::encode(crate::util::hmac::sha256(key, binding.as_slice()))
}

#[allow(clippy::too_many_arguments)]
fn signed_spec_sha256(
    schema_version: u8,
    label: &str,
    request: &Request,
    config: &FreedomConfig,
    config_path: &Path,
    queued_unix: i64,
    launcher: &BgLauncherIdentity,
) -> Result<String> {
    canonical_json_sha256(
        &BgSignedSpec {
            schema_version,
            label,
            request,
            config,
            config_path,
            queued_unix,
            launcher,
        },
        "complete background job specification",
    )
}

fn digest_hex_eq(left: &str, right: &str) -> bool {
    if left.len() != 64 || right.len() != 64 {
        return false;
    }
    let (Ok(left), Ok(right)) = (hex::decode(left), hex::decode(right)) else {
        return false;
    };
    bool::from(left.as_slice().ct_eq(right.as_slice()))
}

impl BgApprovalCapability {
    // Keep every authenticated field explicit at this security boundary. A
    // bag-of-fields argument would make it easier to reuse a stale job spec.
    #[allow(clippy::too_many_arguments)]
    fn mint(
        key: &[u8],
        schema_version: u8,
        job_id: &BgJobId,
        label: &str,
        request: &Request,
        config: &FreedomConfig,
        config_path: &Path,
        queued_unix: i64,
        launcher: &BgLauncherIdentity,
    ) -> Result<Self> {
        anyhow::ensure!(
            key.len() == BG_APPROVAL_KEY_BYTES,
            "background approval key has invalid length"
        );
        let mut nonce = [0_u8; 32];
        getrandom::getrandom(&mut nonce)
            .map_err(|error| anyhow::anyhow!("background approval RNG unavailable: {error}"))?;
        let nonce_hex = hex::encode(nonce);
        nonce.zeroize();
        let expires_unix = crate::time::now_unix_i64()
            .checked_add(BG_APPROVAL_VALID_SECS)
            .context("background approval expiry overflow")?;
        let spec_sha256 = signed_spec_sha256(
            schema_version,
            label,
            request,
            config,
            config_path,
            queued_unix,
            launcher,
        )?;
        let mac_sha256 = capability_mac(
            key,
            schema_version,
            job_id.as_str(),
            expires_unix,
            &nonce_hex,
            &spec_sha256,
        );
        Ok(Self {
            expires_unix,
            nonce_hex,
            spec_sha256,
            mac_sha256,
        })
    }

    // Verification deliberately mirrors `mint` field-for-field so reviewers
    // can audit the complete MAC binding at the call site.
    #[allow(clippy::too_many_arguments)]
    fn verify(
        &self,
        key: &[u8],
        schema_version: u8,
        job_id: &BgJobId,
        label: &str,
        request: &Request,
        config: &FreedomConfig,
        config_path: &Path,
        queued_unix: i64,
        launcher: &BgLauncherIdentity,
        now_unix: i64,
    ) -> Result<VerifiedBgApproval> {
        anyhow::ensure!(
            key.len() == BG_APPROVAL_KEY_BYTES,
            "background approval key has invalid length"
        );
        anyhow::ensure!(
            self.expires_unix >= now_unix,
            "background explicit-request capability expired"
        );
        anyhow::ensure!(
            self.nonce_hex.len() == 64
                && self
                    .nonce_hex
                    .bytes()
                    .all(|byte| { byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) }),
            "background explicit-request capability nonce is malformed"
        );
        let spec_sha256 = signed_spec_sha256(
            schema_version,
            label,
            request,
            config,
            config_path,
            queued_unix,
            launcher,
        )?;
        anyhow::ensure!(
            digest_hex_eq(&self.spec_sha256, &spec_sha256),
            "background explicit-request capability specification binding mismatch"
        );
        let expected_mac = capability_mac(
            key,
            schema_version,
            job_id.as_str(),
            self.expires_unix,
            &self.nonce_hex,
            &spec_sha256,
        );
        anyhow::ensure!(
            digest_hex_eq(&self.mac_sha256, &expected_mac),
            "background explicit-request capability MAC mismatch"
        );
        Ok(VerifiedBgApproval {
            expires_unix: self.expires_unix,
            spec_sha256,
        })
    }
}

fn control_mac(key: &[u8], domain: &[u8], fields: &[&[u8]]) -> String {
    let mut binding = zeroize::Zeroizing::new(Vec::with_capacity(512));
    append_binding_field(&mut binding, domain);
    for field in fields {
        append_binding_field(&mut binding, field);
    }
    hex::encode(crate::util::hmac::sha256(key, binding.as_slice()))
}

fn claim_mac(
    key: &[u8],
    job_id: &str,
    spec_sha256: &str,
    worker_pid: u32,
    worker_start_unix: u64,
    worker_executable_sha256: &str,
    claimed_unix: i64,
) -> String {
    control_mac(
        key,
        b"neoth.background-claim.v1",
        &[
            &[BG_JOB_SCHEMA_VERSION],
            job_id.as_bytes(),
            spec_sha256.as_bytes(),
            &worker_pid.to_be_bytes(),
            &worker_start_unix.to_be_bytes(),
            worker_executable_sha256.as_bytes(),
            &claimed_unix.to_be_bytes(),
        ],
    )
}

fn start_mac(key: &[u8], job_id: &str, spec_sha256: &str, claim_mac_sha256: &str) -> String {
    control_mac(
        key,
        b"neoth.background-start.v1",
        &[
            &[BG_JOB_SCHEMA_VERSION],
            job_id.as_bytes(),
            spec_sha256.as_bytes(),
            claim_mac_sha256.as_bytes(),
        ],
    )
}

fn worker_command_matches_job(command: &[OsString], job_path: &Path) -> bool {
    let expected = [
        OsString::from("--output"),
        OsString::from("json"),
        OsString::from("internal"),
        OsString::from("background-worker"),
        OsString::from("--job"),
        job_path.as_os_str().to_os_string(),
    ];
    command.get(1..) == Some(expected.as_slice())
}

fn mint_claim_record(
    key: &[u8],
    job_id: &BgJobId,
    spec_sha256: &str,
    job_path: &Path,
) -> Result<BgClaimRecord> {
    let worker = live_process_snapshot(std::process::id())?;
    #[cfg(not(test))]
    anyhow::ensure!(
        worker_command_matches_job(&worker.command, job_path),
        "background worker command line is not the exact internal job invocation"
    );
    #[cfg(test)]
    let _ = job_path;
    let claimed_unix = crate::time::now_unix_i64();
    let mac_sha256 = claim_mac(
        key,
        job_id.as_str(),
        spec_sha256,
        worker.pid,
        worker.process_start_unix,
        &worker.executable_sha256,
        claimed_unix,
    );
    Ok(BgClaimRecord {
        schema_version: BG_JOB_SCHEMA_VERSION,
        job_id: job_id.as_str().to_owned(),
        spec_sha256: spec_sha256.to_owned(),
        worker_pid: worker.pid,
        worker_start_unix: worker.process_start_unix,
        worker_executable_sha256: worker.executable_sha256,
        claimed_unix,
        mac_sha256,
    })
}

fn verify_claim_record(
    record: &BgClaimRecord,
    key: &[u8],
    job_id: &BgJobId,
    spec_sha256: &str,
    child_pid: u32,
    job_path: &Path,
) -> Result<()> {
    anyhow::ensure!(
        record.schema_version == BG_JOB_SCHEMA_VERSION
            && record.job_id == job_id.as_str()
            && digest_hex_eq(&record.spec_sha256, spec_sha256)
            && record.worker_pid == child_pid,
        "background worker claim identity mismatch"
    );
    let expected_mac = claim_mac(
        key,
        job_id.as_str(),
        spec_sha256,
        record.worker_pid,
        record.worker_start_unix,
        &record.worker_executable_sha256,
        record.claimed_unix,
    );
    anyhow::ensure!(
        digest_hex_eq(&record.mac_sha256, &expected_mac),
        "background worker claim MAC mismatch"
    );
    let live = live_process_snapshot(record.worker_pid)?;
    anyhow::ensure!(
        live.process_start_unix == record.worker_start_unix
            && digest_hex_eq(&live.executable_sha256, &record.worker_executable_sha256)
            && worker_command_matches_job(&live.command, job_path),
        "background worker claim does not match the live child process"
    );
    Ok(())
}

fn build_start_record(
    key: &[u8],
    job_id: &BgJobId,
    spec_sha256: &str,
    claim: &BgClaimRecord,
) -> BgStartRecord {
    BgStartRecord {
        schema_version: BG_JOB_SCHEMA_VERSION,
        job_id: job_id.as_str().to_owned(),
        spec_sha256: spec_sha256.to_owned(),
        claim_mac_sha256: claim.mac_sha256.clone(),
        mac_sha256: start_mac(key, job_id.as_str(), spec_sha256, &claim.mac_sha256),
    }
}

fn verify_start_record(
    record: &BgStartRecord,
    key: &[u8],
    job_id: &BgJobId,
    spec_sha256: &str,
    claim: &BgClaimRecord,
) -> Result<()> {
    anyhow::ensure!(
        record.schema_version == BG_JOB_SCHEMA_VERSION
            && record.job_id == job_id.as_str()
            && digest_hex_eq(&record.spec_sha256, spec_sha256)
            && digest_hex_eq(&record.claim_mac_sha256, &claim.mac_sha256),
        "background worker start acknowledgement identity mismatch"
    );
    let expected_mac = start_mac(key, job_id.as_str(), spec_sha256, &claim.mac_sha256);
    anyhow::ensure!(
        digest_hex_eq(&record.mac_sha256, &expected_mac),
        "background worker start acknowledgement MAC mismatch"
    );
    Ok(())
}

/// Queue a CLI background job in a separate NEOTH process. A Tokio task is not
/// sufficient here: the one-shot `neoth chat` runtime is destroyed as soon as
/// the slash command returns, which aborts detached tasks. The private job file
/// keeps prompts off the command line and lets the worker outlive the launcher.
pub async fn spawn_background_process(
    label: &str,
    request: Request,
    instance_home: &Path,
    config_path: &Path,
    config: FreedomConfig,
    writer: Option<&crate::wal::writer::WalWriterHandle>,
) -> Result<BgJobId> {
    anyhow::ensure!(
        matches!(label, "background" | "btw"),
        "invalid background job label"
    );
    anyhow::ensure!(
        request
            .model
            .as_deref()
            .is_some_and(|model| !model.trim().is_empty()),
        "background request must carry its exact wire model"
    );
    let job_id = BgJobId::new()?;
    let absolute_home = lexical_absolute(instance_home)?;
    let absolute_config_path = lexical_absolute(config_path)?;
    anyhow::ensure!(
        absolute_config_path.parent() == Some(absolute_home.as_path()),
        "background config must be an immediate child of the authoritative instance home"
    );
    let bgjobs_dir = absolute_home.join("bgjobs");
    let job_path = bgjobs_dir.join(format!("{}.job", job_id.as_str()));
    let claim_path = bgjobs_dir.join(format!("{}.claimed", job_id.as_str()));
    let start_path = bgjobs_dir.join(format!("{}.start", job_id.as_str()));
    let executable = std::env::current_exe().context("locate NEOTH background worker binary")?;
    ensure_background_job_directory(&absolute_home, &bgjobs_dir)?;
    recover_background_jobs(&absolute_home, &bgjobs_dir)?;
    let launcher = current_launcher_identity()?;
    let queued_unix = crate::time::now_unix_i64();
    let mut approval_key = zeroize::Zeroizing::new([0_u8; BG_APPROVAL_KEY_BYTES]);
    getrandom::getrandom(approval_key.as_mut_slice())
        .map_err(|error| anyhow::anyhow!("background approval key RNG unavailable: {error}"))?;
    let approval = BgApprovalCapability::mint(
        approval_key.as_slice(),
        BG_JOB_SCHEMA_VERSION,
        &job_id,
        label,
        &request,
        &config,
        &absolute_config_path,
        queued_unix,
        &launcher,
    )?;
    let mut spec = BgWorkerSpec {
        schema_version: BG_JOB_SCHEMA_VERSION,
        label: label.to_owned(),
        request,
        config,
        config_path: absolute_config_path,
        queued_unix,
        launcher,
        approval,
    };
    let spec_sha256 = spec.approval.spec_sha256.clone();
    let bytes = zeroize::Zeroizing::new(
        serde_json::to_vec(&spec).context("serialize background worker job")?,
    );
    ensure_non_link_directory(&bgjobs_dir)?;
    crate::util::atomic_write::write_private_create_new_durable(&job_path, &bytes)
        .with_context(|| format!("write private background job {}", job_path.display()))?;
    drop(bytes);
    spec.approval.nonce_hex.zeroize();
    let mut command = background_worker_command(&executable, &job_path);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            drop(approval_key);
            let failure = anyhow::Error::new(error).context(format!(
                "spawn detached NEOTH background worker {}",
                executable.display()
            ));
            return match crate::util::atomic_write::durable_remove_file(&job_path) {
                Ok(()) => Err(failure),
                Err(cleanup_error) => Err(failure.context(format!(
                    "durably remove unlaunched background job {} also failed: {cleanup_error}",
                    job_path.display()
                ))),
            };
        }
    };
    if let Err(error) = send_background_approval_key(&mut child, approval_key.as_slice()) {
        let failure = error.context(format!(
            "send one-shot approval key to background worker {}",
            executable.display()
        ));
        drop(approval_key);
        persist_background_worker_startup_error(&bgjobs_dir, &job_path, &job_id, &failure)?;
        return Err(failure);
    }
    let claim = match wait_for_authenticated_claim(
        &mut child,
        &absolute_home,
        &claim_path,
        &job_path,
        &job_id,
        &spec_sha256,
        approval_key.as_slice(),
    )
    .await
    {
        Ok(claim) => claim,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            persist_background_worker_startup_error(&bgjobs_dir, &job_path, &job_id, &error)?;
            drop(approval_key);
            return Err(error);
        }
    };
    let start = build_start_record(approval_key.as_slice(), &job_id, &spec_sha256, &claim);
    let start_bytes = zeroize::Zeroizing::new(
        serde_json::to_vec(&start).context("serialize background start acknowledgement")?,
    );
    if let Err(error) =
        crate::util::atomic_write::write_private_create_new_durable(&start_path, &start_bytes)
    {
        let _ = child.kill();
        let _ = child.wait();
        let failure = anyhow::Error::new(error).context(format!(
            "publish authenticated background start acknowledgement {}",
            start_path.display()
        ));
        persist_background_worker_startup_error(&bgjobs_dir, &job_path, &job_id, &failure)?;
        drop(approval_key);
        return Err(failure);
    }
    drop(approval_key);
    if let Some(writer) = writer {
        emit_wal_bg(
            writer,
            EVENT_TYPE_BG_SESSION_STARTED,
            job_id.as_str(),
            label,
            &spec.request.prompt,
        )
        .await;
    }
    spawn_background_worker_reaper(child, absolute_home, bgjobs_dir, job_id.clone());
    Ok(job_id)
}

async fn wait_for_authenticated_claim(
    child: &mut std::process::Child,
    instance_home: &Path,
    claim_path: &Path,
    job_path: &Path,
    job_id: &BgJobId,
    spec_sha256: &str,
    key: &[u8],
) -> Result<BgClaimRecord> {
    let deadline = Instant::now() + BG_STARTUP_ACK_TIMEOUT;
    loop {
        if claim_path
            .try_exists()
            .with_context(|| format!("inspect background claim {}", claim_path.display()))?
        {
            let bytes = zeroize::Zeroizing::new(
                crate::updater::self_update::read_private_control_file_bounded(
                    instance_home,
                    claim_path,
                    BG_CONTROL_MAX_BYTES,
                    "background worker claim",
                )?,
            );
            let claim: BgClaimRecord =
                serde_json::from_slice(&bytes).context("parse background worker claim")?;
            verify_claim_record(&claim, key, job_id, spec_sha256, child.id(), job_path)?;
            return Ok(claim);
        }
        if let Some(status) = child
            .try_wait()
            .context("poll detached background worker startup")?
        {
            anyhow::bail!(
                "background worker exited before its authenticated durable claim ({status})"
            );
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "background worker did not publish an authenticated durable claim within {} seconds",
            BG_STARTUP_ACK_TIMEOUT.as_secs()
        );
        tokio::time::sleep(BG_STARTUP_POLL_INTERVAL).await;
    }
}

fn send_background_approval_key(child: &mut std::process::Child, key: &[u8]) -> Result<()> {
    use std::io::Write as _;

    anyhow::ensure!(
        key.len() == BG_APPROVAL_KEY_BYTES,
        "background approval pipe key has invalid length"
    );
    let Some(mut stdin) = child.stdin.take() else {
        let _ = child.kill();
        let _ = child.wait();
        anyhow::bail!("background worker stdin pipe was not created");
    };
    let send_result = stdin
        .write_all(key)
        .context("write complete background approval key to child stdin")
        .and_then(|()| stdin.flush().context("flush background approval key pipe"));
    if let Err(error) = send_result {
        // Keep the pipe writer open while terminating the child. Otherwise a
        // fully written key plus a rare flush error could deliver EOF and let
        // the worker race into its claim before the parent handles the error.
        let _ = child.kill();
        drop(stdin);
        let _ = child.wait();
        return Err(error);
    }
    // Dropping the sole parent writer frames the capability: the child accepts
    // exactly 32 bytes followed by EOF and rejects trailing data.
    drop(stdin);
    Ok(())
}

fn background_worker_command(executable: &Path, job_path: &Path) -> std::process::Command {
    use std::process::{Command, Stdio};

    let mut command = Command::new(executable);
    command
        .arg("--output")
        .arg("json")
        .arg("internal")
        .arg("background-worker")
        .arg("--job")
        .arg(job_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        command.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    command
}

fn claim_background_job(claimed_path: &Path, claim: &BgClaimRecord) -> Result<()> {
    let bytes = zeroize::Zeroizing::new(
        serde_json::to_vec(claim).context("serialize authenticated background claim")?,
    );
    crate::util::atomic_write::write_private_create_new_durable(claimed_path, &bytes).with_context(
        || {
            format!(
                "claim background job exactly once {}",
                claimed_path.display()
            )
        },
    )
}

/// Execute one durable CLI background job. This is reached only through the
/// hidden `internal background-worker` command in the child process. Once a
/// valid job path is claimed, every parse/schema/MAC/WAL-start failure becomes
/// a terminal `.result` + `.exit` pair so the launcher cannot leave the user
/// staring at a permanently "running" job.
pub async fn run_background_worker(job_path: &Path) -> Result<BgJobId> {
    let approval_key = {
        let stdin = std::io::stdin();
        let mut stdin = stdin.lock();
        read_background_approval_key(&mut stdin)?
    };
    run_background_worker_with_key(job_path, approval_key).await
}

fn read_background_approval_key(
    reader: &mut impl std::io::Read,
) -> Result<zeroize::Zeroizing<[u8; BG_APPROVAL_KEY_BYTES]>> {
    let mut key = zeroize::Zeroizing::new([0_u8; BG_APPROVAL_KEY_BYTES]);
    reader
        .read_exact(key.as_mut_slice())
        .context("read exact background approval key from inherited stdin pipe")?;
    let mut trailing = [0_u8; 1];
    let trailing_bytes = reader
        .read(&mut trailing)
        .context("verify background approval key pipe EOF")?;
    anyhow::ensure!(
        trailing_bytes == 0,
        "background approval key pipe contains trailing data"
    );
    Ok(key)
}

fn persist_background_worker_startup_error(
    bgjobs_dir: &Path,
    job_path: &Path,
    job_id: &BgJobId,
    error: &anyhow::Error,
) -> Result<()> {
    ensure_non_link_directory(bgjobs_dir)?;
    let result_path = bgjobs_dir.join(format!("{}.result", job_id.as_str()));
    let exit_path = bgjobs_dir.join(format!("{}.exit", job_id.as_str()));
    let message = format!("[bg error] {error:#}");
    crate::util::atomic_write::atomic_write_private(&result_path, message.as_bytes())
        .with_context(|| format!("write background startup error {}", result_path.display()))?;
    crate::util::atomic_write::atomic_write_private(&exit_path, b"failed\n")
        .with_context(|| format!("write background failure marker {}", exit_path.display()))?;
    crate::util::atomic_write::durable_remove_file(job_path)
        .with_context(|| format!("remove rejected background job {}", job_path.display()))?;
    Ok(())
}

fn load_unchanged_live_background_config(
    instance_home: &Path,
    spec: &BgWorkerSpec,
) -> Result<FreedomConfig> {
    anyhow::ensure!(
        spec.config_path.parent() == Some(instance_home),
        "background config path is outside the authenticated instance home"
    );
    let live = FreedomConfig::load_from_path(&spec.config_path).with_context(|| {
        format!(
            "reload live background policy and credentials from {}",
            spec.config_path.display()
        )
    })?;
    let queued_hash = canonical_json_sha256(&spec.config, "queued background config")?;
    let live_hash = canonical_json_sha256(&live, "live background config")?;
    anyhow::ensure!(
        digest_hex_eq(&queued_hash, &live_hash),
        "background policy, provider configuration, or credentials changed after queueing; retry the explicit request"
    );
    Ok(live)
}

async fn wait_for_authenticated_start(
    instance_home: &Path,
    start_path: &Path,
    job_id: &BgJobId,
    spec_sha256: &str,
    claim: &BgClaimRecord,
    key: &[u8],
) -> Result<()> {
    let deadline = Instant::now() + BG_STARTUP_ACK_TIMEOUT;
    loop {
        if start_path.try_exists().with_context(|| {
            format!(
                "inspect background start acknowledgement {}",
                start_path.display()
            )
        })? {
            let bytes = zeroize::Zeroizing::new(
                crate::updater::self_update::read_private_control_file_bounded(
                    instance_home,
                    start_path,
                    BG_CONTROL_MAX_BYTES,
                    "background start acknowledgement",
                )?,
            );
            let start: BgStartRecord =
                serde_json::from_slice(&bytes).context("parse background start acknowledgement")?;
            verify_start_record(&start, key, job_id, spec_sha256, claim)?;
            return Ok(());
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "background launcher did not publish an authenticated start acknowledgement within {} seconds",
            BG_STARTUP_ACK_TIMEOUT.as_secs()
        );
        tokio::time::sleep(BG_STARTUP_POLL_INTERVAL).await;
    }
}

async fn run_background_worker_with_key(
    job_path: &Path,
    approval_key: zeroize::Zeroizing<[u8; BG_APPROVAL_KEY_BYTES]>,
) -> Result<BgJobId> {
    run_background_worker_with_key_and_attestor(job_path, approval_key, verify_live_launcher, true)
        .await
}

async fn run_background_worker_with_key_and_attestor(
    job_path: &Path,
    approval_key: zeroize::Zeroizing<[u8; BG_APPROVAL_KEY_BYTES]>,
    attest_launcher: impl FnOnce(&BgLauncherIdentity) -> Result<()>,
    require_parent_start: bool,
) -> Result<BgJobId> {
    anyhow::ensure!(
        job_path.is_absolute(),
        "background worker job path must be absolute"
    );
    anyhow::ensure!(
        job_path.components().all(|component| !matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )),
        "background worker job path must not contain dot components"
    );
    let bgjobs_dir = job_path
        .parent()
        .filter(|parent| parent.file_name().and_then(|name| name.to_str()) == Some("bgjobs"))
        .context("background job must be an immediate child of a bgjobs directory")?
        .to_path_buf();
    let instance_home = bgjobs_dir
        .parent()
        .context("background job directory has no instance home")?
        .to_path_buf();
    let file_name = job_path
        .file_name()
        .and_then(|name| name.to_str())
        .context("background job filename must be valid UTF-8")?;
    let id = file_name
        .strip_suffix(".job")
        .filter(|id| {
            id.len() == 16
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .context("background job filename must be a lowercase 16-character hex id")?;
    let job_id = BgJobId(id.to_owned());

    // Read and authenticate before consuming the one-shot claim. A malformed
    // job or wrong pipe key therefore cannot burn an operator's valid retry.
    ensure_non_link_directory(&bgjobs_dir)?;
    let claimed_path = bgjobs_dir.join(format!("{}.claimed", job_id.as_str()));
    let start_path = bgjobs_dir.join(format!("{}.start", job_id.as_str()));
    let bytes = zeroize::Zeroizing::new(
        crate::updater::self_update::read_private_control_file_bounded(
            &instance_home,
            job_path,
            BG_JOB_MAX_BYTES,
            "background worker job",
        )?,
    );
    let mut spec: BgWorkerSpec =
        serde_json::from_slice(&bytes).context("parse background worker job")?;
    drop(bytes);
    anyhow::ensure!(
        spec.schema_version == BG_JOB_SCHEMA_VERSION,
        "unsupported background job schema {}",
        spec.schema_version
    );
    anyhow::ensure!(
        matches!(spec.label.as_str(), "background" | "btw"),
        "invalid background job label"
    );
    anyhow::ensure!(
        spec.config_path.is_absolute()
            && spec.config_path.parent() == Some(instance_home.as_path()),
        "background job config path is not the authoritative instance config"
    );
    anyhow::ensure!(
        spec.request
            .model
            .as_deref()
            .is_some_and(|model| !model.trim().is_empty()),
        "background job request has no exact wire model"
    );
    let verification = spec.approval.verify(
        approval_key.as_slice(),
        spec.schema_version,
        &job_id,
        &spec.label,
        &spec.request,
        &spec.config,
        &spec.config_path,
        spec.queued_unix,
        &spec.launcher,
        crate::time::now_unix_i64(),
    );
    spec.approval.nonce_hex.zeroize();
    let verified_approval = verification?;
    attest_launcher(&spec.launcher)?;

    // This durable authenticated tombstone is never removed. Replaying the
    // same request file can therefore never execute twice.
    let claim = mint_claim_record(
        approval_key.as_slice(),
        &job_id,
        &verified_approval.spec_sha256,
        job_path,
    )?;
    claim_background_job(&claimed_path, &claim)?;
    if require_parent_start
        && let Err(error) = wait_for_authenticated_start(
            &instance_home,
            &start_path,
            &job_id,
            &verified_approval.spec_sha256,
            &claim,
            approval_key.as_slice(),
        )
        .await
    {
        persist_background_worker_startup_error(&bgjobs_dir, job_path, &job_id, &error)?;
        return Ok(job_id);
    }
    drop(approval_key);

    let segment = crate::wal::writer::unique_standalone_segment_path(
        &instance_home.join("wal"),
        "background-worker",
    );
    let (writer, writer_join) =
        match crate::wal::writer::spawn_for_home(segment, instance_home.to_path_buf()) {
            Ok(writer) => writer,
            Err(error) => {
                let error = anyhow::anyhow!("{error}").context("spawn background worker WAL");
                persist_background_worker_startup_error(&bgjobs_dir, job_path, &job_id, &error)?;
                return Ok(job_id);
            }
        };

    let result = async {
        // Policy, provider selection, credentials and consent are mutable.
        // Refuse a stale queued snapshot and repeat the check immediately
        // before dispatch so a later cheaper policy cannot be reused.
        let live_config = load_unchanged_live_background_config(&instance_home, &spec)?;
        crate::consent::ensure_all_still_granted(&instance_home, &live_config)
            .context("background provider consent is no longer granted")?;
        let provider = crate::providers::fallback_chain_from_config(
            &live_config,
            &instance_home,
            Some(writer.clone()),
        )
        .await
        .context("construct background provider chain")?;
        let request = spec.request.clone();
        let authorizer = crate::providers::cost_authorization::ProviderCallAuthorizer::explicit_request_capability(
            live_config.autonomy_policy(),
            writer.clone(),
            live_config.tokens.max_per_request,
            verified_approval.expires_unix,
        )
        .with_usage_home(instance_home.clone())
        .with_usage_automated(true)
        .with_audit_context(
            crate::providers::cost_authorization::ProviderCallAuditContext {
                source: Some("chat"),
                call_type: Some("background_session"),
                request_id: Some(job_id.as_str().to_owned()),
                task_id: Some(spec.label.clone()),
                operator_id: live_config.operator_id.clone(),
                model_source: Some("background_exact_request"),
                cost_estimate_model: request.model.clone(),
                ..Default::default()
            },
        );
        let provider = crate::providers::cost_authorization::AuthorizedProvider::from_box(
            provider,
            authorizer,
            request.model.clone(),
            "background_session",
        );
        let dispatch_config = load_unchanged_live_background_config(&instance_home, &spec)?;
        crate::consent::ensure_all_still_granted(&instance_home, &dispatch_config)
            .context("background provider consent was revoked before dispatch")?;
        provider
            .complete(request)
            .await
            .map(|completion| completion.text)
    }
    .await;

    let (result_text, exit_marker) = match result {
        Ok(text) if text.len() <= BG_RESULT_MAX_BYTES => (text, b"done\n".as_slice()),
        Ok(text) => (
            format!(
                "[bg error] provider result exceeded the {} byte durable delivery limit ({} bytes)",
                BG_RESULT_MAX_BYTES,
                text.len()
            ),
            b"failed\n".as_slice(),
        ),
        Err(error) => {
            warn!(job_id = job_id.as_str(), error = %error, "background worker call failed");
            (format!("[bg error] {error:#}"), b"failed\n".as_slice())
        }
    };
    let result_path = bgjobs_dir.join(format!("{}.result", job_id.as_str()));
    let exit_path = bgjobs_dir.join(format!("{}.exit", job_id.as_str()));
    let persist_result: Result<()> = async {
        ensure_non_link_directory(&bgjobs_dir)?;
        crate::util::atomic_write::atomic_write_private(&result_path, result_text.as_bytes())
            .with_context(|| format!("write background result {}", result_path.display()))?;
        crate::util::atomic_write::atomic_write_private(&exit_path, exit_marker)
            .with_context(|| format!("write background exit marker {}", exit_path.display()))?;
        emit_wal_bg_done(&writer, job_id.as_str(), &spec.label).await;
        crate::util::atomic_write::durable_remove_file(job_path)
            .with_context(|| format!("remove completed background job {}", job_path.display()))?;
        crate::util::atomic_write::durable_remove_file(&start_path).with_context(|| {
            format!(
                "remove consumed background start acknowledgement {}",
                start_path.display()
            )
        })?;
        Ok(())
    }
    .await;

    // No return path may abandon the standalone WAL task. All provider,
    // fallback, and authorizer handles are already out of scope above; drop
    // the final sender and await the drain even if result/exit persistence
    // failed.
    drop(writer);
    let wal_result = writer_join.await.context("join background worker WAL");
    if let Err(error) = persist_result {
        if let Err(wal_error) = wal_result {
            warn!(error = %wal_error, "background worker WAL drain also failed");
        }
        return Err(error);
    }
    wal_result?;
    Ok(job_id)
}

/// Spawn a background provider call. Returns the [`BgJobId`] so the
/// caller can log it; the actual result lands later via
/// [`maybe_deliver_bg_result`].
///
/// `label` is `"background"` or `"btw"` — stored in the WAL payload
/// so the operator can distinguish the two command names in `neoth wal
/// show`. `system` is the fully composed context/presentation block from the
/// originating CLI or channel turn; the exact bytes are bound by the leaf
/// authorizer below.
pub async fn spawn_background_session(
    label: &str,
    prompt: String,
    system: Option<String>,
    instance_home: &std::path::Path,
    config_path: &std::path::Path,
    config: FreedomConfig,
    provider: Arc<dyn Provider>,
    writer: Option<&crate::wal::writer::WalWriterHandle>,
) -> Result<BgJobId> {
    let mut request = build_bg_request(&prompt, &config, system);
    let requested_model = request.model.clone();
    request.model = Some(crate::providers::resolve_configured_request_model_for_wire(
        &config,
        provider.as_ref(),
        requested_model.as_deref(),
    )?);
    spawn_background_process(label, request, instance_home, config_path, config, writer).await
}

/// Thin headless provider call. Uses `provider.complete()` directly —
/// no stdout, no WAL/hook overhead, no skill routing. Intentionally
/// thin: ephemeral background sessions trade depth for speed.
fn build_bg_request(prompt: &str, config: &FreedomConfig, system: Option<String>) -> Request {
    let default_model = config
        .inference
        .slot_for(crate::config::inference::HemisphereRole::Left)
        .model
        .clone()
        .or(config.provider_model.clone());
    Request {
        prompt: prompt.to_owned(),
        system,
        model: default_model,
        temperature: None,
        top_p: None,
        sampling_seed: None,
        stop_sequences: vec![],
        thinking_budget: None,
    }
}

fn valid_background_id(id: &str) -> bool {
    id.len() == 16
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn claim_worker_is_live(claim: &BgClaimRecord, job_path: &Path) -> bool {
    if claim.schema_version != BG_JOB_SCHEMA_VERSION || !valid_background_id(&claim.job_id) {
        return false;
    }
    live_process_snapshot(claim.worker_pid).is_ok_and(|live| {
        live.process_start_unix == claim.worker_start_unix
            && digest_hex_eq(&live.executable_sha256, &claim.worker_executable_sha256)
            && worker_command_matches_job(&live.command, job_path)
    })
}

fn recover_one_background_job(
    instance_home: &Path,
    bgjobs_dir: &Path,
    job_id: &BgJobId,
) -> Result<()> {
    let job_path = bgjobs_dir.join(format!("{}.job", job_id.as_str()));
    let claim_path = bgjobs_dir.join(format!("{}.claimed", job_id.as_str()));
    let start_path = bgjobs_dir.join(format!("{}.start", job_id.as_str()));
    let result_path = bgjobs_dir.join(format!("{}.result", job_id.as_str()));
    let exit_path = bgjobs_dir.join(format!("{}.exit", job_id.as_str()));

    if exit_path
        .try_exists()
        .with_context(|| format!("inspect background exit marker {}", exit_path.display()))?
    {
        crate::util::atomic_write::durable_remove_file(&job_path)?;
        crate::util::atomic_write::durable_remove_file(&start_path)?;
        return Ok(());
    }

    if claim_path
        .try_exists()
        .with_context(|| format!("inspect background claim {}", claim_path.display()))?
    {
        let claim = crate::updater::self_update::read_private_control_file_bounded(
            instance_home,
            &claim_path,
            BG_CONTROL_MAX_BYTES,
            "background recovery claim",
        )
        .ok()
        .and_then(|bytes| serde_json::from_slice::<BgClaimRecord>(&bytes).ok());
        if claim.as_ref().is_some_and(|claim| {
            claim.job_id == job_id.as_str() && claim_worker_is_live(claim, &job_path)
        }) {
            return Ok(());
        }
        if result_path.try_exists().with_context(|| {
            format!(
                "inspect recovered background result {}",
                result_path.display()
            )
        })? {
            crate::util::atomic_write::write_private_create_new_durable(&exit_path, b"recovered\n")
                .or_else(|error| {
                    (error.kind() == std::io::ErrorKind::AlreadyExists)
                        .then_some(())
                        .ok_or(error)
                })?;
            crate::util::atomic_write::durable_remove_file(&job_path)?;
            crate::util::atomic_write::durable_remove_file(&start_path)?;
            return Ok(());
        }
        let failure = anyhow::anyhow!(
            "background worker terminated before publishing a durable terminal result"
        );
        persist_background_worker_startup_error(bgjobs_dir, &job_path, job_id, &failure)?;
        crate::util::atomic_write::durable_remove_file(&start_path)?;
        return Ok(());
    }

    let queued_unix = crate::updater::self_update::read_private_control_file_bounded(
        instance_home,
        &job_path,
        BG_JOB_MAX_BYTES,
        "unclaimed background recovery job",
    )
    .ok()
    .and_then(|bytes| serde_json::from_slice::<BgWorkerSpec>(&bytes).ok())
    .map(|spec| spec.queued_unix)
    .unwrap_or(i64::MIN);
    if crate::time::now_unix_i64().saturating_sub(queued_unix) >= BG_UNCLAIMED_RECOVERY_SECS {
        let failure =
            anyhow::anyhow!("background worker never published an authenticated durable claim");
        persist_background_worker_startup_error(bgjobs_dir, &job_path, job_id, &failure)?;
    }
    Ok(())
}

fn recover_background_jobs(instance_home: &Path, bgjobs_dir: &Path) -> Result<()> {
    let entries = match std::fs::read_dir(bgjobs_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("scan background recovery directory"),
    };
    for entry in entries.take(4_096) {
        let entry = entry.context("read background recovery entry")?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(id) = name
            .strip_suffix(".job")
            .filter(|id| valid_background_id(id))
        else {
            continue;
        };
        recover_one_background_job(instance_home, bgjobs_dir, &BgJobId(id.to_owned()))?;
    }
    Ok(())
}

fn spawn_background_worker_reaper(
    mut child: std::process::Child,
    instance_home: PathBuf,
    bgjobs_dir: PathBuf,
    job_id: BgJobId,
) {
    tokio::spawn(async move {
        let wait = tokio::task::spawn_blocking(move || child.wait()).await;
        if let Err(error) = wait {
            warn!(job_id = job_id.as_str(), %error, "background worker reaper task failed");
        }
        if let Err(error) = recover_one_background_job(&instance_home, &bgjobs_dir, &job_id) {
            warn!(job_id = job_id.as_str(), %error, "background worker recovery failed");
        }
    });
}

/// Scan `bgjobs/` for completed-but-undelivered results. Called at the
/// top of each interactive `run_chat_with` turn ("next idle" delivery).
///
/// Returns a `Vec<(label_inferred, result_text)>` — the caller prints
/// each entry prefixed with `[btw] <text>`. A `<id>.delivered` marker
/// prevents re-delivery (idempotent).
///
/// `bgjobs_home` should be `~/.neoth/bgjobs` (or a tempdir in tests).
pub async fn maybe_deliver_bg_result(bgjobs_home: &Path) -> Vec<PendingBgDelivery> {
    let mut delivered = Vec::new();
    let Some(instance_home) = bgjobs_home.parent() else {
        return delivered;
    };
    if let Err(error) = recover_background_jobs(instance_home, bgjobs_home) {
        warn!(%error, "bg_session: recovery scan failed before delivery");
    }
    let process = match live_process_snapshot(std::process::id()) {
        Ok(process) => process,
        Err(error) => {
            warn!(%error, "bg_session: cannot attest result delivery process");
            return delivered;
        }
    };
    let read_dir = match std::fs::read_dir(bgjobs_home) {
        Ok(d) => d,
        Err(_) => return delivered, // dir not yet created = no pending results
    };
    for entry in read_dir.take(4_096).flatten() {
        let path = entry.path();
        let fname = match path.file_name().and_then(|f| f.to_str()) {
            Some(f) => f.to_string(),
            None => continue,
        };

        // Only process `.result` files.
        let Some(id) = fname.strip_suffix(".result") else {
            continue;
        };
        if !valid_background_id(id) {
            continue;
        }

        let exit_path = bgjobs_home.join(format!("{id}.exit"));
        let delivered_path = bgjobs_home.join(format!("{id}.delivered"));
        let delivering_path = bgjobs_home.join(format!("{id}.delivering"));

        // Not done yet.
        if !exit_path.exists() {
            continue;
        }
        // Already delivered.
        if delivered_path.exists() {
            continue;
        }

        if delivering_path.exists() {
            let live_claim = crate::updater::self_update::read_private_control_file_bounded(
                instance_home,
                &delivering_path,
                BG_CONTROL_MAX_BYTES,
                "background delivery claim",
            )
            .ok()
            .and_then(|bytes| serde_json::from_slice::<BgDeliveryClaim>(&bytes).ok())
            .is_some_and(|claim| {
                claim.schema_version == BG_JOB_SCHEMA_VERSION
                    && claim.job_id == id
                    && crate::time::now_unix_i64().saturating_sub(claim.claimed_unix)
                        < BG_DELIVERY_CLAIM_RECOVERY_SECS
                    && live_process_snapshot(claim.process_pid)
                        .is_ok_and(|live| live.process_start_unix == claim.process_start_unix)
            });
            if live_claim {
                continue;
            }
            if let Err(error) = crate::util::atomic_write::durable_remove_file(&delivering_path) {
                warn!(id, %error, "bg_session: failed to recover stale delivery claim");
                continue;
            }
        }
        let claim = BgDeliveryClaim {
            schema_version: BG_JOB_SCHEMA_VERSION,
            job_id: id.to_owned(),
            process_pid: process.pid,
            process_start_unix: process.process_start_unix,
            claimed_unix: crate::time::now_unix_i64(),
        };
        let claim_bytes = match serde_json::to_vec(&claim) {
            Ok(bytes) => bytes,
            Err(error) => {
                warn!(id, %error, "bg_session: failed to serialize delivery claim");
                continue;
            }
        };
        match crate::util::atomic_write::write_private_create_new_durable(
            &delivering_path,
            &claim_bytes,
        ) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                warn!(id, %error, "bg_session: failed to claim result delivery");
                continue;
            }
        }
        let text = crate::updater::self_update::read_private_control_file_bounded(
            instance_home,
            &path,
            BG_RESULT_MAX_BYTES,
            "background result",
        )
        .and_then(|bytes| String::from_utf8(bytes).context("background result is not UTF-8"));
        match text {
            Ok(text) => delivered.push(PendingBgDelivery {
                text: text.trim_end().to_owned(),
                delivering_path,
                delivered_path,
            }),
            Err(error) => {
                warn!(id, %error, "bg_session: failed to read bounded result file");
                let _ = crate::util::atomic_write::durable_remove_file(&delivering_path);
            }
        }
    }

    delivered
}

/// Best-effort WAL emission for background-session lifecycle events.
async fn emit_wal_bg(
    writer: &crate::wal::writer::WalWriterHandle,
    event_type: u8,
    job_id: &str,
    label: &str,
    prompt: &str,
) {
    // Prompt is hashed for privacy; the job_id + label land in the clear
    // so `neoth wal show --type bg_session_started` gives useful output.
    use std::hash::{Hash, Hasher};
    struct FnvHasher(u64);
    impl Hasher for FnvHasher {
        fn finish(&self) -> u64 {
            self.0
        }
        fn write(&mut self, bytes: &[u8]) {
            for &b in bytes {
                self.0 ^= u64::from(b);
                self.0 = self.0.wrapping_mul(0x00000100_000001b3);
            }
        }
    }
    impl Default for FnvHasher {
        fn default() -> Self {
            Self(0xcbf2_9ce4_8422_2325)
        }
    }
    let mut h = FnvHasher::default();
    prompt.hash(&mut h);
    let prompt_hash = format!("{:016x}", h.finish());

    let payload = match serde_json::to_vec(&serde_json::json!({
        "job_id": job_id,
        "label": label,
        "prompt_hash": prompt_hash,
        "ts_unix": crate::time::now_unix_secs(),
    })) {
        Ok(v) => v,
        Err(_) => return,
    };
    let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
    if let Err(e) = writer.append(header, payload).await {
        warn!(error = %e, event_type = event_type, "bg_session: WAL append failed (best-effort)");
    }
}

async fn emit_wal_bg_done(writer: &crate::wal::writer::WalWriterHandle, job_id: &str, label: &str) {
    match serde_json::to_vec(&serde_json::json!({
        "job_id": job_id,
        "label": label,
        "ts_unix": crate::time::now_unix_secs(),
    })) {
        Ok(payload) => {
            let header =
                crate::wal::HeaderBuilder::new(EVENT_TYPE_BG_SESSION_DONE, &payload).build();
            if let Err(error) = writer.append(header, payload).await {
                warn!(%error, "bg_session: BG_SESSION_DONE append failed (best-effort)");
            }
        }
        Err(error) => warn!(%error, "bg_session: BG_SESSION_DONE serialization failed"),
    }
}

/// Convenience: build the result-file path for a given job id and
/// bgjobs home. Used in tests to inspect output without going through
/// the delivery scan.
pub fn result_path_for(bgjobs_home: &Path, job_id: &BgJobId) -> PathBuf {
    bgjobs_home.join(format!("{}.result", job_id.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    // ── Minimal mock provider ─────────────────────────────────────────
    struct MockProvider {
        reply: String,
    }

    impl MockProvider {
        fn new(reply: &str) -> Self {
            Self {
                reply: reply.to_string(),
            }
        }
    }

    #[async_trait::async_trait]
    impl Provider for MockProvider {
        fn name(&self) -> &'static str {
            "mock"
        }
        fn default_model(&self) -> Option<&str> {
            Some("mock-model")
        }
        async fn complete(&self, _req: Request) -> Result<crate::providers::Completion> {
            Ok(crate::providers::Completion {
                text: self.reply.clone(),
                identity: Default::default(),
                model: "mock".to_string(),
                latency: std::time::Duration::ZERO,
                input_tokens: None,
                output_tokens: None,
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
    }

    // ── BgJobId uniqueness ────────────────────────────────────────────

    #[test]
    fn bg_job_id_is_16_hex_chars() {
        let id = BgJobId::new().unwrap();
        assert_eq!(id.as_str().len(), 16);
        assert!(
            id.as_str().chars().all(|c| c.is_ascii_hexdigit()),
            "BgJobId must be hex: {}",
            id.as_str()
        );
    }

    #[test]
    fn bg_job_ids_are_distinct() {
        let a = BgJobId::new().unwrap();
        let b = BgJobId::new().unwrap();
        assert_ne!(a.as_str(), b.as_str(), "OS-random job ids must be unique");
    }

    #[test]
    fn capability_canonical_json_is_independent_of_hashmap_iteration_order() {
        let mut first = std::collections::HashMap::new();
        first.insert("alpha", 1_u8);
        first.insert("beta", 2_u8);
        let mut second = std::collections::HashMap::new();
        second.insert("beta", 2_u8);
        second.insert("alpha", 1_u8);

        assert_eq!(
            canonical_json_sha256(&first, "first map").unwrap(),
            canonical_json_sha256(&second, "second map").unwrap()
        );
    }

    fn exact_test_request() -> Request {
        Request {
            prompt: "do the queued work".to_owned(),
            system: Some("protected system".to_owned()),
            model: Some("claude-sonnet-4-20250514".to_owned()),
            temperature: Some(0.2),
            top_p: Some(0.9),
            sampling_seed: Some(7),
            stop_sequences: vec!["STOP".to_owned()],
            thinking_budget: Some(1_024),
        }
    }

    const TEST_APPROVAL_KEY: [u8; BG_APPROVAL_KEY_BYTES] = [0x5a; BG_APPROVAL_KEY_BYTES];
    const TEST_QUEUED_UNIX: i64 = 1_700_000_000;

    fn test_config_path() -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(r"C:\neoth-test\freedom.yaml")
        } else {
            PathBuf::from("/tmp/neoth-test/freedom.yaml")
        }
    }

    fn test_launcher() -> BgLauncherIdentity {
        BgLauncherIdentity {
            pid: 42,
            process_start_unix: 123,
            executable_sha256: "11".repeat(32),
            role: BgLauncherRole::Chat,
        }
    }

    fn mint_test_approval(
        id: &BgJobId,
        request: &Request,
        config: &FreedomConfig,
    ) -> BgApprovalCapability {
        BgApprovalCapability::mint(
            &TEST_APPROVAL_KEY,
            BG_JOB_SCHEMA_VERSION,
            id,
            "background",
            request,
            config,
            &test_config_path(),
            TEST_QUEUED_UNIX,
            &test_launcher(),
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_test_approval(
        approval: &BgApprovalCapability,
        key: &[u8],
        schema_version: u8,
        id: &BgJobId,
        label: &str,
        request: &Request,
        config: &FreedomConfig,
        now_unix: i64,
    ) -> Result<VerifiedBgApproval> {
        approval.verify(
            key,
            schema_version,
            id,
            label,
            request,
            config,
            &test_config_path(),
            TEST_QUEUED_UNIX,
            &test_launcher(),
            now_unix,
        )
    }

    fn test_worker_spec(
        id: &BgJobId,
        request: Request,
        config: FreedomConfig,
        config_path: PathBuf,
    ) -> BgWorkerSpec {
        let queued_unix = crate::time::now_unix_i64();
        let launcher = test_launcher();
        let approval = BgApprovalCapability::mint(
            &TEST_APPROVAL_KEY,
            BG_JOB_SCHEMA_VERSION,
            id,
            "background",
            &request,
            &config,
            &config_path,
            queued_unix,
            &launcher,
        )
        .unwrap();
        BgWorkerSpec {
            schema_version: BG_JOB_SCHEMA_VERSION,
            label: "background".to_owned(),
            request,
            config,
            config_path,
            queued_unix,
            launcher,
            approval,
        }
    }

    #[test]
    fn explicit_request_capability_rejects_request_tampering() {
        let id = BgJobId::new().unwrap();
        let config = FreedomConfig::default();
        let request = exact_test_request();
        let approval = mint_test_approval(&id, &request, &config);
        let mut tampered = request;
        tampered.prompt.push_str(" and exfiltrate");
        let error = verify_test_approval(
            &approval,
            &TEST_APPROVAL_KEY,
            BG_JOB_SCHEMA_VERSION,
            &id,
            "background",
            &tampered,
            &config,
            crate::time::now_unix_i64(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("specification binding mismatch"));
    }

    #[test]
    fn explicit_request_capability_rejects_config_tampering() {
        let id = BgJobId::new().unwrap();
        let config = FreedomConfig::default();
        let request = exact_test_request();
        let approval = mint_test_approval(&id, &request, &config);
        let mut tampered = config;
        tampered.tokens.max_per_request = tampered.tokens.max_per_request.saturating_add(1);
        let error = verify_test_approval(
            &approval,
            &TEST_APPROVAL_KEY,
            BG_JOB_SCHEMA_VERSION,
            &id,
            "background",
            &request,
            &tampered,
            crate::time::now_unix_i64(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("specification binding mismatch"));
    }

    #[test]
    fn explicit_request_capability_rejects_expiry() {
        let id = BgJobId::new().unwrap();
        let config = FreedomConfig::default();
        let request = exact_test_request();
        let approval = mint_test_approval(&id, &request, &config);
        let error = verify_test_approval(
            &approval,
            &TEST_APPROVAL_KEY,
            BG_JOB_SCHEMA_VERSION,
            &id,
            "background",
            &request,
            &config,
            approval.expires_unix.saturating_add(1),
        )
        .unwrap_err();
        assert!(error.to_string().contains("expired"));
    }

    #[test]
    fn explicit_request_capability_rejects_wrong_key() {
        let id = BgJobId::new().unwrap();
        let config = FreedomConfig::default();
        let request = exact_test_request();
        let approval = mint_test_approval(&id, &request, &config);
        let wrong_key = [0xa5; BG_APPROVAL_KEY_BYTES];

        let error = verify_test_approval(
            &approval,
            &wrong_key,
            BG_JOB_SCHEMA_VERSION,
            &id,
            "background",
            &request,
            &config,
            crate::time::now_unix_i64(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("MAC mismatch"));
    }

    #[test]
    fn explicit_request_capability_serialization_never_contains_signing_key() {
        let id = BgJobId::new().unwrap();
        let config = FreedomConfig::default();
        let request = exact_test_request();
        let approval = mint_test_approval(&id, &request, &config);
        let serialized = serde_json::to_string(&approval).unwrap();

        assert!(!serialized.contains(&hex::encode(TEST_APPROVAL_KEY)));
        assert!(!serialized.contains("approval_key"));
    }

    #[test]
    fn recomputed_plain_hashes_cannot_mint_explicit_request_capability() {
        let id = BgJobId::new().unwrap();
        let config = FreedomConfig::default();
        let request = exact_test_request();
        let mut forged = mint_test_approval(&id, &request, &config);
        let mut tampered = request;
        tampered.prompt.push_str(" and bypass authorization");

        // An attacker controlling only the job can recompute every public
        // digest and the old unkeyed binding. That must still not produce a
        // capability accepted under the one-shot per-job secret key.
        forged.spec_sha256 = signed_spec_sha256(
            BG_JOB_SCHEMA_VERSION,
            "background",
            &tampered,
            &config,
            &test_config_path(),
            TEST_QUEUED_UNIX,
            &test_launcher(),
        )
        .unwrap();
        let public_binding = capability_binding_bytes(
            BG_JOB_SCHEMA_VERSION,
            id.as_str(),
            forged.expires_unix,
            &forged.nonce_hex,
            &forged.spec_sha256,
        );
        forged.mac_sha256 = hex::encode(Sha256::digest(public_binding.as_slice()));

        let error = verify_test_approval(
            &forged,
            &TEST_APPROVAL_KEY,
            BG_JOB_SCHEMA_VERSION,
            &id,
            "background",
            &tampered,
            &config,
            crate::time::now_unix_i64(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("MAC mismatch"));
    }

    #[test]
    fn explicit_request_capability_binds_job_schema() {
        let id = BgJobId::new().unwrap();
        let config = FreedomConfig::default();
        let request = exact_test_request();
        let approval = mint_test_approval(&id, &request, &config);

        let error = verify_test_approval(
            &approval,
            &TEST_APPROVAL_KEY,
            BG_JOB_SCHEMA_VERSION.saturating_add(1),
            &id,
            "background",
            &request,
            &config,
            crate::time::now_unix_i64(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("specification binding mismatch"));
    }

    #[test]
    fn explicit_request_capability_binds_job_label_expiry_and_nonce() {
        let id = BgJobId::new().unwrap();
        let other_id = BgJobId::new().unwrap();
        let config = FreedomConfig::default();
        let request = exact_test_request();
        let approval = mint_test_approval(&id, &request, &config);
        let now = crate::time::now_unix_i64();

        for (candidate, candidate_id, candidate_label, expected_error) in [
            (approval.clone(), &other_id, "background", "MAC mismatch"),
            (
                approval.clone(),
                &id,
                "btw",
                "specification binding mismatch",
            ),
            (
                BgApprovalCapability {
                    expires_unix: approval.expires_unix.saturating_add(1),
                    ..approval.clone()
                },
                &id,
                "background",
                "MAC mismatch",
            ),
            (
                BgApprovalCapability {
                    nonce_hex: format!(
                        "{}{}",
                        if approval.nonce_hex.starts_with('0') {
                            '1'
                        } else {
                            '0'
                        },
                        &approval.nonce_hex[1..]
                    ),
                    ..approval.clone()
                },
                &id,
                "background",
                "MAC mismatch",
            ),
        ] {
            let error = verify_test_approval(
                &candidate,
                &TEST_APPROVAL_KEY,
                BG_JOB_SCHEMA_VERSION,
                candidate_id,
                candidate_label,
                &request,
                &config,
                now,
            )
            .unwrap_err();
            assert!(
                error.to_string().contains(expected_error),
                "expected {expected_error:?}, got {error:#}"
            );
        }
    }

    #[test]
    fn approval_key_pipe_requires_exactly_32_bytes_and_eof() {
        let exact = read_background_approval_key(&mut std::io::Cursor::new(TEST_APPROVAL_KEY))
            .expect("exact key plus EOF is accepted");
        assert_eq!(*exact, TEST_APPROVAL_KEY);

        let mut short = std::io::Cursor::new(&TEST_APPROVAL_KEY[..BG_APPROVAL_KEY_BYTES - 1]);
        let short_error = read_background_approval_key(&mut short).unwrap_err();
        assert!(short_error.to_string().contains("read exact"));

        let mut trailing = TEST_APPROVAL_KEY.to_vec();
        trailing.push(0xff);
        let trailing_error =
            read_background_approval_key(&mut std::io::Cursor::new(trailing)).unwrap_err();
        assert!(trailing_error.to_string().contains("trailing data"));
    }

    #[test]
    fn background_job_claim_is_one_shot() {
        let temp = tempfile::tempdir().unwrap();
        let claimed = temp.path().join("0123456789abcdef.claimed");
        let claim = BgClaimRecord {
            schema_version: BG_JOB_SCHEMA_VERSION,
            job_id: "0123456789abcdef".to_owned(),
            spec_sha256: "22".repeat(32),
            worker_pid: std::process::id(),
            worker_start_unix: 1,
            worker_executable_sha256: "33".repeat(32),
            claimed_unix: crate::time::now_unix_i64(),
            mac_sha256: "44".repeat(32),
        };
        let sync_attempts_before =
            crate::util::atomic_write::create_new_parent_sync_attempts_for_test();
        claim_background_job(&claimed, &claim).unwrap();
        let sync_attempts_after =
            crate::util::atomic_write::create_new_parent_sync_attempts_for_test();
        assert!(
            sync_attempts_after > sync_attempts_before,
            "claim tombstone must pass through the durable parent-sync commit helper"
        );
        let error = claim_background_job(&claimed, &claim).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("claim background job exactly once")
        );
    }

    #[test]
    fn detached_worker_command_contains_only_private_job_path() {
        let executable = std::path::Path::new("neoth-test-binary");
        let job = std::path::Path::new("C:/private/bgjobs/0123456789abcdef.job");
        let command = background_worker_command(executable, job);
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            [
                "--output",
                "json",
                "internal",
                "background-worker",
                "--job",
                "C:/private/bgjobs/0123456789abcdef.job",
            ]
        );
        assert!(!args.iter().any(|arg| arg.contains("do the queued work")));
        assert!(
            command.get_envs().next().is_none(),
            "approval key must not be placed in an explicit child environment entry"
        );
    }

    #[tokio::test]
    async fn preconfirmed_gate_never_overrides_a_policy_deny() {
        let gate = crate::permissions::Gate::for_level(crate::permissions::AutonomyLevel::Standard)
            .with_preconfirmed_confirmation("explicit_request_capability");
        let action = crate::permissions::Action::SelfSourceEdit {
            target_paths: vec!["src/lib.rs".to_owned()],
        };
        let error = gate.check(&action, None).await.unwrap_err();
        assert!(matches!(
            error,
            crate::permissions::gate::GateError::Denied(_)
        ));
    }

    #[tokio::test]
    async fn unauthenticated_modified_job_cannot_burn_the_valid_claim() {
        let temp = tempfile::tempdir().unwrap();
        let bgjobs = temp.path().join("bgjobs");
        std::fs::create_dir_all(&bgjobs).unwrap();
        let config = FreedomConfig::default();
        let request = exact_test_request();
        let id = BgJobId::new().unwrap();
        let config_path = temp.path().join("freedom.yaml");
        let mut spec = test_worker_spec(&id, request, config, config_path);
        spec.request.prompt.push_str(" and tamper after approval");
        let job = bgjobs.join(format!("{}.job", id.as_str()));
        let job_bytes = serde_json::to_vec(&spec).unwrap();
        crate::util::atomic_write::write_private_create_new_durable(&job, &job_bytes).unwrap();

        let error = run_background_worker_with_key_and_attestor(
            &job,
            zeroize::Zeroizing::new(TEST_APPROVAL_KEY),
            |_| Ok(()),
            false,
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("specification binding mismatch"));
        assert!(!bgjobs.join(format!("{}.claimed", id.as_str())).exists());
        assert!(!bgjobs.join(format!("{}.result", id.as_str())).exists());
        assert!(
            job.exists(),
            "failed authentication must not consume the job"
        );
    }

    #[tokio::test]
    async fn worker_rechecks_consent_before_provider_construction() {
        let temp = tempfile::tempdir().unwrap();
        let bgjobs = temp.path().join("bgjobs");
        std::fs::create_dir_all(&bgjobs).unwrap();
        let mut config = FreedomConfig::default();
        config.provider_kind = Some(crate::cli::init::ProviderKind::ClaudeCli);
        let config_path = temp.path().join("freedom.yaml");
        crate::util::atomic_write::atomic_write_private(
            &config_path,
            config.public_yaml().unwrap().as_bytes(),
        )
        .unwrap();
        let request = exact_test_request();
        let id = BgJobId::new().unwrap();
        let spec = test_worker_spec(&id, request, config, config_path);
        let job = bgjobs.join(format!("{}.job", id.as_str()));
        let job_bytes = serde_json::to_vec(&spec).unwrap();
        crate::util::atomic_write::write_private_create_new_durable(&job, &job_bytes).unwrap();

        let completed = run_background_worker_with_key_and_attestor(
            &job,
            zeroize::Zeroizing::new(TEST_APPROVAL_KEY),
            |_| Ok(()),
            false,
        )
        .await
        .unwrap();
        assert_eq!(completed.as_str(), id.as_str());
        let result =
            std::fs::read_to_string(bgjobs.join(format!("{}.result", id.as_str()))).unwrap();
        assert!(result.contains("consent for provider `claude_cli` was revoked"));
        assert!(bgjobs.join(format!("{}.claimed", id.as_str())).exists());
        assert!(!job.exists());

        crate::util::atomic_write::write_private_create_new_durable(&job, &job_bytes).unwrap();
        let replay_error = run_background_worker_with_key_and_attestor(
            &job,
            zeroize::Zeroizing::new(TEST_APPROVAL_KEY),
            |_| Ok(()),
            false,
        )
        .await
        .unwrap_err();
        assert!(
            replay_error
                .to_string()
                .contains("claim background job exactly once")
        );
    }

    // ── result_path_for ───────────────────────────────────────────────

    #[test]
    fn result_path_for_builds_correct_path() {
        let dir = std::path::Path::new("/tmp/test_bgjobs");
        let id = BgJobId("abc123".to_string());
        let p = result_path_for(dir, &id);
        assert_eq!(p, dir.join("abc123.result"));
    }

    // ── maybe_deliver_bg_result ───────────────────────────────────────

    fn write_ready_result(dir: &Path, id: &BgJobId, text: &[u8]) {
        crate::util::atomic_write::atomic_write_private(
            &dir.join(format!("{}.result", id.as_str())),
            text,
        )
        .unwrap();
        crate::util::atomic_write::atomic_write_private(
            &dir.join(format!("{}.exit", id.as_str())),
            b"done\n",
        )
        .unwrap();
    }

    #[tokio::test]
    async fn deliver_returns_empty_when_dir_missing() {
        let dir = std::path::Path::new("/nonexistent_bgjobs_dir_test");
        let results = maybe_deliver_bg_result(dir).await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn deliver_returns_empty_when_no_exit_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let id = BgJobId::new().unwrap();
        // Write result but NO .exit — should not be delivered yet.
        crate::util::atomic_write::atomic_write_private(
            &tmp.path().join(format!("{}.result", id.as_str())),
            b"hello",
        )
        .unwrap();
        let results = maybe_deliver_bg_result(tmp.path()).await;
        assert!(results.is_empty(), "no exit marker = not ready");
    }

    #[tokio::test]
    async fn deliver_returns_result_when_exit_present() {
        let tmp = tempfile::tempdir().unwrap();
        let id = BgJobId::new().unwrap();
        write_ready_result(tmp.path(), &id, b"background-answer");

        let mut results = maybe_deliver_bg_result(tmp.path()).await;
        assert_eq!(results.len(), 1);
        let result = results.pop().unwrap();
        assert_eq!(result.text(), "background-answer");
        result.acknowledge().unwrap();
    }

    #[tokio::test]
    async fn deliver_is_idempotent_via_delivered_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let id = BgJobId::new().unwrap();
        write_ready_result(tmp.path(), &id, b"once");

        let mut r1 = maybe_deliver_bg_result(tmp.path()).await;
        assert_eq!(r1.len(), 1);
        r1.pop().unwrap().acknowledge().unwrap();

        // Second call sees the .delivered marker and returns nothing.
        let r2 = maybe_deliver_bg_result(tmp.path()).await;
        assert!(r2.is_empty(), "second delivery must be idempotent");
    }

    #[tokio::test]
    async fn deliver_trims_trailing_whitespace() {
        let tmp = tempfile::tempdir().unwrap();
        let id = BgJobId::new().unwrap();
        write_ready_result(tmp.path(), &id, b"answer\n\n");

        let mut results = maybe_deliver_bg_result(tmp.path()).await;
        let result = results.pop().unwrap();
        assert_eq!(result.text(), "answer");
        result.acknowledge().unwrap();
    }

    // ── spawn_background_session integration ──────────────────────────

    #[test]
    fn background_session_resolves_the_exact_wire_model_before_signing() {
        let provider: Arc<dyn Provider> = Arc::new(MockProvider::new("the-answer"));
        let config = FreedomConfig::default();
        let mut request = build_bg_request("test prompt", &config, None);
        request.model = Some(
            crate::providers::resolve_configured_request_model_for_wire(
                &config,
                provider.as_ref(),
                request.model.as_deref(),
            )
            .unwrap(),
        );
        assert!(
            request
                .model
                .as_deref()
                .is_some_and(|model| !model.is_empty())
        );
    }

    #[test]
    fn background_request_preserves_the_originating_system_contract() {
        let config = FreedomConfig::default();
        let system = concat!(
            "<communication_preferences authority=\"presentation_only\">\n",
            "- Be direct.\n",
            "</communication_preferences>"
        )
        .to_owned();
        let request = build_bg_request("test prompt", &config, Some(system.clone()));
        assert_eq!(request.system.as_deref(), Some(system.as_str()));
    }

    #[tokio::test]
    async fn spawn_and_deliver_end_to_end() {
        // Full integration: spawn → wait for exit marker → deliver.
        let dir = tempfile::tempdir().unwrap();

        // Write the result + exit markers manually to simulate the spawn
        // task completing (we can't redirect FreedomConfig::default_neoth_home
        // to dir without a process-wide env change).
        let id = BgJobId("deadbeef1234abcd".to_string());
        write_ready_result(dir.path(), &id, b"end-to-end-result");

        let mut results = maybe_deliver_bg_result(dir.path()).await;
        assert_eq!(results.len(), 1, "result should be delivered");
        let result = results.pop().unwrap();
        assert!(result.text().contains("end-to-end-result"));
        result.acknowledge().unwrap();

        // Idempotent.
        let r2 = maybe_deliver_bg_result(dir.path()).await;
        assert!(r2.is_empty());
    }

    #[tokio::test]
    async fn multiple_pending_results_all_delivered() {
        let tmp = tempfile::tempdir().unwrap();
        for suffix in ["aaa", "bbb", "ccc"] {
            let id = format!("{suffix:0<16}");
            write_ready_result(
                tmp.path(),
                &BgJobId(id),
                format!("result-{suffix}").as_bytes(),
            );
        }
        let results = maybe_deliver_bg_result(tmp.path()).await;
        let mut texts = results
            .iter()
            .map(|result| result.text().to_owned())
            .collect::<Vec<_>>();
        texts.sort();
        assert_eq!(results.len(), 3);
        assert!(texts.iter().any(|result| result == "result-aaa"));
        assert!(texts.iter().any(|result| result == "result-bbb"));
        assert!(texts.iter().any(|result| result == "result-ccc"));
        for result in results {
            result.acknowledge().unwrap();
        }
    }
}
