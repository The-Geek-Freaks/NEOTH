//! Local, operator-directed transfer of secret-bearing files.
//!
//! Secret bytes stay on the local data plane: they never enter an LLM prompt,
//! argv, structured logs, the replay store, or the terminal report.
//! Every effect is bracketed by an owner-private authenticated journal. A
//! restart reconciles the exact destination against keyed source/content/plan
//! bindings before either reporting success or starting a fresh permit.

use std::ffi::{OsStr, OsString};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::fs::OpenOptions;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::secret_transfer::{
    CommandOrigin, DeliveryReceipt, DestinationBinding, OperatorCommand, OperatorPrincipal,
    PermitConsumptionError, PermitConsumptionRecord, PermitConsumptionStore, SecretPayload,
    SourceBinding, TransferAuthority, TransferFailureReason, TransferNonce, TransferOperation,
    TransferPhase,
};
use crate::skills::store::{
    BoundDirectory, DirectorySyncOutcome, atomic_write_private_child,
    atomic_write_private_child_create_new, create_private_regular_file_child_create_new,
    open_bound_directory, open_bound_directory_from_trusted_anchor, open_bound_regular_file,
    open_bound_regular_file_readwrite, open_or_create_private_child_dir, sync_parent_directory,
};

const MAX_LOCAL_SECRET_FILE_BYTES: u64 = 64 * 1024 * 1024;
const PERMIT_LIFETIME_SECONDS: i64 = 60;
const MAX_TRANSFER_JOURNAL_BYTES: u64 = 32 * 1024;
const TRANSFER_JOURNAL_SCHEMA_VERSION: u32 = 2;
const REPLAY_TOMBSTONE_DOMAIN: &[u8] = b"neoth.secret-transfer.replay-tombstone.v1";
const DESTINATION_BINDING_DOMAIN: &[u8] = b"neoth.secret-transfer.local-destination.v1";
const SOURCE_BINDING_DOMAIN: &[u8] = b"neoth.secret-transfer.local-source.v1";
const INTENT_BINDING_DOMAIN: &[u8] = b"neoth.secret-transfer.local-intent.v1";
const CONTENT_BINDING_DOMAIN: &[u8] = b"neoth.secret-transfer.local-content.v1";
const DESTINATION_OBJECT_BINDING_DOMAIN: &[u8] =
    b"neoth.secret-transfer.local-destination-object.v1";
const JOURNAL_AUTH_DOMAIN: &[u8] = b"neoth.secret-transfer.journal-auth.v1";
const DELIVERY_EVIDENCE_DOMAIN: &[u8] = b"neoth.secret-transfer.local-delivery.v1";
const CONSUMED_MARKER: &[u8] = b"neoth-secret-transfer-consumed-v1\n";
const TRANSFER_LOCK_MARKER: &[u8] = b"neoth-secret-transfer-lock-v1\n";
const TRANSFER_LOCK_NAME: &str = ".transfer.lock";
const LOCK_RETRY_EVERY: Duration = Duration::from_millis(25);
const LOCK_GIVE_UP_AFTER: Duration = Duration::from_secs(5);
const TRANSFER_AUTHORITY_KEY_NAME: &str = "authority.key";
const TRANSFER_AUTHORITY_KEY_BYTES: usize = 32;
const COPY_SUCCESS_WITH_DURABLE_NAMESPACE: &str = "Credential copy succeeded: destination data and namespace durability were live-verified; source preserved.";
const COPY_SUCCESS_WITH_UNSUPPORTED_NAMESPACE: &str = "Credential copy succeeded: destination data were live-verified; this platform cannot confirm parent-directory power-loss durability; source preserved.";

#[derive(Debug, Serialize)]
struct FileTransferReport {
    operation: &'static str,
    phase: TransferPhase,
    plan_fingerprint: String,
    byte_len: u64,
    delivered_at_unix: i64,
    live_destination_verified: bool,
    namespace_durability: NamespaceDurability,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum NamespaceDurability {
    Confirmed,
    Unsupported,
}

impl From<DirectorySyncOutcome> for NamespaceDurability {
    fn from(value: DirectorySyncOutcome) -> Self {
        match value {
            DirectorySyncOutcome::Confirmed => Self::Confirmed,
            DirectorySyncOutcome::Unsupported => Self::Unsupported,
        }
    }
}

struct BoundFilePath {
    parent: BoundDirectory,
    name: OsString,
    display_path: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FileCopyCheckpoint {
    AfterPlannedJournal,
    AfterExecutionStarted,
    BeforeDestinationPublish,
    AfterDestinationPublish,
}

#[derive(Clone, Debug)]
struct JournalBindings {
    intent: [u8; 32],
    source: [u8; 32],
    destination: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferJournalEnvelope {
    journal: TransferJournal,
    authentication_tag: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferJournal {
    schema_version: u32,
    operation: TransferOperation,
    nonce: String,
    plan_fingerprint: String,
    source_binding: String,
    destination_binding: String,
    content_binding: String,
    #[serde(default)]
    destination_object_binding: Option<String>,
    #[serde(default)]
    destination_namespace_durability: Option<NamespaceDurability>,
    byte_len: u64,
    state: TransferJournalState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
enum TransferJournalState {
    Planned {
        created_at_unix: i64,
    },
    Executing {
        started_at_unix: i64,
    },
    Delivered {
        delivered_at_unix: i64,
    },
    Failed {
        failed_at_unix: i64,
        reason: JournalFailureReason,
    },
    Indeterminate {
        marked_at_unix: i64,
        reason: JournalIndeterminateReason,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum JournalFailureReason {
    Authorization,
    SourceChanged,
    DestinationRejected,
    Transport,
    ProcessInterruptedBeforeEffect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum JournalIndeterminateReason {
    DestinationMismatch,
    PreviouslyDeliveredDestinationMissing,
    DeliveryOutcomeUnknown,
}

struct TransferJournalStore {
    directory: BoundDirectory,
}

struct TransferJournalLock {
    _file: std::fs::File,
}

enum DestinationObservation {
    Absent,
    Matching { identity_token: String },
    Mismatching,
}

enum ExistingJournalDecision {
    Delivered(FileTransferReport),
    StartFresh { replace_existing: bool },
}

impl TransferJournalStore {
    fn open(home: &Path) -> Result<Self> {
        let path = home.join("secret-transfers").join("journal");
        let directory = open_private_instance_directory(home, &path, "secret-transfer journal")?;
        Ok(Self { directory })
    }

    fn journal_name(bindings: &JournalBindings) -> OsString {
        OsString::from(format!("{}.json", hex::encode(bindings.intent)))
    }

    fn acquire_lock(&self) -> Result<TransferJournalLock> {
        let name = OsStr::new(TRANSFER_LOCK_NAME);
        let display_path = self.directory.display_path.join(name);
        match atomic_write_private_child_create_new(
            &self.directory.dir,
            name,
            &display_path,
            TRANSFER_LOCK_MARKER,
        ) {
            Ok(()) => {}
            Err(error) if error_has_io_kind(&error, std::io::ErrorKind::AlreadyExists) => {}
            Err(error) => return Err(error.context("create private secret-transfer lock file")),
        }

        let started = Instant::now();
        loop {
            match try_open_transfer_lock(&self.directory, name, &display_path)? {
                Some(file) => return Ok(TransferJournalLock { _file: file }),
                None if started.elapsed() < LOCK_GIVE_UP_AFTER => {
                    std::thread::sleep(LOCK_RETRY_EVERY);
                }
                None => {
                    anyhow::bail!(
                        "another local secret transfer held the journal lock for more than {}s",
                        LOCK_GIVE_UP_AFTER.as_secs()
                    );
                }
            }
        }
    }

    fn load(&self, name: &OsStr, root_key: &[u8]) -> Result<Option<TransferJournal>> {
        let display_path = self.directory.display_path.join(name);
        match self.directory.dir.symlink_metadata(name) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect transfer journal {}", display_path.display())
                });
            }
            Ok(metadata) if !metadata.is_file() => {
                anyhow::bail!(
                    "secret-transfer journal is not a regular file: {}",
                    display_path.display()
                );
            }
            Ok(_) => {}
        }

        let (mut file, binding) = open_bound_regular_file(&self.directory.dir, name, &display_path)
            .context("open exact secret-transfer journal generation")?;
        verify_private_journal_file(&file, &display_path)?;
        anyhow::ensure!(
            binding.matches_regular_file_child_readonly(
                &self.directory.dir,
                name,
                &display_path
            )?,
            "secret-transfer journal changed while it was being read"
        );
        let metadata = file
            .metadata()
            .context("inspect secret-transfer journal size")?;
        anyhow::ensure!(
            metadata.len() <= MAX_TRANSFER_JOURNAL_BYTES,
            "secret-transfer journal exceeds the {} byte limit",
            MAX_TRANSFER_JOURNAL_BYTES
        );
        let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
        std::io::Read::by_ref(&mut file)
            .take(MAX_TRANSFER_JOURNAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .context("read secret-transfer journal")?;
        anyhow::ensure!(
            u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_TRANSFER_JOURNAL_BYTES,
            "secret-transfer journal grew beyond its bounded read"
        );
        let envelope: TransferJournalEnvelope =
            serde_json::from_slice(&bytes).context("parse secret-transfer journal")?;
        let canonical =
            serde_json::to_vec(&envelope.journal).context("canonicalize transfer journal")?;
        let expected_tag = journal_authentication_tag(root_key, &canonical);
        let observed_tag = decode_hex_32(
            "secret-transfer journal authentication tag",
            &envelope.authentication_tag,
        )?;
        anyhow::ensure!(
            bool::from(expected_tag.ct_eq(&observed_tag)),
            "secret-transfer journal authentication failed"
        );
        validate_journal_shape(&envelope.journal)?;
        Ok(Some(envelope.journal))
    }

    fn persist(
        &self,
        name: &OsStr,
        journal: &TransferJournal,
        root_key: &[u8],
        create_new: bool,
    ) -> Result<()> {
        validate_journal_shape(journal)?;
        let canonical = serde_json::to_vec(journal).context("serialize transfer journal body")?;
        let envelope = TransferJournalEnvelope {
            journal: journal.clone(),
            authentication_tag: hex::encode(journal_authentication_tag(root_key, &canonical)),
        };
        let bytes =
            serde_json::to_vec(&envelope).context("serialize authenticated transfer journal")?;
        anyhow::ensure!(
            u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_TRANSFER_JOURNAL_BYTES,
            "serialized secret-transfer journal exceeds its bounded size"
        );
        let display_path = self.directory.display_path.join(name);
        if create_new {
            atomic_write_private_child_create_new(&self.directory.dir, name, &display_path, &bytes)
        } else {
            atomic_write_private_child(&self.directory.dir, name, &display_path, &bytes)
        }
        .context("durably persist authenticated secret-transfer journal")?;

        let persisted = self
            .load(name, root_key)?
            .context("authenticated secret-transfer journal disappeared after persistence")?;
        let persisted_canonical = serde_json::to_vec(&persisted)
            .context("canonicalize persisted secret-transfer journal")?;
        anyhow::ensure!(
            persisted_canonical == canonical,
            "authenticated secret-transfer journal changed during persistence"
        );
        Ok(())
    }
}

struct DurablePermitStore {
    directory: BoundDirectory,
}

impl DurablePermitStore {
    fn open(home: &Path) -> Result<Self> {
        let path = home.join("secret-transfers").join("consumed");
        let directory =
            open_private_instance_directory(home, &path, "secret-transfer replay store")?;
        Ok(Self { directory })
    }

    fn tombstone_name(nonce: TransferNonce) -> OsString {
        let mut digest = Sha256::new();
        digest.update(REPLAY_TOMBSTONE_DOMAIN);
        digest.update(nonce.as_bytes());
        OsString::from(format!("{}.used", hex::encode(digest.finalize())))
    }
}

fn open_private_instance_directory(
    home: &Path,
    target: &Path,
    label: &str,
) -> Result<BoundDirectory> {
    let absolute_home = std::path::absolute(home)
        .with_context(|| format!("resolve absolute NEOTH instance home {}", home.display()))?;
    let absolute_target = std::path::absolute(target)
        .with_context(|| format!("resolve absolute {label} path {}", target.display()))?;
    let relative_target = absolute_target
        .strip_prefix(&absolute_home)
        .with_context(|| {
            format!(
                "{label} must remain below NEOTH instance home {}: {}",
                absolute_home.display(),
                absolute_target.display()
            )
        })?;
    let trusted_parent = absolute_home.parent().with_context(|| {
        format!(
            "NEOTH instance home needs an existing parent anchor: {}",
            absolute_home.display()
        )
    })?;

    let mut current = open_bound_directory_from_trusted_anchor(
        trusted_parent,
        &absolute_home,
        true,
        "NEOTH instance home",
    )?
    .with_context(|| {
        format!(
            "open or create NEOTH instance home {}",
            absolute_home.display()
        )
    })?;
    harden_private_instance_directory(&current.dir, &current.display_path)?;

    for component in relative_target.components() {
        let std::path::Component::Normal(name) = component else {
            anyhow::bail!(
                "{label} contains a non-normal path component below NEOTH instance home: {}",
                absolute_target.display()
            );
        };
        let child_path = current.display_path.join(name);
        let child = open_or_create_private_child_dir(&current.dir, name, &child_path)
            .with_context(|| format!("open or create private {label} {}", child_path.display()))?;
        harden_private_instance_directory(&child, &child_path)?;
        current = BoundDirectory {
            dir: child,
            display_path: child_path,
        };
    }

    Ok(current)
}

fn harden_private_instance_directory(
    directory: &cap_std::fs::Dir,
    display_path: &Path,
) -> Result<()> {
    #[cfg(unix)]
    {
        use cap_std::fs::{MetadataExt as _, PermissionsExt as _};
        directory
            .set_permissions(".", cap_std::fs::Permissions::from_mode(0o700))
            .with_context(|| {
                format!(
                    "set owner-private permissions on NEOTH directory {}",
                    display_path.display()
                )
            })?;
        let metadata = directory.dir_metadata().with_context(|| {
            format!(
                "inspect owner-private NEOTH directory {}",
                display_path.display()
            )
        })?;
        anyhow::ensure!(
            metadata.is_dir() && metadata.mode() & 0o7777 == 0o700,
            "NEOTH directory is not an owner-private mode-0700 directory: {}",
            display_path.display()
        );
        // SAFETY: geteuid has no preconditions and does not retain a pointer.
        let effective_uid = unsafe { libc::geteuid() };
        anyhow::ensure!(
            metadata.uid() == effective_uid,
            "NEOTH directory is not owned by the effective user: {}",
            display_path.display()
        );
    }
    #[cfg(windows)]
    {
        crate::wal::win_native::set_private_current_user_directory_dacl_bound(
            display_path,
            directory,
        )
        .with_context(|| {
            format!(
                "set owner-private DACL on NEOTH directory {}",
                display_path.display()
            )
        })?;
        crate::wal::win_native::verify_private_directory_handle_dacl(directory).with_context(
            || {
                format!(
                    "verify owner-private DACL on NEOTH directory {}",
                    display_path.display()
                )
            },
        )?;
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (directory, display_path);
        anyhow::bail!("owner-private NEOTH directories are unsupported on this target");
    }
    Ok(())
}

fn read_bound_transfer_authority_key(directory: &BoundDirectory) -> Result<Vec<u8>> {
    let name = OsStr::new(TRANSFER_AUTHORITY_KEY_NAME);
    let display_path = directory.display_path.join(name);
    let (mut file, binding) = open_bound_regular_file(&directory.dir, name, &display_path)
        .with_context(|| {
            format!(
                "open secret-transfer authority key without following links {}",
                display_path.display()
            )
        })?;
    verify_private_local_file(&file, &display_path, "secret-transfer authority key")?;
    anyhow::ensure!(
        binding.matches_regular_file_child_readonly(&directory.dir, name, &display_path)?,
        "secret-transfer authority key changed while it was being bound: {}",
        display_path.display()
    );
    let metadata = file.metadata().with_context(|| {
        format!(
            "inspect secret-transfer authority key {}",
            display_path.display()
        )
    })?;
    anyhow::ensure!(
        usize::try_from(metadata.len()).unwrap_or(usize::MAX) == TRANSFER_AUTHORITY_KEY_BYTES,
        "secret-transfer authority key must contain exactly {} bytes: {}",
        TRANSFER_AUTHORITY_KEY_BYTES,
        display_path.display()
    );
    let mut body = Zeroizing::new(Vec::with_capacity(TRANSFER_AUTHORITY_KEY_BYTES));
    std::io::Read::by_ref(&mut file)
        .take(u64::try_from(TRANSFER_AUTHORITY_KEY_BYTES).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut body)
        .with_context(|| {
            format!(
                "read secret-transfer authority key {}",
                display_path.display()
            )
        })?;
    anyhow::ensure!(
        body.len() == TRANSFER_AUTHORITY_KEY_BYTES,
        "secret-transfer authority key changed length during its bounded read: {}",
        display_path.display()
    );
    anyhow::ensure!(
        binding.matches_regular_file_child_readonly(&directory.dir, name, &display_path)?,
        "secret-transfer authority key changed while it was being read: {}",
        display_path.display()
    );
    Ok(body.to_vec())
}

fn load_or_init_transfer_authority_key(home: &Path) -> Result<Vec<u8>> {
    let key_directory_path = home.join("secret-transfers");
    let directory = open_private_instance_directory(
        home,
        &key_directory_path,
        "secret-transfer authority directory",
    )?;
    let name = OsStr::new(TRANSFER_AUTHORITY_KEY_NAME);
    let display_path = directory.display_path.join(name);

    match directory.dir.symlink_metadata(name) {
        Ok(_) => return read_bound_transfer_authority_key(&directory),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "inspect secret-transfer authority key {}",
                    display_path.display()
                )
            });
        }
    }

    let mut generated = Zeroizing::new(vec![0u8; TRANSFER_AUTHORITY_KEY_BYTES]);
    getrandom::getrandom(generated.as_mut_slice()).context(
        "OS RNG unavailable - refusing to generate a weak secret-transfer authority key",
    )?;

    match atomic_write_private_child_create_new(
        &directory.dir,
        name,
        &display_path,
        generated.as_slice(),
    ) {
        Ok(()) => {}
        Err(error) if error_has_io_kind(&error, std::io::ErrorKind::AlreadyExists) => {
            return read_bound_transfer_authority_key(&directory)
                .context("load concurrently created secret-transfer authority key");
        }
        Err(error) => {
            return Err(error).context("create secret-transfer authority key without replacement");
        }
    }

    let installed = Zeroizing::new(
        read_bound_transfer_authority_key(&directory)
            .context("re-read newly created secret-transfer authority key")?,
    );
    anyhow::ensure!(
        installed.len() == generated.len()
            && bool::from(installed.as_slice().ct_eq(generated.as_slice())),
        "newly created secret-transfer authority key did not round-trip exactly"
    );
    Ok(generated.to_vec())
}

impl PermitConsumptionStore for DurablePermitStore {
    fn consume_once(
        &mut self,
        record: &PermitConsumptionRecord,
    ) -> Result<(), PermitConsumptionError> {
        let name = Self::tombstone_name(record.nonce);
        let display_path = self.directory.display_path.join(&name);
        match atomic_write_private_child_create_new(
            &self.directory.dir,
            &name,
            &display_path,
            CONSUMED_MARKER,
        ) {
            Ok(()) => Ok(()),
            Err(error) if error_has_io_kind(&error, std::io::ErrorKind::AlreadyExists) => {
                Err(PermitConsumptionError::Replay)
            }
            Err(_) => Err(PermitConsumptionError::Unavailable),
        }
    }
}

pub(crate) fn run_file_copy(source: &Path, destination: &Path, output: OutputFormat) -> Result<()> {
    let report = execute_file_copy_with_clock(
        &FreedomConfig::default_neoth_home(),
        source,
        destination,
        unix_now,
        |_| Ok(()),
    )?;

    match output {
        OutputFormat::Table => println!(
            "{}",
            human_copy_success_message(report.namespace_durability)
        ),
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string(&report)?);
        }
    }
    Ok(())
}

fn human_copy_success_message(namespace_durability: NamespaceDurability) -> &'static str {
    match namespace_durability {
        NamespaceDurability::Confirmed => COPY_SUCCESS_WITH_DURABLE_NAMESPACE,
        NamespaceDurability::Unsupported => COPY_SUCCESS_WITH_UNSUPPORTED_NAMESPACE,
    }
}

fn execute_file_copy_with_clock(
    home: &Path,
    source: &Path,
    destination: &Path,
    mut clock: impl FnMut() -> Result<i64>,
    mut checkpoint: impl FnMut(FileCopyCheckpoint) -> Result<()>,
) -> Result<FileTransferReport> {
    let source_path = bind_parent(source, "secret-transfer source")?;
    let destination_path = bind_parent(destination, "secret-transfer destination")?;

    let (mut source_file, source_object) = open_bound_regular_file(
        &source_path.parent.dir,
        &source_path.name,
        &source_path.display_path,
    )
    .context("open exact source generation")?;
    let initial_payload = read_bounded_payload(&mut source_file)?;
    let source_digest = initial_payload.digest();
    let byte_len = u64::try_from(initial_payload.len()).context("source length exceeds u64")?;
    drop(initial_payload);

    let transfer_key = Zeroizing::new(
        load_or_init_transfer_authority_key(home)
            .context("load bound secret-transfer authority key")?,
    );
    let authority = TransferAuthority::from_active_instance_hmac_key(transfer_key.as_slice())
        .context("derive local secret-transfer authority")?;
    let bindings = journal_bindings(
        transfer_key.as_slice(),
        &source_path.display_path,
        source_object.identity_token(),
        &destination_path.display_path,
        &source_digest,
        byte_len,
    );
    let journal_store = TransferJournalStore::open(home)?;
    let _journal_lock = journal_store.acquire_lock()?;
    let journal_name = TransferJournalStore::journal_name(&bindings);

    let replace_existing_journal =
        match journal_store.load(&journal_name, transfer_key.as_slice())? {
            Some(mut journal) => {
                let reconciled_at_unix = clock()
                    .context("read clock before reconciling an existing secret-transfer journal")?;
                match reconcile_existing_journal(
                    &journal_store,
                    &journal_name,
                    &mut journal,
                    &bindings,
                    transfer_key.as_slice(),
                    &destination_path,
                    &source_digest,
                    byte_len,
                    source_object.identity_token(),
                    reconciled_at_unix,
                )? {
                    ExistingJournalDecision::Delivered(report) => return Ok(report),
                    ExistingJournalDecision::StartFresh { replace_existing } => replace_existing,
                }
            }
            None => false,
        };
    ensure_destination_absent(&destination_path)?;

    let mut nonce_bytes = [0_u8; 32];
    getrandom::getrandom(&mut nonce_bytes)
        .context("OS RNG unavailable for one-shot secret-transfer permit")?;
    let nonce = TransferNonce::new(nonce_bytes);
    let request_id = uuid::Uuid::now_v7().simple().to_string();
    let session_id = format!("cli:{}", uuid::Uuid::now_v7().simple());
    let instance_id = local_instance_binding(home);
    let source_id = format!("local-file:{}", source_object.identity_token());
    let destination_id =
        local_destination_binding(transfer_key.as_slice(), &destination_path.display_path);
    let issued_at_unix = clock().context("read clock before issuing secret-transfer permit")?;
    let command = OperatorCommand::new(
        OperatorPrincipal::new_metadata("local-os-user", &session_id)?,
        CommandOrigin::new("cli", &instance_id, &session_id)?,
        format!("credential-copy:{request_id}"),
        SourceBinding::new(source_id, source_digest, byte_len)?,
        DestinationBinding::new("local-file", "local-os-user", destination_id)?,
        TransferOperation::Copy,
        issued_at_unix,
        issued_at_unix
            .checked_add(PERMIT_LIFETIME_SECONDS)
            .context("secret-transfer expiry overflow")?,
        nonce,
    )?;
    let plan = authority.authorize(command)?;
    let plan_fingerprint = *plan.fingerprint();
    let mut execution = plan.into_execution();
    let created_at_unix = clock().context("read clock before creating secret-transfer journal")?;
    let mut journal = TransferJournal {
        schema_version: TRANSFER_JOURNAL_SCHEMA_VERSION,
        operation: TransferOperation::Copy,
        nonce: hex::encode(nonce.as_bytes()),
        plan_fingerprint: hex::encode(plan_fingerprint),
        source_binding: hex::encode(bindings.source),
        destination_binding: hex::encode(bindings.destination),
        content_binding: hex::encode(content_binding(
            transfer_key.as_slice(),
            &plan_fingerprint,
            &source_digest,
            byte_len,
        )),
        destination_object_binding: None,
        destination_namespace_durability: None,
        byte_len,
        state: TransferJournalState::Planned { created_at_unix },
    };
    journal_store.persist(
        &journal_name,
        &journal,
        transfer_key.as_slice(),
        !replace_existing_journal,
    )?;
    checkpoint(FileCopyCheckpoint::AfterPlannedJournal)?;

    let mut permit_store = DurablePermitStore::open(home)?;
    let consumed_at_unix =
        clock().context("read clock immediately before consuming secret-transfer permit")?;
    if let Err(error) = execution.begin(&authority, &mut permit_store, consumed_at_unix) {
        let failed_at_unix =
            clock().context("read clock after secret-transfer authorization failure")?;
        journal.state = TransferJournalState::Failed {
            failed_at_unix,
            reason: JournalFailureReason::Authorization,
        };
        journal_store.persist(&journal_name, &journal, transfer_key.as_slice(), false)?;
        return Err(error).context("begin authenticated local secret transfer");
    }
    let started_at_unix = clock().context("read clock after consuming secret-transfer permit")?;
    journal.state = TransferJournalState::Executing { started_at_unix };
    journal_store.persist(&journal_name, &journal, transfer_key.as_slice(), false)?;
    checkpoint(FileCopyCheckpoint::AfterExecutionStarted)?;

    let source_identity_matches = match source_object.matches_regular_file_child_readonly(
        &source_path.parent.dir,
        &source_path.name,
        &source_path.display_path,
    ) {
        Ok(matches) => matches,
        Err(error) => {
            execution.fail(TransferFailureReason::Transport)?;
            let failed_at_unix =
                clock().context("read clock after source identity revalidation failure")?;
            journal.state = TransferJournalState::Failed {
                failed_at_unix,
                reason: JournalFailureReason::Transport,
            };
            journal_store.persist(&journal_name, &journal, transfer_key.as_slice(), false)?;
            return Err(error.context("revalidate exact source generation before copy"));
        }
    };
    if !source_identity_matches {
        execution.fail(TransferFailureReason::SourceChanged)?;
        let failed_at_unix = clock().context("read clock after source identity changed")?;
        journal.state = TransferJournalState::Failed {
            failed_at_unix,
            reason: JournalFailureReason::SourceChanged,
        };
        journal_store.persist(&journal_name, &journal, transfer_key.as_slice(), false)?;
        anyhow::bail!("source changed after authorization; nothing was copied");
    }

    let payload = match read_bounded_payload(&mut source_file) {
        Ok(payload) => payload,
        Err(error) => {
            execution.fail(TransferFailureReason::Transport)?;
            let failed_at_unix = clock().context("read clock after source read failure")?;
            journal.state = TransferJournalState::Failed {
                failed_at_unix,
                reason: JournalFailureReason::Transport,
            };
            journal_store.persist(&journal_name, &journal, transfer_key.as_slice(), false)?;
            return Err(error.context("re-read exact source generation before copy"));
        }
    };
    if payload.digest() != source_digest
        || u64::try_from(payload.len()).context("source length exceeds u64")? != byte_len
    {
        execution.fail(TransferFailureReason::SourceChanged)?;
        let failed_at_unix = clock().context("read clock after source content changed")?;
        journal.state = TransferJournalState::Failed {
            failed_at_unix,
            reason: JournalFailureReason::SourceChanged,
        };
        journal_store.persist(&journal_name, &journal, transfer_key.as_slice(), false)?;
        anyhow::bail!("source content changed after authorization; nothing was copied");
    }
    checkpoint(FileCopyCheckpoint::BeforeDestinationPublish)?;
    if let Err(error) = ensure_destination_absent(&destination_path) {
        let reconciled_at_unix =
            clock().context("read clock before reconciling destination rejection")?;
        return reconcile_failed_effect(
            error,
            &journal_store,
            &journal_name,
            &mut journal,
            &mut execution,
            transfer_key.as_slice(),
            &destination_path,
            &source_digest,
            byte_len,
            source_object.identity_token(),
            reconciled_at_unix,
        );
    }

    let (mut destination_file, destination_object) =
        match create_private_regular_file_child_create_new(
            &destination_path.parent.dir,
            &destination_path.name,
            &destination_path.display_path,
        ) {
            Ok(value) => value,
            Err(error) => {
                let reconciled_at_unix = clock()
                    .context("read clock before reconciling destination creation failure")?;
                return reconcile_failed_effect(
                    error.context("create private destination object"),
                    &journal_store,
                    &journal_name,
                    &mut journal,
                    &mut execution,
                    transfer_key.as_slice(),
                    &destination_path,
                    &source_digest,
                    byte_len,
                    source_object.identity_token(),
                    reconciled_at_unix,
                );
            }
        };
    let destination_object_binding = destination_object_binding(
        transfer_key.as_slice(),
        &plan_fingerprint,
        destination_object.identity_token(),
    );
    journal.destination_object_binding = Some(hex::encode(destination_object_binding));
    journal_store.persist(&journal_name, &journal, transfer_key.as_slice(), false)?;
    if !destination_object.matches_regular_file_child_readonly(
        &destination_path.parent.dir,
        &destination_path.name,
        &destination_path.display_path,
    )? {
        execution.mark_indeterminate(
            crate::secret_transfer::IndeterminateReason::DeliveryOutcomeUnknown,
        )?;
        let marked_at_unix = clock().context("read clock after destination identity changed")?;
        journal.state = TransferJournalState::Indeterminate {
            marked_at_unix,
            reason: JournalIndeterminateReason::DestinationMismatch,
        };
        journal_store.persist(&journal_name, &journal, transfer_key.as_slice(), false)?;
        anyhow::bail!("destination identity changed before the first secret byte");
    }
    let write_result = payload.expose_once(|bytes| {
        destination_file
            .write_all(bytes)
            .context("write direct private credential-copy destination")?;
        destination_file
            .sync_all()
            .context("sync direct private credential-copy destination")?;
        sync_parent_directory(
            &destination_path.parent.dir,
            destination_path
                .display_path
                .parent()
                .unwrap_or(&destination_path.display_path),
        )
        .context("sync direct credential-copy destination directory")
    });
    let _initial_namespace_sync = match write_result {
        Ok(outcome) => outcome,
        Err(error) => {
            let reconciled_at_unix =
                clock().context("read clock before reconciling destination publication failure")?;
            return reconcile_failed_effect(
                error.context("publish private destination file"),
                &journal_store,
                &journal_name,
                &mut journal,
                &mut execution,
                transfer_key.as_slice(),
                &destination_path,
                &source_digest,
                byte_len,
                source_object.identity_token(),
                reconciled_at_unix,
            );
        }
    };
    checkpoint(FileCopyCheckpoint::AfterDestinationPublish)?;

    let destination_observation = match observe_destination(
        &destination_path,
        &source_digest,
        byte_len,
        source_object.identity_token(),
    ) {
        Ok(observation) => observation,
        Err(error) => {
            execution.mark_indeterminate(
                crate::secret_transfer::IndeterminateReason::DeliveryOutcomeUnknown,
            )?;
            let marked_at_unix =
                clock().context("read clock after destination verification failure")?;
            journal.state = TransferJournalState::Indeterminate {
                marked_at_unix,
                reason: JournalIndeterminateReason::DeliveryOutcomeUnknown,
            };
            journal_store.persist(&journal_name, &journal, transfer_key.as_slice(), false)?;
            return Err(error.context("verify committed credential-copy destination"));
        }
    };
    let DestinationObservation::Matching { identity_token } = destination_observation else {
        execution.mark_indeterminate(
            crate::secret_transfer::IndeterminateReason::DeliveryOutcomeUnknown,
        )?;
        let marked_at_unix =
            clock().context("read clock after destination verification mismatch")?;
        journal.state = TransferJournalState::Indeterminate {
            marked_at_unix,
            reason: JournalIndeterminateReason::DeliveryOutcomeUnknown,
        };
        journal_store.persist(&journal_name, &journal, transfer_key.as_slice(), false)?;
        anyhow::bail!("destination verification failed; source was preserved");
    };
    if !journal_binds_destination_object(
        &journal,
        transfer_key.as_slice(),
        &plan_fingerprint,
        &identity_token,
    )? {
        execution.mark_indeterminate(
            crate::secret_transfer::IndeterminateReason::DeliveryOutcomeUnknown,
        )?;
        let marked_at_unix =
            clock().context("read clock after destination object binding mismatch")?;
        journal.state = TransferJournalState::Indeterminate {
            marked_at_unix,
            reason: JournalIndeterminateReason::DestinationMismatch,
        };
        journal_store.persist(&journal_name, &journal, transfer_key.as_slice(), false)?;
        anyhow::bail!(
            "matching destination is not the exact object created by this authenticated transfer; refusing false delivery"
        );
    }
    let namespace_durability =
        match confirm_destination_data_and_namespace(&destination_path, &identity_token) {
            Ok(outcome) => NamespaceDurability::from(outcome),
            Err(error) => {
                execution.mark_indeterminate(
                    crate::secret_transfer::IndeterminateReason::DeliveryOutcomeUnknown,
                )?;
                let marked_at_unix =
                    clock().context("read clock after final destination confirmation failure")?;
                journal.state = TransferJournalState::Indeterminate {
                    marked_at_unix,
                    reason: JournalIndeterminateReason::DeliveryOutcomeUnknown,
                };
                journal_store.persist(&journal_name, &journal, transfer_key.as_slice(), false)?;
                return Err(error.context(
                "verified credential-copy destination exists but final data confirmation failed",
            ));
            }
        };
    journal.destination_namespace_durability = Some(namespace_durability);

    let delivered_at_unix =
        clock().context("read clock before recording secret-transfer delivery")?;
    if let Err(error) = record_local_delivery(
        &mut execution,
        transfer_key.as_slice(),
        &plan_fingerprint,
        &identity_token,
        &source_digest,
        byte_len,
        delivered_at_unix,
    ) {
        if execution.phase() == TransferPhase::Executing {
            execution.mark_indeterminate(
                crate::secret_transfer::IndeterminateReason::DeliveryOutcomeUnknown,
            )?;
        }
        let marked_at_unix = clock().context("read clock after delivery receipt failure")?;
        journal.state = TransferJournalState::Indeterminate {
            marked_at_unix,
            reason: JournalIndeterminateReason::DeliveryOutcomeUnknown,
        };
        journal_store.persist(&journal_name, &journal, transfer_key.as_slice(), false)?;
        return Err(error.context("record verified local credential-copy receipt"));
    }
    journal.state = TransferJournalState::Delivered { delivered_at_unix };
    journal_store.persist(&journal_name, &journal, transfer_key.as_slice(), false)?;

    Ok(FileTransferReport {
        operation: "copy",
        phase: execution.phase(),
        plan_fingerprint: hex::encode(plan_fingerprint),
        byte_len,
        delivered_at_unix,
        live_destination_verified: true,
        namespace_durability,
    })
}

#[cfg(test)]
fn execute_file_copy_at(
    home: &Path,
    source: &Path,
    destination: &Path,
    now_unix: i64,
    checkpoint: impl FnMut(FileCopyCheckpoint) -> Result<()>,
) -> Result<FileTransferReport> {
    execute_file_copy_with_clock(home, source, destination, || Ok(now_unix), checkpoint)
}

#[allow(clippy::too_many_arguments)]
fn reconcile_existing_journal(
    store: &TransferJournalStore,
    name: &OsStr,
    journal: &mut TransferJournal,
    bindings: &JournalBindings,
    root_key: &[u8],
    destination: &BoundFilePath,
    source_digest: &[u8; 32],
    byte_len: u64,
    source_identity: &str,
    now_unix: i64,
) -> Result<ExistingJournalDecision> {
    anyhow::ensure!(
        journal.operation == TransferOperation::Copy,
        "secret-transfer journal operation does not match credential copy"
    );
    anyhow::ensure!(
        journal.byte_len == byte_len,
        "secret-transfer journal byte length does not match the current source"
    );
    let observed_source = decode_hex_32("journal source binding", &journal.source_binding)?;
    let observed_destination =
        decode_hex_32("journal destination binding", &journal.destination_binding)?;
    anyhow::ensure!(
        bool::from(bindings.source.ct_eq(&observed_source))
            && bool::from(bindings.destination.ct_eq(&observed_destination)),
        "secret-transfer journal bindings do not match the exact local copy request"
    );
    let plan_fingerprint = decode_hex_32("journal plan fingerprint", &journal.plan_fingerprint)?;
    let observed_content = decode_hex_32("journal content binding", &journal.content_binding)?;
    let expected_content = content_binding(root_key, &plan_fingerprint, source_digest, byte_len);
    anyhow::ensure!(
        bool::from(expected_content.ct_eq(&observed_content)),
        "secret-transfer journal content binding does not match the current source and plan"
    );

    let observation =
        match observe_destination(destination, source_digest, byte_len, source_identity) {
            Ok(observation) => observation,
            Err(error) => {
                journal.state = TransferJournalState::Indeterminate {
                    marked_at_unix: now_unix,
                    reason: JournalIndeterminateReason::DeliveryOutcomeUnknown,
                };
                store.persist(name, journal, root_key, false)?;
                return Err(error.context(
                    "existing destination could not be reconciled against the authenticated plan",
                ));
            }
        };
    match observation {
        DestinationObservation::Matching { identity_token } => {
            let state_can_reconcile = matches!(
                journal.state,
                TransferJournalState::Executing { .. }
                    | TransferJournalState::Delivered { .. }
                    | TransferJournalState::Indeterminate {
                        reason: JournalIndeterminateReason::DeliveryOutcomeUnknown,
                        ..
                    }
            );
            if !state_can_reconcile
                || !journal_binds_destination_object(
                    journal,
                    root_key,
                    &plan_fingerprint,
                    &identity_token,
                )?
            {
                journal.state = TransferJournalState::Indeterminate {
                    marked_at_unix: now_unix,
                    reason: JournalIndeterminateReason::DestinationMismatch,
                };
                store.persist(name, journal, root_key, false)?;
                anyhow::bail!(
                    "matching destination was not created by the authenticated executing transfer; refusing false delivery"
                );
            }
            let namespace_durability = match confirm_destination_data_and_namespace(
                destination,
                &identity_token,
            ) {
                Ok(outcome) => NamespaceDurability::from(outcome),
                Err(error) => {
                    journal.state = TransferJournalState::Indeterminate {
                        marked_at_unix: now_unix,
                        reason: JournalIndeterminateReason::DeliveryOutcomeUnknown,
                    };
                    store.persist(name, journal, root_key, false)?;
                    return Err(error.context(
                            "matching credential-copy destination exists but final data confirmation failed",
                        ));
                }
            };
            let delivered_at_unix = match journal.state {
                TransferJournalState::Delivered { delivered_at_unix } => delivered_at_unix,
                _ => now_unix,
            };
            let journal_needs_update =
                !matches!(journal.state, TransferJournalState::Delivered { .. })
                    || journal.destination_namespace_durability != Some(namespace_durability);
            journal.destination_namespace_durability = Some(namespace_durability);
            if journal_needs_update {
                journal.state = TransferJournalState::Delivered { delivered_at_unix };
                store.persist(name, journal, root_key, false)?;
            }
            Ok(ExistingJournalDecision::Delivered(FileTransferReport {
                operation: "copy",
                phase: TransferPhase::Delivered,
                plan_fingerprint: journal.plan_fingerprint.clone(),
                byte_len,
                delivered_at_unix,
                live_destination_verified: true,
                namespace_durability,
            }))
        }
        DestinationObservation::Absent => match journal.state {
            TransferJournalState::Delivered { .. } => {
                journal.state = TransferJournalState::Indeterminate {
                    marked_at_unix: now_unix,
                    reason: JournalIndeterminateReason::PreviouslyDeliveredDestinationMissing,
                };
                store.persist(name, journal, root_key, false)?;
                anyhow::bail!(
                    "a previously verified credential-copy destination is now missing; source was preserved"
                );
            }
            TransferJournalState::Planned { .. } | TransferJournalState::Executing { .. } => {
                journal.state = TransferJournalState::Failed {
                    failed_at_unix: now_unix,
                    reason: JournalFailureReason::ProcessInterruptedBeforeEffect,
                };
                store.persist(name, journal, root_key, false)?;
                Ok(ExistingJournalDecision::StartFresh {
                    replace_existing: true,
                })
            }
            TransferJournalState::Failed { .. } | TransferJournalState::Indeterminate { .. } => {
                Ok(ExistingJournalDecision::StartFresh {
                    replace_existing: true,
                })
            }
        },
        DestinationObservation::Mismatching => {
            journal.state = TransferJournalState::Indeterminate {
                marked_at_unix: now_unix,
                reason: JournalIndeterminateReason::DestinationMismatch,
            };
            store.persist(name, journal, root_key, false)?;
            anyhow::bail!(
                "existing destination does not match the authenticated independent credential-copy target; refusing overwrite"
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn reconcile_failed_effect(
    effect_error: anyhow::Error,
    store: &TransferJournalStore,
    name: &OsStr,
    journal: &mut TransferJournal,
    execution: &mut crate::secret_transfer::TransferExecution,
    root_key: &[u8],
    destination: &BoundFilePath,
    source_digest: &[u8; 32],
    byte_len: u64,
    source_identity: &str,
    now_unix: i64,
) -> Result<FileTransferReport> {
    let observation =
        match observe_destination(destination, source_digest, byte_len, source_identity) {
            Ok(observation) => observation,
            Err(reconcile_error) => {
                execution.mark_indeterminate(
                    crate::secret_transfer::IndeterminateReason::DeliveryOutcomeUnknown,
                )?;
                journal.state = TransferJournalState::Indeterminate {
                    marked_at_unix: now_unix,
                    reason: JournalIndeterminateReason::DeliveryOutcomeUnknown,
                };
                store.persist(name, journal, root_key, false)?;
                return Err(effect_error.context(format!(
                    "destination outcome could not be reconciled: {reconcile_error:#}"
                )));
            }
        };
    match observation {
        DestinationObservation::Matching { identity_token } => {
            let plan_fingerprint =
                decode_hex_32("journal plan fingerprint", &journal.plan_fingerprint)?;
            if !journal_binds_destination_object(
                journal,
                root_key,
                &plan_fingerprint,
                &identity_token,
            )? {
                execution.mark_indeterminate(
                    crate::secret_transfer::IndeterminateReason::DeliveryOutcomeUnknown,
                )?;
                journal.state = TransferJournalState::Indeterminate {
                    marked_at_unix: now_unix,
                    reason: JournalIndeterminateReason::DestinationMismatch,
                };
                store.persist(name, journal, root_key, false)?;
                return Err(effect_error.context(
                    "matching destination is not the object bound before the first secret byte; refusing false delivery",
                ));
            }
            let namespace_durability = match confirm_destination_data_and_namespace(
                destination,
                &identity_token,
            ) {
                Ok(outcome) => NamespaceDurability::from(outcome),
                Err(confirmation_error) => {
                    execution.mark_indeterminate(
                        crate::secret_transfer::IndeterminateReason::DeliveryOutcomeUnknown,
                    )?;
                    journal.state = TransferJournalState::Indeterminate {
                        marked_at_unix: now_unix,
                        reason: JournalIndeterminateReason::DeliveryOutcomeUnknown,
                    };
                    store.persist(name, journal, root_key, false)?;
                    return Err(effect_error.context(format!(
                            "matching destination exists but final data confirmation failed: {confirmation_error:#}"
                        )));
                }
            };
            record_local_delivery(
                execution,
                root_key,
                &plan_fingerprint,
                &identity_token,
                source_digest,
                byte_len,
                now_unix,
            )?;
            journal.destination_namespace_durability = Some(namespace_durability);
            journal.state = TransferJournalState::Delivered {
                delivered_at_unix: now_unix,
            };
            store.persist(name, journal, root_key, false)?;
            Ok(FileTransferReport {
                operation: "copy",
                phase: TransferPhase::Delivered,
                plan_fingerprint: journal.plan_fingerprint.clone(),
                byte_len,
                delivered_at_unix: now_unix,
                live_destination_verified: true,
                namespace_durability,
            })
        }
        DestinationObservation::Absent => {
            let (transfer_reason, journal_reason) =
                if error_has_io_kind(&effect_error, std::io::ErrorKind::AlreadyExists) {
                    (
                        TransferFailureReason::DestinationRejected,
                        JournalFailureReason::DestinationRejected,
                    )
                } else {
                    (
                        TransferFailureReason::Transport,
                        JournalFailureReason::Transport,
                    )
                };
            execution.fail(transfer_reason)?;
            journal.state = TransferJournalState::Failed {
                failed_at_unix: now_unix,
                reason: journal_reason,
            };
            store.persist(name, journal, root_key, false)?;
            Err(effect_error)
        }
        DestinationObservation::Mismatching => {
            execution.mark_indeterminate(
                crate::secret_transfer::IndeterminateReason::DeliveryOutcomeUnknown,
            )?;
            journal.state = TransferJournalState::Indeterminate {
                marked_at_unix: now_unix,
                reason: JournalIndeterminateReason::DestinationMismatch,
            };
            store.persist(name, journal, root_key, false)?;
            Err(effect_error.context(
                "destination appeared during credential copy with different content or is not an independent target; refusing overwrite",
            ))
        }
    }
}

fn observe_destination(
    destination: &BoundFilePath,
    source_digest: &[u8; 32],
    byte_len: u64,
    source_identity: &str,
) -> Result<DestinationObservation> {
    match destination.parent.dir.symlink_metadata(&destination.name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(DestinationObservation::Absent);
        }
        Err(error) => return Err(error).context("inspect exact destination namespace"),
        Ok(metadata) if !metadata.is_file() => {
            return Ok(DestinationObservation::Mismatching);
        }
        Ok(_) => {}
    }
    let (mut delivered_file, delivered_object) = match open_bound_regular_file(
        &destination.parent.dir,
        &destination.name,
        &destination.display_path,
    ) {
        Ok(value) => value,
        Err(error) => {
            return Err(error).context("open delivered destination generation for verification");
        }
    };
    if delivered_object.identity_token() == source_identity {
        return Ok(DestinationObservation::Mismatching);
    }
    verify_private_local_file(
        &delivered_file,
        &destination.display_path,
        "credential-copy destination",
    )?;
    let delivered_payload = read_bounded_payload(&mut delivered_file)?;
    let matching = delivered_payload.digest() == *source_digest
        && u64::try_from(delivered_payload.len()).context("destination length exceeds u64")?
            == byte_len
        && delivered_object.matches_regular_file_child_readonly(
            &destination.parent.dir,
            &destination.name,
            &destination.display_path,
        )?;
    if matching {
        Ok(DestinationObservation::Matching {
            identity_token: delivered_object.identity_token().to_owned(),
        })
    } else {
        Ok(DestinationObservation::Mismatching)
    }
}

fn confirm_destination_data_and_namespace(
    destination: &BoundFilePath,
    expected_identity: &str,
) -> Result<DirectorySyncOutcome> {
    let (file, identity) = open_bound_regular_file_readwrite(
        &destination.parent.dir,
        &destination.name,
        &destination.display_path,
    )
    .context("open matching destination for final data confirmation")?;
    anyhow::ensure!(
        identity.identity_token() == expected_identity,
        "destination identity changed before final data confirmation"
    );
    verify_private_local_file(
        &file,
        &destination.display_path,
        "credential-copy destination",
    )?;
    file.sync_all()
        .context("sync matching credential-copy destination data")?;
    anyhow::ensure!(
        identity.matches_regular_file_child_readonly(
            &destination.parent.dir,
            &destination.name,
            &destination.display_path,
        )?,
        "destination identity changed during final data confirmation"
    );
    let (_verified_file, verified_identity) = open_bound_regular_file(
        &destination.parent.dir,
        &destination.name,
        &destination.display_path,
    )
    .context("re-open destination after final data confirmation")?;
    anyhow::ensure!(
        verified_identity.identity_token() == expected_identity,
        "destination identity changed during final data confirmation"
    );
    sync_parent_directory(
        &destination.parent.dir,
        destination
            .display_path
            .parent()
            .unwrap_or(&destination.display_path),
    )
    .context("attempt credential-copy destination directory sync")
}

fn record_local_delivery(
    execution: &mut crate::secret_transfer::TransferExecution,
    root_key: &[u8],
    plan_fingerprint: &[u8; 32],
    destination_identity: &str,
    source_digest: &[u8; 32],
    byte_len: u64,
    delivered_at_unix: i64,
) -> Result<()> {
    let mut evidence_binding = Zeroizing::new(Vec::with_capacity(160));
    evidence_binding.extend_from_slice(DELIVERY_EVIDENCE_DOMAIN);
    evidence_binding.extend_from_slice(plan_fingerprint);
    evidence_binding.extend_from_slice(destination_identity.as_bytes());
    evidence_binding.extend_from_slice(source_digest);
    evidence_binding.extend_from_slice(&byte_len.to_be_bytes());
    let delivery_evidence = crate::util::hmac::sha256(root_key, &evidence_binding);
    let receipt = DeliveryReceipt::for_execution(execution, delivered_at_unix, delivery_evidence)?;
    execution.record_delivered(receipt, &|candidate: &DeliveryReceipt| {
        candidate.transport_evidence_sha256() == &delivery_evidence
    })?;
    Ok(())
}

fn bind_parent(path: &Path, label: &str) -> Result<BoundFilePath> {
    let absolute =
        std::path::absolute(path).with_context(|| format!("resolve absolute {label} path"))?;
    let name = absolute
        .file_name()
        .filter(|name| !name.is_empty())
        .context("secret-transfer path must name a direct file")?
        .to_os_string();
    let parent_path = absolute
        .parent()
        .context("secret-transfer file must have a parent directory")?;
    let parent = open_bound_directory(parent_path, false, label)?
        .with_context(|| format!("{label} parent directory does not exist"))?;
    let display_path = parent.display_path.join(&name);
    Ok(BoundFilePath {
        parent,
        name,
        display_path,
    })
}

fn ensure_destination_absent(destination: &BoundFilePath) -> Result<()> {
    match destination.parent.dir.symlink_metadata(&destination.name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "destination already exists; local secret copy never overwrites an existing object",
        )
        .into()),
        Err(error) => Err(error).context("inspect exact destination namespace"),
    }
}

fn read_bounded_payload(file: &mut cap_std::fs::File) -> Result<SecretPayload> {
    let metadata = file.metadata().context("inspect secret-bearing file")?;
    anyhow::ensure!(
        metadata.len() <= MAX_LOCAL_SECRET_FILE_BYTES,
        "secret-bearing file exceeds the {} MiB local-transfer limit",
        MAX_LOCAL_SECRET_FILE_BYTES / (1024 * 1024)
    );
    file.seek(SeekFrom::Start(0))
        .context("rewind secret-bearing file")?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    std::io::Read::by_ref(&mut *file)
        .take(MAX_LOCAL_SECRET_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read secret-bearing file")?;
    anyhow::ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_LOCAL_SECRET_FILE_BYTES,
        "secret-bearing file grew beyond the local-transfer limit"
    );
    Ok(SecretPayload::new(bytes))
}

fn local_instance_binding(home: &Path) -> String {
    let mut digest = Sha256::new();
    digest.update(b"neoth.secret-transfer.local-instance.v1");
    digest.update(home.as_os_str().to_string_lossy().as_bytes());
    format!("local:{}", hex::encode(digest.finalize()))
}

fn local_destination_binding(root_key: &[u8], path: &Path) -> String {
    hex::encode(keyed_binding(
        root_key,
        DESTINATION_BINDING_DOMAIN,
        &[path.as_os_str().as_encoded_bytes()],
    ))
}

fn journal_bindings(
    root_key: &[u8],
    source_path: &Path,
    source_identity: &str,
    destination_path: &Path,
    source_digest: &[u8; 32],
    byte_len: u64,
) -> JournalBindings {
    let byte_len_bytes = byte_len.to_be_bytes();
    let source = keyed_binding(
        root_key,
        SOURCE_BINDING_DOMAIN,
        &[
            source_path.as_os_str().as_encoded_bytes(),
            source_identity.as_bytes(),
            source_digest,
            &byte_len_bytes,
        ],
    );
    let destination = keyed_binding(
        root_key,
        DESTINATION_BINDING_DOMAIN,
        &[destination_path.as_os_str().as_encoded_bytes()],
    );
    let intent = keyed_binding(
        root_key,
        INTENT_BINDING_DOMAIN,
        &[&source, &destination, b"copy"],
    );
    JournalBindings {
        intent,
        source,
        destination,
    }
}

fn content_binding(
    root_key: &[u8],
    plan_fingerprint: &[u8; 32],
    source_digest: &[u8; 32],
    byte_len: u64,
) -> [u8; 32] {
    let byte_len_bytes = byte_len.to_be_bytes();
    keyed_binding(
        root_key,
        CONTENT_BINDING_DOMAIN,
        &[plan_fingerprint, source_digest, &byte_len_bytes],
    )
}

fn destination_object_binding(
    root_key: &[u8],
    plan_fingerprint: &[u8; 32],
    identity_token: &str,
) -> [u8; 32] {
    keyed_binding(
        root_key,
        DESTINATION_OBJECT_BINDING_DOMAIN,
        &[plan_fingerprint, identity_token.as_bytes()],
    )
}

fn journal_binds_destination_object(
    journal: &TransferJournal,
    root_key: &[u8],
    plan_fingerprint: &[u8; 32],
    identity_token: &str,
) -> Result<bool> {
    let Some(encoded) = journal.destination_object_binding.as_deref() else {
        return Ok(false);
    };
    let observed = decode_hex_32("journal destination object binding", encoded)?;
    let expected = destination_object_binding(root_key, plan_fingerprint, identity_token);
    Ok(bool::from(expected.ct_eq(&observed)))
}

fn keyed_binding(root_key: &[u8], domain: &[u8], components: &[&[u8]]) -> [u8; 32] {
    let mut binding = Zeroizing::new(Vec::with_capacity(
        domain.len()
            + components
                .iter()
                .map(|value| value.len() + 8)
                .sum::<usize>(),
    ));
    binding.extend_from_slice(domain);
    for component in components {
        binding.extend_from_slice(
            &u64::try_from(component.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        binding.extend_from_slice(component);
    }
    crate::util::hmac::sha256(root_key, &binding)
}

fn journal_authentication_tag(root_key: &[u8], canonical_journal: &[u8]) -> [u8; 32] {
    keyed_binding(root_key, JOURNAL_AUTH_DOMAIN, &[canonical_journal])
}

fn decode_hex_32(label: &str, encoded: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(encoded).with_context(|| format!("decode {label}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} must encode exactly 32 bytes"))
}

fn validate_journal_shape(journal: &TransferJournal) -> Result<()> {
    anyhow::ensure!(
        journal.schema_version == TRANSFER_JOURNAL_SCHEMA_VERSION,
        "unsupported secret-transfer journal schema {}",
        journal.schema_version
    );
    anyhow::ensure!(
        journal.operation == TransferOperation::Copy,
        "credential-copy journal contains a non-copy operation"
    );
    anyhow::ensure!(
        journal.byte_len <= MAX_LOCAL_SECRET_FILE_BYTES,
        "credential-copy journal length exceeds the local-transfer limit"
    );
    decode_hex_32("journal nonce", &journal.nonce)?;
    decode_hex_32("journal plan fingerprint", &journal.plan_fingerprint)?;
    decode_hex_32("journal source binding", &journal.source_binding)?;
    decode_hex_32("journal destination binding", &journal.destination_binding)?;
    decode_hex_32("journal content binding", &journal.content_binding)?;
    if let Some(binding) = journal.destination_object_binding.as_deref() {
        decode_hex_32("journal destination object binding", binding)?;
    }
    if matches!(journal.state, TransferJournalState::Delivered { .. }) {
        anyhow::ensure!(
            journal.destination_object_binding.is_some(),
            "delivered credential-copy journal lacks an exact destination object binding"
        );
        anyhow::ensure!(
            journal.destination_namespace_durability.is_some(),
            "delivered credential-copy journal lacks an explicit namespace durability outcome"
        );
    }
    Ok(())
}

fn verify_private_journal_file(file: &cap_std::fs::File, display_path: &Path) -> Result<()> {
    verify_private_local_file(file, display_path, "secret-transfer journal")
}

fn verify_private_local_file(
    file: &cap_std::fs::File,
    display_path: &Path,
    label: &str,
) -> Result<()> {
    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt as _;
        let mode = file
            .metadata()
            .with_context(|| format!("inspect private {label} {}", display_path.display()))?
            .permissions()
            .mode();
        anyhow::ensure!(
            mode & 0o077 == 0,
            "{label} is accessible by group or other users: {}",
            display_path.display()
        );
    }
    #[cfg(windows)]
    {
        let clone = file
            .try_clone()
            .with_context(|| format!("clone private {label} {}", display_path.display()))?
            .into_std();
        crate::wal::win_native::verify_private_file_handle(&clone)
            .with_context(|| format!("verify owner-private {label} {}", display_path.display()))?;
    }
    Ok(())
}

fn try_open_transfer_lock(
    directory: &BoundDirectory,
    name: &OsStr,
    display_path: &Path,
) -> Result<Option<std::fs::File>> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.mode(0o600);
        let file = directory
            .dir
            .open_with(name, &options)
            .with_context(|| format!("open transfer journal lock {}", display_path.display()))?;
        verify_private_journal_file(&file, display_path)?;
        let file = file.into_std();
        use std::os::fd::AsRawFd as _;
        // SAFETY: `file` owns a valid descriptor for the lifetime of the lock.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            Ok(Some(file))
        } else {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(error)
                    .with_context(|| format!("lock transfer journal {}", display_path.display()))
            }
        }
    }
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, READ_CONTROL,
        };
        const ERROR_SHARING_VIOLATION: i32 = 32;
        options
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL)
            .share_mode(FILE_SHARE_READ);
        match directory.dir.open_with(name, &options) {
            Ok(file) => {
                verify_private_journal_file(&file, display_path)?;
                Ok(Some(file.into_std()))
            }
            Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => Ok(None),
            Err(error) => Err(error)
                .with_context(|| format!("open transfer journal lock {}", display_path.display())),
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (directory, name, display_path, options);
        anyhow::bail!("durable local secret-transfer locking is unsupported on this target");
    }
}

fn error_has_io_kind(error: &anyhow::Error, kind: std::io::ErrorKind) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|io_error| io_error.kind() == kind)
}

fn unix_now() -> Result<i64> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before Unix epoch")?
            .as_secs(),
    )
    .context("system time exceeds i64")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn journal_files(home: &Path) -> Vec<PathBuf> {
        let directory = home.join("secret-transfers").join("journal");
        let mut files = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension() == Some(OsStr::new("json")))
            .collect::<Vec<_>>();
        files.sort();
        files
    }

    fn only_journal_json(home: &Path) -> serde_json::Value {
        let files = journal_files(home);
        assert_eq!(files.len(), 1);
        serde_json::from_slice(&std::fs::read(&files[0]).unwrap()).unwrap()
    }

    fn journal_phase(home: &Path) -> String {
        only_journal_json(home)["journal"]["state"]["phase"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn assert_no_plaintext_stage_files(directory: &Path, expected_files: &[&Path], secret: &[u8]) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            assert!(
                !name.starts_with(".neoth-private-empty-") && !name.starts_with(".neoth-atomic-"),
                "credential-copy stage survived publication: {}",
                path.display()
            );
            if !expected_files.contains(&path.as_path()) && path.is_file() {
                let bytes = std::fs::read(&path).unwrap();
                assert!(
                    !bytes.windows(secret.len()).any(|part| part == secret),
                    "secret bytes leaked to sibling stage file {}",
                    path.display()
                );
            }
        }
    }

    fn fresh_transfer_nonce() -> TransferNonce {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes)
            .expect("OS entropy source unavailable while minting test transfer nonce");
        TransferNonce::new(bytes)
    }

    fn permit_record(nonce: TransferNonce) -> PermitConsumptionRecord {
        PermitConsumptionRecord {
            plan_fingerprint: [0x11; 32],
            nonce,
            principal_id: "local-os-user".to_owned(),
            origin_instance_id: "local:test".to_owned(),
            turn_request_id: "credential-copy:test".to_owned(),
            consumed_at_unix: 1_800_000_000,
        }
    }

    fn replace_wal_hmac_key_for_test(home: &Path, fill: u8) {
        let wal = home.join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let path = wal.join("hmac.key");
        let encoded = crate::wal::compaction::encode_key_for_storage(&path, &[fill; 32]).unwrap();
        std::fs::write(&path, encoded).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        #[cfg(windows)]
        crate::wal::win_native::set_private_current_user_dacl(&path).unwrap();
    }

    #[cfg(any(unix, windows))]
    fn try_link_directory(target: &Path, link: &Path) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link)
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_dir(target, link)
        }
    }

    #[cfg(any(unix, windows))]
    fn try_link_file(target: &Path, link: &Path) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link)
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file(target, link)
        }
    }

    #[test]
    #[cfg(any(unix, windows))]
    fn planted_instance_home_link_is_never_used_as_a_trusted_anchor() {
        let parent = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let linked_home = parent.path().join("linked-neoth-home");
        if try_link_directory(outside.path(), &linked_home).is_err() {
            return;
        }

        let error = match TransferJournalStore::open(&linked_home) {
            Ok(_) => panic!("planted instance-home link was accepted"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("without following links")
                || error.to_string().contains("real directory"),
            "{error:#}"
        );
        assert!(!outside.path().join("secret-transfers").exists());
    }

    #[test]
    #[cfg(any(unix, windows))]
    fn planted_transfer_authority_key_link_is_rejected_without_touching_target() {
        let parent = tempfile::tempdir().unwrap();
        let home = parent.path().join("neoth-home");
        let transfer_root = home.join("secret-transfers");
        std::fs::create_dir_all(&transfer_root).unwrap();
        let outside = parent.path().join("outside.key");
        let outside_key = [0x5a_u8; TRANSFER_AUTHORITY_KEY_BYTES];
        std::fs::write(&outside, outside_key).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        #[cfg(windows)]
        crate::wal::win_native::set_private_current_user_dacl(&outside).unwrap();
        if try_link_file(&outside, &transfer_root.join(TRANSFER_AUTHORITY_KEY_NAME)).is_err() {
            return;
        }

        let error = load_or_init_transfer_authority_key(&home).unwrap_err();
        assert!(
            error.to_string().contains("without following links")
                || error.to_string().contains("real regular file"),
            "{error:#}"
        );
        assert_eq!(std::fs::read(&outside).unwrap(), outside_key);
    }

    #[test]
    #[cfg(unix)]
    fn existing_instance_state_directories_are_hardened_before_use() {
        use std::os::unix::fs::PermissionsExt as _;

        let parent = tempfile::tempdir().unwrap();
        let home = parent.path().join("neoth-home");
        let transfer_root = home.join("secret-transfers");
        let journal = transfer_root.join("journal");
        std::fs::create_dir_all(&journal).unwrap();
        for path in [&home, &transfer_root, &journal] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777)).unwrap();
        }

        TransferJournalStore::open(&home).unwrap();

        for path in [&home, &transfer_root, &journal] {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o7777,
                0o700,
                "{}",
                path.display()
            );
        }
    }

    #[test]
    fn durable_permit_store_rejects_replay_across_instances() {
        let home = tempfile::tempdir().unwrap();
        let nonce = fresh_transfer_nonce();
        let mut first = DurablePermitStore::open(home.path()).unwrap();
        first.consume_once(&permit_record(nonce)).unwrap();
        drop(first);

        let mut reopened = DurablePermitStore::open(home.path()).unwrap();
        assert_eq!(
            reopened.consume_once(&permit_record(nonce)),
            Err(PermitConsumptionError::Replay)
        );
    }

    #[test]
    fn human_copy_success_messages_are_static_and_metadata_free() {
        assert_eq!(
            human_copy_success_message(NamespaceDurability::Confirmed),
            "Credential copy succeeded: destination data and namespace durability were live-verified; source preserved."
        );
        assert_eq!(
            human_copy_success_message(NamespaceDurability::Unsupported),
            "Credential copy succeeded: destination data were live-verified; this platform cannot confirm parent-directory power-loss durability; source preserved."
        );
    }

    #[test]
    fn local_copy_is_exact_private_and_preserves_source() {
        let home = tempfile::tempdir().unwrap();
        let source_dir = tempfile::tempdir().unwrap();
        let destination_dir = tempfile::tempdir().unwrap();
        let source = source_dir.path().join("source.bin");
        let destination = destination_dir.path().join("destination.bin");
        let sentinel = format!("secret-{}", uuid::Uuid::new_v4());
        std::fs::write(&source, sentinel.as_bytes()).unwrap();

        let report = execute_file_copy_at(
            home.path(),
            &source,
            &destination,
            1_800_000_000,
            |_| Ok(()),
        )
        .unwrap();

        assert_eq!(report.phase, TransferPhase::Delivered);
        assert_eq!(report.byte_len, sentinel.len() as u64);
        assert!(report.live_destination_verified);
        #[cfg(unix)]
        assert_eq!(report.namespace_durability, NamespaceDurability::Confirmed);
        #[cfg(windows)]
        assert_eq!(
            report.namespace_durability,
            NamespaceDurability::Unsupported
        );
        assert_eq!(std::fs::read(&source).unwrap(), sentinel.as_bytes());
        assert_eq!(std::fs::read(&destination).unwrap(), sentinel.as_bytes());
        assert_no_plaintext_stage_files(
            destination_dir.path(),
            &[destination.as_path()],
            sentinel.as_bytes(),
        );
        let report_json = serde_json::to_string(&report).unwrap();
        assert!(!report_json.contains(&sentinel));

        let replay_dir = home.path().join("secret-transfers").join("consumed");
        for entry in std::fs::read_dir(replay_dir).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            assert!(
                !bytes
                    .windows(sentinel.len())
                    .any(|part| part == sentinel.as_bytes())
            );
        }
        let raw_digest = hex::encode(Sha256::digest(sentinel.as_bytes()));
        for path in journal_files(home.path()) {
            let bytes = std::fs::read(&path).unwrap();
            assert!(
                !bytes
                    .windows(sentinel.len())
                    .any(|part| part == sentinel.as_bytes())
            );
            let text = String::from_utf8(bytes).unwrap();
            assert!(!text.contains(&raw_digest));
            assert!(!text.contains("source.bin"));
            assert!(!text.contains("destination.bin"));
        }
        assert_eq!(journal_phase(home.path()), "delivered");
        let journal = only_journal_json(home.path());
        #[cfg(unix)]
        assert_eq!(
            journal["journal"]["destination_namespace_durability"],
            "confirmed"
        );
        #[cfg(windows)]
        assert_eq!(
            journal["journal"]["destination_namespace_durability"],
            "unsupported"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&destination)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            for path in journal_files(home.path()) {
                assert_eq!(
                    std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        #[cfg(windows)]
        {
            crate::wal::win_native::verify_private_dacl(&destination).unwrap();
            for path in journal_files(home.path()) {
                crate::wal::win_native::verify_private_dacl(&path).unwrap();
            }
        }
    }

    #[test]
    fn local_copy_refuses_to_overwrite_destination() {
        let home = tempfile::tempdir().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.bin");
        let destination = directory.path().join("destination.bin");
        std::fs::write(&source, b"source-secret").unwrap();
        std::fs::write(&destination, b"existing-secret").unwrap();

        let error =
            execute_file_copy_at(
                home.path(),
                &source,
                &destination,
                1_800_000_000,
                |_| Ok(()),
            )
            .unwrap_err();
        assert!(error.to_string().contains("never overwrites"));
        assert_eq!(std::fs::read(&destination).unwrap(), b"existing-secret");
        assert_eq!(std::fs::read(&source).unwrap(), b"source-secret");
    }

    #[test]
    fn source_change_after_permit_is_fail_closed() {
        let home = tempfile::tempdir().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.bin");
        let destination = directory.path().join("destination.bin");
        std::fs::write(&source, b"first-secret").unwrap();

        let error = execute_file_copy_at(
            home.path(),
            &source,
            &destination,
            1_800_000_000,
            |checkpoint| {
                if checkpoint == FileCopyCheckpoint::AfterExecutionStarted {
                    std::fs::write(&source, b"changed-secret").unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("changed after authorization"));
        assert!(!destination.exists());
        assert_eq!(std::fs::read(&source).unwrap(), b"changed-secret");
        assert_eq!(journal_phase(home.path()), "failed");
    }

    #[test]
    fn permit_expiry_is_checked_against_the_clock_at_consumption() {
        let home = tempfile::tempdir().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.bin");
        let destination = directory.path().join("destination.bin");
        std::fs::write(&source, b"expiring-secret").unwrap();
        let now = std::cell::Cell::new(1_800_000_000_i64);

        let error = execute_file_copy_with_clock(
            home.path(),
            &source,
            &destination,
            || Ok(now.get()),
            |checkpoint| {
                if checkpoint == FileCopyCheckpoint::AfterPlannedJournal {
                    now.set(now.get().checked_add(PERMIT_LIFETIME_SECONDS + 1).unwrap());
                }
                Ok(())
            },
        )
        .unwrap_err();

        let error_chain = format!("{error:#}");
        assert!(
            error_chain.to_ascii_lowercase().contains("expired"),
            "{error_chain}"
        );
        assert!(!destination.exists());
        assert_eq!(std::fs::read(&source).unwrap(), b"expiring-secret");
        assert_eq!(journal_phase(home.path()), "failed");
        assert_eq!(
            only_journal_json(home.path())["journal"]["state"]["reason"],
            "authorization"
        );
    }

    #[test]
    fn restart_from_planned_journal_does_not_claim_an_unexecuted_delivery() {
        let home = tempfile::tempdir().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.bin");
        let destination = directory.path().join("destination.bin");
        std::fs::write(&source, b"planned-secret").unwrap();

        execute_file_copy_at(
            home.path(),
            &source,
            &destination,
            1_800_000_000,
            |checkpoint| {
                if checkpoint == FileCopyCheckpoint::AfterPlannedJournal {
                    anyhow::bail!("simulated crash before permit consumption");
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(journal_phase(home.path()), "planned");
        assert!(!destination.exists());

        let report = execute_file_copy_at(
            home.path(),
            &source,
            &destination,
            1_800_000_001,
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(report.phase, TransferPhase::Delivered);
        assert_eq!(std::fs::read(&destination).unwrap(), b"planned-secret");
        assert_eq!(journal_phase(home.path()), "delivered");
        let consumed = std::fs::read_dir(home.path().join("secret-transfers").join("consumed"))
            .unwrap()
            .count();
        assert_eq!(consumed, 1);
    }

    #[test]
    fn restart_after_consumption_without_effect_starts_a_fresh_bound_attempt() {
        let home = tempfile::tempdir().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.bin");
        let destination = directory.path().join("destination.bin");
        std::fs::write(&source, b"restart-secret").unwrap();

        let error = execute_file_copy_at(
            home.path(),
            &source,
            &destination,
            1_800_000_000,
            |checkpoint| {
                if checkpoint == FileCopyCheckpoint::AfterExecutionStarted {
                    anyhow::bail!("simulated process interruption");
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("simulated process interruption"));
        assert_eq!(journal_phase(home.path()), "executing");
        assert!(!destination.exists());

        let report = execute_file_copy_at(
            home.path(),
            &source,
            &destination,
            1_800_000_001,
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(report.phase, TransferPhase::Delivered);
        assert_eq!(std::fs::read(&destination).unwrap(), b"restart-secret");
        assert_eq!(journal_phase(home.path()), "delivered");

        let consumed = std::fs::read_dir(home.path().join("secret-transfers").join("consumed"))
            .unwrap()
            .count();
        assert_eq!(consumed, 2, "the interrupted permit stays consumed");
    }

    #[test]
    fn restart_after_publish_reconciles_existing_destination_instead_of_replay() {
        let home = tempfile::tempdir().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.bin");
        let destination = directory.path().join("destination.bin");
        let sentinel = b"low-entropy-password";
        std::fs::write(&source, sentinel).unwrap();
        replace_wal_hmac_key_for_test(home.path(), 0x31);

        let error = execute_file_copy_at(
            home.path(),
            &source,
            &destination,
            1_800_000_000,
            |checkpoint| {
                if checkpoint == FileCopyCheckpoint::AfterDestinationPublish {
                    anyhow::bail!("simulated crash after destination commit");
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("simulated crash"));
        assert_eq!(std::fs::read(&destination).unwrap(), sentinel);
        assert_eq!(journal_phase(home.path()), "executing");
        let first_journal = std::fs::read(&journal_files(home.path())[0]).unwrap();
        let raw_digest = hex::encode(Sha256::digest(sentinel));
        let first_text = String::from_utf8(first_journal).unwrap();
        assert!(!first_text.contains(&raw_digest));
        assert!(!first_text.contains("low-entropy-password"));
        let destination_path = bind_parent(&destination, "test destination").unwrap();
        let (_, first_destination_object) = open_bound_regular_file(
            &destination_path.parent.dir,
            &destination_path.name,
            &destination_path.display_path,
        )
        .unwrap();
        let first_destination_identity = first_destination_object.identity_token().to_owned();
        replace_wal_hmac_key_for_test(home.path(), 0x52);

        let mut replay_effect_checkpoints = 0_u8;
        let report = execute_file_copy_at(
            home.path(),
            &source,
            &destination,
            1_800_000_001,
            |checkpoint| {
                if checkpoint == FileCopyCheckpoint::BeforeDestinationPublish {
                    replay_effect_checkpoints = replay_effect_checkpoints.saturating_add(1);
                }
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(report.phase, TransferPhase::Delivered);
        assert_eq!(
            replay_effect_checkpoints, 0,
            "reconciliation must not enter a second destination effect path"
        );
        let (_, reconciled_destination_object) = open_bound_regular_file(
            &destination_path.parent.dir,
            &destination_path.name,
            &destination_path.display_path,
        )
        .unwrap();
        assert_eq!(
            reconciled_destination_object.identity_token(),
            first_destination_identity.as_str()
        );
        assert_eq!(std::fs::read(&destination).unwrap(), sentinel);
        assert_no_plaintext_stage_files(
            directory.path(),
            &[source.as_path(), destination.as_path()],
            sentinel,
        );
        assert_eq!(journal_phase(home.path()), "delivered");
        let consumed = std::fs::read_dir(home.path().join("secret-transfers").join("consumed"))
            .unwrap()
            .count();
        assert_eq!(
            consumed, 1,
            "restart reconciles the original plan without consuming a second permit"
        );
    }

    #[test]
    fn tampered_journal_fails_closed_before_any_destination_effect() {
        let home = tempfile::tempdir().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.bin");
        let destination = directory.path().join("destination.bin");
        std::fs::write(&source, b"journal-auth-secret").unwrap();

        execute_file_copy_at(
            home.path(),
            &source,
            &destination,
            1_800_000_000,
            |checkpoint| {
                if checkpoint == FileCopyCheckpoint::AfterExecutionStarted {
                    anyhow::bail!("simulated process interruption");
                }
                Ok(())
            },
        )
        .unwrap_err();
        let journal_path = journal_files(home.path()).pop().unwrap();
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&journal_path).unwrap()).unwrap();
        envelope["journal"]["byte_len"] = serde_json::json!(999_u64);
        std::fs::write(&journal_path, serde_json::to_vec(&envelope).unwrap()).unwrap();

        let error =
            execute_file_copy_at(
                home.path(),
                &source,
                &destination,
                1_800_000_001,
                |_| Ok(()),
            )
            .unwrap_err();
        assert!(error.to_string().contains("authentication failed"));
        assert!(!destination.exists());
        assert_eq!(std::fs::read(&source).unwrap(), b"journal-auth-secret");
    }

    #[test]
    fn destination_race_is_indeterminate_and_never_overwritten() {
        let home = tempfile::tempdir().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.bin");
        let destination = directory.path().join("destination.bin");
        std::fs::write(&source, b"source-secret").unwrap();

        let error = execute_file_copy_at(
            home.path(),
            &source,
            &destination,
            1_800_000_000,
            |checkpoint| {
                if checkpoint == FileCopyCheckpoint::BeforeDestinationPublish {
                    std::fs::write(&destination, b"racing-object").unwrap();
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt as _;
                        std::fs::set_permissions(
                            &destination,
                            std::fs::Permissions::from_mode(0o600),
                        )
                        .unwrap();
                    }
                    #[cfg(windows)]
                    crate::wal::win_native::set_private_current_user_dacl(&destination).unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("different content"));
        assert_eq!(std::fs::read(&destination).unwrap(), b"racing-object");
        assert_eq!(std::fs::read(&source).unwrap(), b"source-secret");
        assert_eq!(journal_phase(home.path()), "indeterminate");
    }

    #[test]
    fn independent_private_same_content_race_is_not_false_delivery() {
        let home = tempfile::tempdir().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.bin");
        let destination = directory.path().join("destination.bin");
        std::fs::write(&source, b"same-private-secret").unwrap();

        let error = execute_file_copy_at(
            home.path(),
            &source,
            &destination,
            1_800_000_000,
            |checkpoint| {
                if checkpoint == FileCopyCheckpoint::BeforeDestinationPublish {
                    std::fs::write(&destination, b"same-private-secret").unwrap();
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt as _;
                        std::fs::set_permissions(
                            &destination,
                            std::fs::Permissions::from_mode(0o600),
                        )
                        .unwrap();
                    }
                    #[cfg(windows)]
                    crate::wal::win_native::set_private_current_user_dacl(&destination).unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("not the object bound"));
        assert_eq!(std::fs::read(&destination).unwrap(), b"same-private-secret");
        assert_eq!(journal_phase(home.path()), "indeterminate");
    }

    #[test]
    fn independent_same_content_replacement_after_publish_is_not_false_delivery() {
        let home = tempfile::tempdir().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.bin");
        let destination = directory.path().join("destination.bin");
        let displaced = directory.path().join("displaced-original.bin");
        std::fs::write(&source, b"post-publish-private-secret").unwrap();

        let error = execute_file_copy_at(
            home.path(),
            &source,
            &destination,
            1_800_000_000,
            |checkpoint| {
                if checkpoint == FileCopyCheckpoint::AfterDestinationPublish {
                    std::fs::rename(&destination, &displaced).unwrap();
                    std::fs::write(&destination, b"post-publish-private-secret").unwrap();
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt as _;
                        std::fs::set_permissions(
                            &destination,
                            std::fs::Permissions::from_mode(0o600),
                        )
                        .unwrap();
                    }
                    #[cfg(windows)]
                    crate::wal::win_native::set_private_current_user_dacl(&destination).unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(
            error.to_string().contains("not the exact object"),
            "{error:#}"
        );
        assert_eq!(
            std::fs::read(&destination).unwrap(),
            b"post-publish-private-secret"
        );
        assert_eq!(
            std::fs::read(&source).unwrap(),
            b"post-publish-private-secret"
        );
        assert_eq!(journal_phase(home.path()), "indeterminate");
    }

    #[test]
    #[cfg(unix)]
    fn same_content_race_without_private_destination_is_indeterminate() {
        let home = tempfile::tempdir().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.bin");
        let destination = directory.path().join("destination.bin");
        std::fs::write(&source, b"same-secret").unwrap();

        let error = execute_file_copy_at(
            home.path(),
            &source,
            &destination,
            1_800_000_000,
            |checkpoint| {
                if checkpoint == FileCopyCheckpoint::BeforeDestinationPublish {
                    std::fs::write(&destination, b"same-secret").unwrap();
                    use std::os::unix::fs::PermissionsExt as _;
                    std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o644))
                        .unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("could not be reconciled"));
        assert_eq!(std::fs::read(&destination).unwrap(), b"same-secret");
        assert_eq!(journal_phase(home.path()), "indeterminate");
    }

    #[test]
    fn hardlink_race_to_source_is_never_accepted_as_a_copy() {
        let home = tempfile::tempdir().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.bin");
        let destination = directory.path().join("destination.bin");
        std::fs::write(&source, b"hardlink-secret").unwrap();

        let error = execute_file_copy_at(
            home.path(),
            &source,
            &destination,
            1_800_000_000,
            |checkpoint| {
                if checkpoint == FileCopyCheckpoint::BeforeDestinationPublish {
                    std::fs::hard_link(&source, &destination).unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("not an independent target"));
        assert_eq!(std::fs::read(&source).unwrap(), b"hardlink-secret");
        assert_eq!(std::fs::read(&destination).unwrap(), b"hardlink-secret");
        assert_eq!(journal_phase(home.path()), "indeterminate");
    }
}
