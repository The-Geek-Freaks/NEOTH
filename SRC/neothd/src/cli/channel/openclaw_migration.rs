//! One source-bound, reversible, file-backed OpenClaw account migration.
//! Provider probing is the only injected external effect in coordinator tests.

use std::ffi::OsStr;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::{
    SlackProbeBinding, SlackProbeOutcome, probe_slack_account_binding_with,
    resolve_slack_probe_binding,
};
use crate::channels::registry::ChannelAccountId;
use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::config::credentials::{Credentials, with_coherent_pair_transaction_at};
use crate::secret::SecretString;
use crate::skills::store;

mod participants;
use participants::{
    PairState, ParticipantCustody, ParticipantKind, PreparedParticipant, PrivateRequest,
    ProbeBinding, ProbeOutcome, SelectedSource,
};

const MAX_REQUEST: usize = 8 * 1024;
const MAX_RECORD: usize = 16 * 1024;
const MAX_PAIR: usize = 64 * 1024 * 1024;
const PROBE_VALIDITY: Duration = Duration::from_secs(60);

#[derive(Subcommand, Debug)]
pub enum OpenclawMigrationAction {
    /// Bind one supported Slack or Telegram account and the current target pair.
    Plan {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        request: PathBuf,
    },
    /// Verify and apply the exact plan; resupply the same private inputs on retry.
    Apply {
        #[arg(long)]
        id: String,
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long, required = true)]
        confirm: bool,
    },
    /// Inspect persisted evidence and the actual config/credentials generation.
    Status {
        #[arg(long)]
        id: String,
    },
    /// Restore the exact prior pair only while this operation still owns it.
    Rollback {
        #[arg(long)]
        id: String,
        #[arg(long, required = true)]
        confirm: bool,
    },
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Plan {
    version: u8,
    id: String,
    source_binding: String,
    request_binding: String,
    pair_before: String,
    // Absent for existing Slack v1 plans: serialization and plan hashes stay
    // unchanged. Only v2 Telegram plans carry an explicit participant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    participant: Option<ParticipantKind>,
}

impl Plan {
    fn kind(&self) -> ParticipantKind {
        self.participant.unwrap_or(ParticipantKind::Slack)
    }
    fn valid_version(&self) -> bool {
        matches!(
            (self.version, self.participant),
            (1, None) | (2, Some(ParticipantKind::Telegram))
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Planned,
    Applying,
    Committed,
    RollingBack,
    RolledBack,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum HoldReason {
    SourceOrRequestChanged,
    TargetDrift,
    CustodyInvalid,
    ReceiptInvalid,
    RollbackPending,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u8,
    plan_binding: String,
    phase: Phase,
    custody_binding: Option<String>,
    held: Option<HoldReason>,
    reload_for: Option<Phase>,
}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Terminal {
    version: u8,
    plan_binding: String,
    custody_binding: String,
    pair_before: String,
    pair_after: String,
    phase: Phase,
}

#[derive(Debug, Serialize)]
struct Status {
    schema_version: u8,
    id: String,
    phase: Phase,
    pair_state: &'static str,
    committed_steps: u8,
    reversed_steps: u8,
    held: bool,
    reason: Option<HoldReason>,
    participants: u8,
    reload_requested: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Checkpoint {
    CustodySaved,
    ApplyingRecorded,
    PairPublished,
    ForwardReceiptSaved,
    CommittedRecorded,
    ForwardReloadRecorded,
    RollingBackRecorded,
    PairRestored,
    ReverseReceiptSaved,
    RolledBackRecorded,
    ReverseReloadRecorded,
}

/// A capability-bound operation directory and one OS lock held across the
/// external probe. The config-pair authority is acquired only synchronously.
struct OperationStore {
    home: PathBuf,
    directory: store::BoundDirectory,
    id: String,
    _lock: std::fs::File,
}

impl OperationStore {
    fn open(home: &Path, id: &str, create: bool) -> Result<Self> {
        let uuid = uuid::Uuid::parse_str(id).context("invalid migration id")?;
        ensure!(
            uuid.hyphenated().to_string() == id,
            "noncanonical migration id"
        );
        let home = std::path::absolute(home)?;
        let directory = store::open_bound_directory(
            &home.join("openclaw-migrations"),
            create,
            "private migration journal",
        )?
        .context("migration journal is absent")?;
        let name = format!("{id}.lock");
        let (lock, _) = store::open_or_create_bound_lockfile(
            &directory.dir,
            OsStr::new(&name),
            &directory.physical_display_path.join(&name),
        )?;
        lock.try_lock()
            .context("migration operation is already active")?;
        Ok(Self {
            home,
            directory,
            id: id.to_owned(),
            _lock: lock,
        })
    }

    fn read<T: DeserializeOwned>(&self, suffix: &str) -> Result<Option<T>> {
        let name = format!("{}.{suffix}.json", self.id);
        match self.directory.dir.symlink_metadata(&name) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
            Ok(_) => {
                let bytes = store::read_regular_file_bounded(
                    &self.directory.dir,
                    OsStr::new(&name),
                    &self.directory.physical_display_path.join(&name),
                    MAX_RECORD,
                )?;
                Ok(Some(
                    serde_json::from_slice(&bytes).context("invalid migration record")?,
                ))
            }
        }
    }

    fn write<T: Serialize>(&self, suffix: &str, record: &T, create: bool) -> Result<()> {
        let name = format!("{}.{suffix}.json", self.id);
        let path = self.directory.physical_display_path.join(&name);
        let bytes = serde_json::to_vec(record)?;
        ensure!(bytes.len() <= MAX_RECORD, "migration record exceeds bound");
        if create {
            store::atomic_write_private_child_create_new(
                &self.directory.dir,
                OsStr::new(&name),
                &path,
                &bytes,
            )
        } else {
            store::atomic_write_private_child(&self.directory.dir, OsStr::new(&name), &path, &bytes)
        }
    }

    fn load(&self) -> Result<(Plan, State)> {
        let plan: Plan = self.read("plan")?.context("migration plan absent")?;
        ensure!(
            plan.valid_version() && plan.id == self.id,
            "migration plan identity invalid"
        );
        for digest in [
            &plan.source_binding,
            &plan.request_binding,
            &plan.pair_before,
        ] {
            validate_digest(digest)?;
        }
        let binding = plan_binding(&plan)?;
        let state = match self.read::<State>("state")? {
            Some(state) => state,
            None => {
                // Only the plan-to-initial-state crash window permits absence.
                // Losing a later journal must not erase a rollback direction.
                ensure!(
                    ParticipantCustody::load_optional_at(
                        plan.kind(),
                        &self.home.join("freedom.yaml"),
                        &self.id,
                        &binding
                    )?
                    .is_none()
                        && self.read::<Terminal>("committed")?.is_none()
                        && self.read::<Terminal>("rolled-back")?.is_none(),
                    "migration state is missing after custody publication"
                );
                State {
                    version: 1,
                    plan_binding: binding.clone(),
                    phase: Phase::Planned,
                    custody_binding: None,
                    held: None,
                    reload_for: None,
                }
            }
        };
        ensure!(
            state.version == 1 && state.plan_binding == binding,
            "migration state belongs to a different plan"
        );
        if let Some(digest) = &state.custody_binding {
            validate_digest(digest)?;
        }
        ensure!(
            state
                .reload_for
                .is_none_or(|phase| matches!(phase, Phase::Committed | Phase::RolledBack)),
            "invalid reload generation"
        );
        Ok((plan, state))
    }

    fn custody(&self, plan: &Plan, state: &mut State) -> Result<Option<ParticipantCustody>> {
        let binding = plan_binding(plan)?;
        match ParticipantCustody::load_optional_at(
            plan.kind(),
            &self.home.join("freedom.yaml"),
            &self.id,
            &binding,
        )? {
            None => {
                ensure!(
                    state.custody_binding.is_none() && state.phase == Phase::Planned,
                    "recorded migration custody is absent"
                );
                Ok(None)
            }
            Some(custody) => {
                ensure!(
                    custody.before_sha256() == plan.pair_before,
                    "custody differs from planned pair baseline"
                );
                let digest = custody.custody_sha256();
                if let Some(expected) = &state.custody_binding {
                    ensure!(expected == &digest, "migration custody was replaced");
                } else {
                    state.custody_binding = Some(digest);
                }
                Ok(Some(custody))
            }
        }
    }

    fn observe(&self, plan: &Plan, custody: &ParticipantCustody) -> Result<PairState> {
        custody.inspect_at(
            &self.home.join("freedom.yaml"),
            &self.home.join("credentials.yaml"),
            &self.id,
            &plan_binding(plan)?,
        )
    }

    fn terminal(
        &self,
        plan: &Plan,
        custody: &ParticipantCustody,
        phase: Phase,
        create: bool,
    ) -> Result<bool> {
        ensure!(
            matches!(phase, Phase::Committed | Phase::RolledBack),
            "invalid terminal phase"
        );
        let suffix = if phase == Phase::Committed {
            "committed"
        } else {
            "rolled-back"
        };
        let expected = Terminal {
            version: 1,
            plan_binding: plan_binding(plan)?,
            custody_binding: custody.custody_sha256(),
            pair_before: custody.before_sha256().to_owned(),
            pair_after: custody.after_sha256().to_owned(),
            phase,
        };
        if let Some(existing) = self.read::<Terminal>(suffix)? {
            ensure!(
                existing == expected,
                "immutable terminal migration receipt differs"
            );
            Ok(true)
        } else if create {
            self.write(suffix, &expected, true)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn hold<T>(&self, state: &mut State, reason: HoldReason) -> Result<T> {
        // Retain the durable direction. A held rollback must never become an
        // eligible forward apply simply because a diagnostic was recorded.
        state.held = Some(reason);
        self.write("state", state, false)?;
        anyhow::bail!("migration held: {reason:?}")
    }
}

pub async fn run(action: OpenclawMigrationAction, output: &OutputFormat) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let outcome = match action {
        OpenclawMigrationAction::Plan { config, request } => plan_at(&home, &config, &request),
        OpenclawMigrationAction::Apply {
            id,
            config,
            request,
            confirm,
        } => {
            ensure!(confirm, "apply requires --confirm");
            apply_participant_at_with(&home, &id, &config, &request, participants::probe, |_| {
                Ok(())
            })
            .await
        }
        OpenclawMigrationAction::Status { id } => status_at(&home, &id),
        OpenclawMigrationAction::Rollback { id, confirm } => {
            ensure!(confirm, "rollback requires --confirm");
            rollback_at_with(&home, &id, |_| Ok(()))
        }
    };
    // Errors from source/schema/provider/file internals may contain private
    // inputs. Public diagnostics deliberately expose no nested error chain.
    let status = outcome.map_err(|_| {
        anyhow::anyhow!(
            "OpenClaw migration refused; inspect the operation status and original private inputs"
        )
    })?;
    match output {
        OutputFormat::Table => println!(
            "openclaw migration {}: {:?}, pair={}, held={}, reload_requested={}",
            status.id, status.phase, status.pair_state, status.held, status.reload_requested
        ),
        OutputFormat::Json | OutputFormat::Jsonl => println!("{}", serde_json::to_string(&status)?),
    }
    Ok(())
}

fn plan_at(home: &Path, config: &Path, request_path: &Path) -> Result<Status> {
    let request = load_request(request_path)?;
    let selected = select_source(config, &request)?;
    let source_binding = source_binding(selected.source_set())?;
    let request_binding = request_binding(&request)?;
    let id = uuid::Uuid::now_v7().to_string();
    let store = OperationStore::open(home, &id, true)?;
    let plan = with_coherent_pair_transaction_at(&store.home.join("freedom.yaml"), || {
        let plan = Plan {
            version: if request.kind() == ParticipantKind::Slack {
                1
            } else {
                2
            },
            id: id.clone(),
            source_binding,
            request_binding,
            pair_before: pair_baseline(&store.home, request.kind())?,
            participant: (request.kind() != ParticipantKind::Slack).then_some(request.kind()),
        };
        // The ordinary prepared candidate validates the supported backend,
        // account policy and credential shape, without publishing target data.
        let _candidate = prepare_candidate(&store.home, &plan, &request, selected)?;
        recheck_source(&plan, config, &request)?;
        Ok(plan)
    })?;
    store.write("plan", &plan, true)?;
    let (_, state) = store.load()?;
    store.write("state", &state, true)?;
    Ok(make_status(&plan, &state, "before", true))
}

async fn apply_participant_at_with<P, F>(
    home: &Path,
    id: &str,
    config: &Path,
    request_path: &Path,
    probe: P,
    mut checkpoint: impl FnMut(Checkpoint) -> Result<()>,
) -> Result<Status>
where
    P: FnOnce(ProbeBinding) -> F,
    F: Future<Output = Result<ProbeOutcome>>,
{
    let store = OperationStore::open(home, id, false)?;
    let (plan, mut state) = store.load()?;
    let request = match load_request(request_path).and_then(|request| {
        ensure!(
            request.kind() == plan.kind() && request_binding(&request)? == plan.request_binding,
            "request differs from plan"
        );
        recheck_source(&plan, config, &request)?;
        Ok(request)
    }) {
        Ok(request) => request,
        Err(_) => return store.hold(&mut state, HoldReason::SourceOrRequestChanged),
    };
    let custody = match store.custody(&plan, &mut state) {
        Ok(value) => value,
        Err(_) => return store.hold(&mut state, HoldReason::CustodyInvalid),
    };
    if matches!(state.phase, Phase::RollingBack | Phase::RolledBack)
        || store.read::<Terminal>("rolled-back")?.is_some()
    {
        return store.hold(&mut state, HoldReason::RollbackPending);
    }
    if let Some(custody) = &custody {
        match store.observe(&plan, custody)? {
            PairState::After => {
                return with_coherent_pair_transaction_at(&store.home.join("freedom.yaml"), || {
                    if recheck_inputs(&plan, config, request_path).is_err() {
                        return store.hold(&mut state, HoldReason::SourceOrRequestChanged);
                    }
                    ensure!(
                        store.observe(&plan, custody)? == PairState::After,
                        "pair drift before terminal receipt"
                    );
                    if state.phase == Phase::Committed
                        && !store
                            .terminal(&plan, custody, Phase::Committed, false)
                            .unwrap_or(false)
                    {
                        return store.hold(&mut state, HoldReason::ReceiptInvalid);
                    }
                    finish(
                        &store,
                        &plan,
                        &mut state,
                        custody,
                        Phase::Committed,
                        &mut checkpoint,
                    )
                });
            }
            PairState::Mixed => return store.hold(&mut state, HoldReason::TargetDrift),
            PairState::Before => {
                if state.phase == Phase::Committed || store.read::<Terminal>("committed")?.is_some()
                {
                    return store.hold(&mut state, HoldReason::TargetDrift);
                }
            }
        }
    }
    let prepared = with_coherent_pair_transaction_at(&store.home.join("freedom.yaml"), || {
        ensure!(
            pair_baseline(&store.home, plan.kind())? == plan.pair_before,
            "target differs from plan"
        );
        let selected = select_source(config, &request)?;
        ensure!(
            source_binding(selected.source_set())? == plan.source_binding,
            "source changed before preparation"
        );
        prepare_candidate(&store.home, &plan, &request, selected)
    })?;
    let binding = prepared.probe_binding()?;
    let started = Instant::now();
    let outcome = tokio::time::timeout(PROBE_VALIDITY, probe(binding))
        .await
        .context("migration probe timed out")??;
    let evidence = outcome.evidence(plan.kind())?;
    if recheck_inputs(&plan, config, request_path).is_err() {
        return store.hold(&mut state, HoldReason::SourceOrRequestChanged);
    }
    with_coherent_pair_transaction_at(&store.home.join("freedom.yaml"), || {
        ensure!(
            started.elapsed() < PROBE_VALIDITY,
            "migration probe expired"
        );
        if recheck_inputs(&plan, config, request_path).is_err() {
            return store.hold(&mut state, HoldReason::SourceOrRequestChanged);
        }
        if pair_baseline(&store.home, plan.kind())? != plan.pair_before {
            return store.hold(&mut state, HoldReason::TargetDrift);
        }
        let custody = if let Some(custody) = custody {
            custody.validate_retry(&request, &evidence)?;
            custody
        } else {
            let custody = prepared.persist(&evidence)?;
            checkpoint(Checkpoint::CustodySaved)?;
            custody
        };
        ensure!(
            custody.before_sha256() == plan.pair_before,
            "prepared before image differs from plan"
        );
        state.custody_binding = Some(custody.custody_sha256());
        state.phase = Phase::Applying;
        state.held = None;
        store.write("state", &state, false)?;
        checkpoint(Checkpoint::ApplyingRecorded)?;
        ensure!(
            started.elapsed() < PROBE_VALIDITY,
            "migration probe expired before publication"
        );
        if recheck_inputs(&plan, config, request_path).is_err() {
            return store.hold(&mut state, HoldReason::SourceOrRequestChanged);
        }
        let committed = custody.commit_if_before_at(
            &store.home.join("freedom.yaml"),
            &store.home.join("credentials.yaml"),
            id,
            &plan_binding(&plan)?,
        )?;
        ensure!(
            committed.before_sha256 == plan.pair_before
                && committed.after_sha256 == custody.after_sha256(),
            "participant commitment differs from custody"
        );
        checkpoint(Checkpoint::PairPublished)?;
        ensure!(
            store.observe(&plan, &custody)? == PairState::After,
            "migration pair publication is not exact"
        );
        finish(
            &store,
            &plan,
            &mut state,
            &custody,
            Phase::Committed,
            &mut checkpoint,
        )
    })
}

fn rollback_at_with(
    home: &Path,
    id: &str,
    mut checkpoint: impl FnMut(Checkpoint) -> Result<()>,
) -> Result<Status> {
    let store = OperationStore::open(home, id, false)?;
    let (plan, mut state) = store.load()?;
    let custody = store
        .custody(&plan, &mut state)?
        .context("migration has no published custody to roll back")?;
    with_coherent_pair_transaction_at(&store.home.join("freedom.yaml"), || {
        let observed = store.observe(&plan, &custody)?;
        let terminal = store.terminal(&plan, &custody, Phase::RolledBack, false)?;
        if terminal || state.phase == Phase::RolledBack {
            if !terminal || observed != PairState::Before {
                return store.hold(&mut state, HoldReason::TargetDrift);
            }
            return finish(
                &store,
                &plan,
                &mut state,
                &custody,
                Phase::RolledBack,
                &mut checkpoint,
            );
        }
        match observed {
            PairState::Mixed => return store.hold(&mut state, HoldReason::TargetDrift),
            PairState::Before if state.phase != Phase::RollingBack => {
                return store.hold(&mut state, HoldReason::TargetDrift);
            }
            PairState::Before => {}
            PairState::After => {
                state.phase = Phase::RollingBack;
                state.held = None;
                store.write("state", &state, false)?;
                checkpoint(Checkpoint::RollingBackRecorded)?;
                custody.rollback_if_exact_at(
                    &store.home.join("freedom.yaml"),
                    &store.home.join("credentials.yaml"),
                    id,
                    &plan_binding(&plan)?,
                )?;
                checkpoint(Checkpoint::PairRestored)?;
            }
        }
        ensure!(
            store.observe(&plan, &custody)? == PairState::Before,
            "rollback pair is not exact"
        );
        finish(
            &store,
            &plan,
            &mut state,
            &custody,
            Phase::RolledBack,
            &mut checkpoint,
        )
    })
}

fn finish(
    store: &OperationStore,
    plan: &Plan,
    state: &mut State,
    custody: &ParticipantCustody,
    phase: Phase,
    checkpoint: &mut impl FnMut(Checkpoint) -> Result<()>,
) -> Result<Status> {
    let forward = phase == Phase::Committed;
    store.terminal(plan, custody, phase, true)?;
    checkpoint(if forward {
        Checkpoint::ForwardReceiptSaved
    } else {
        Checkpoint::ReverseReceiptSaved
    })?;
    if state.phase != phase || state.held.is_some() {
        state.phase = phase;
        state.held = None;
        store.write("state", state, false)?;
    }
    checkpoint(if forward {
        Checkpoint::CommittedRecorded
    } else {
        Checkpoint::RolledBackRecorded
    })?;
    if state.reload_for != Some(phase) {
        // Crash after sentinel write but before state write may request another
        // reload. This is at-least-once convergence, never a live-readiness claim.
        crate::cli::reload::request_reload_at(&store.home)?;
        state.reload_for = Some(phase);
        store.write("state", state, false)?;
    }
    checkpoint(if forward {
        Checkpoint::ForwardReloadRecorded
    } else {
        Checkpoint::ReverseReloadRecorded
    })?;
    Ok(make_status(
        plan,
        state,
        if forward { "after" } else { "before" },
        true,
    ))
}

fn status_at(home: &Path, id: &str) -> Result<Status> {
    let store = OperationStore::open(home, id, false)?;
    let (plan, mut state) = store.load()?;
    let custody = match store.custody(&plan, &mut state) {
        Ok(value) => value,
        Err(_) => {
            state.held = Some(HoldReason::CustodyInvalid);
            return Ok(make_status(&plan, &state, "custody_invalid", false));
        }
    };
    with_coherent_pair_transaction_at(&store.home.join("freedom.yaml"), || {
        let Some(custody) = custody else {
            let valid = pair_baseline(&store.home, plan.kind())? == plan.pair_before;
            return Ok(make_status(
                &plan,
                &state,
                if valid { "before" } else { "drift" },
                valid,
            ));
        };
        let observed = store.observe(&plan, &custody)?;
        let terminal_valid = if matches!(state.phase, Phase::Committed | Phase::RolledBack) {
            match store.terminal(&plan, &custody, state.phase, false) {
                Ok(true) => true,
                Ok(false) | Err(_) => {
                    state.held = Some(HoldReason::ReceiptInvalid);
                    false
                }
            }
        } else {
            true
        };
        let consistent = terminal_valid
            && match state.phase {
                Phase::Committed => observed == PairState::After,
                Phase::RolledBack => observed == PairState::Before,
                _ => observed != PairState::Mixed,
            };
        let pair_state = match observed {
            PairState::Before => "before",
            PairState::After => "after",
            PairState::Mixed => "drift",
        };
        Ok(make_status(&plan, &state, pair_state, consistent))
    })
}

fn make_status(plan: &Plan, state: &State, pair_state: &'static str, consistent: bool) -> Status {
    Status {
        schema_version: 1,
        id: plan.id.clone(),
        phase: state.phase,
        pair_state,
        committed_steps: u8::from(consistent && state.phase == Phase::Committed),
        reversed_steps: u8::from(consistent && state.phase == Phase::RolledBack),
        held: state.held.is_some() || !consistent,
        reason: state
            .held
            .or((!consistent).then_some(HoldReason::TargetDrift)),
        participants: 1,
        reload_requested: state.reload_for == Some(state.phase),
    }
}

fn prepare_candidate(
    home: &Path,
    plan: &Plan,
    request: &PrivateRequest,
    selected: SelectedSource,
) -> Result<PreparedParticipant> {
    selected.prepare(home, plan, request)
}

fn select_source(config: &Path, request: &PrivateRequest) -> Result<SelectedSource> {
    SelectedSource::select(config, request)
}

fn recheck_source(plan: &Plan, config: &Path, request: &PrivateRequest) -> Result<()> {
    ensure!(
        source_binding(select_source(config, request)?.source_set())? == plan.source_binding,
        "OpenClaw source binding changed"
    );
    Ok(())
}

fn recheck_inputs(plan: &Plan, config: &Path, request_path: &Path) -> Result<()> {
    let request = load_request(request_path)?;
    ensure!(
        request.kind() == plan.kind() && request_binding(&request)? == plan.request_binding,
        "request changed during operation"
    );
    recheck_source(plan, config, &request)
}

fn source_binding(binding: &neoth_openclaw_custody::SourceSetBinding) -> Result<String> {
    Ok(hash(
        b"neoth-openclaw-migration-source-v1\0",
        &serde_json::to_vec(binding)?,
    ))
}

fn request_binding(request: &PrivateRequest) -> Result<String> {
    request.binding()
}

fn plan_binding(plan: &Plan) -> Result<String> {
    Ok(hash(
        if plan.version == 1 {
            b"neoth-openclaw-migration-plan-v1\0"
        } else {
            b"neoth-openclaw-migration-plan-v2\0"
        },
        &serde_json::to_vec(plan)?,
    ))
}
fn hash(domain: &[u8], bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(domain);
    h.update((bytes.len() as u64).to_le_bytes());
    h.update(bytes);
    format!("{:x}", h.finalize())
}
fn validate_digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid migration binding"
    );
    Ok(())
}

fn load_request(path: &Path) -> Result<PrivateRequest> {
    let absolute = std::path::absolute(path)?;
    let parent = absolute.parent().context("request parent absent")?;
    let name = absolute.file_name().context("request file absent")?;
    let bound = store::open_bound_directory(parent, false, "migration request parent")?
        .context("request parent absent")?;
    let bytes = Zeroizing::new(store::read_regular_file_bounded(
        &bound.dir,
        name,
        &absolute,
        MAX_REQUEST,
    )?);
    let request: PrivateRequest =
        serde_json::from_slice(&bytes).context("invalid private migration request")?;
    request.validate()?;
    Ok(request)
}

fn pair_baseline(home: &Path, kind: ParticipantKind) -> Result<String> {
    let bound = store::open_bound_directory(home, false, "migration target home")?
        .context("target home absent")?;
    let mut digest = Sha256::new();
    // Same exact raw-pair commitment as the private credential participant.
    digest.update(kind.pair_domain());
    for name in ["freedom.yaml", "credentials.yaml"] {
        digest.update(name.as_bytes());
        digest.update([0]);
        match bound.dir.symlink_metadata(name) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => digest.update([0]),
            Err(error) => return Err(error.into()),
            Ok(_) => {
                let bytes = Zeroizing::new(store::read_regular_file_bounded(
                    &bound.dir,
                    OsStr::new(name),
                    &bound.physical_display_path.join(name),
                    MAX_PAIR,
                )?);
                digest.update([1]);
                digest.update((bytes.len() as u64).to_le_bytes());
                digest.update(bytes.as_slice());
            }
        }
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod telegram_tests;
