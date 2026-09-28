//! One aggregate, file-backed custody for an ordered Slack/Telegram migration batch.
//!
//! Single-account migration custody deliberately remains untouched.  This module
//! owns one raw pair before-image and one raw pair after-image, so it cannot
//! expose an account-by-account publication prefix.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize;

use super::{
    Credentials, FileSnapshot, InlineTelegramTokenPolicy, JournalFileSnapshot,
    SlackAccountCredentials, TelegramAccountCredentials, publish_prepared_file_pair,
    render_freedom_preserving_unknown_yaml, sibling_credentials_path, transaction_directory,
    validate_exact_pair_target, with_config_writer_guard, with_dual_file_transaction_lock,
    with_legacy_pair_locks,
};
use crate::channels::registry::ChannelAccountId;
use crate::config::{
    AccountIncarnation, FreedomConfig, RuntimeConfigPair, SecretsBackend, SlackAccountConfig,
    TelegramAccountConfig,
};
use crate::secret::SecretString;

const VERSION: u8 = 1;
const PREFIX: &str = ".openclaw-file-batch-migration-";
const SUFFIX: &str = ".custody.yaml";
const MAX_PARTICIPANTS: usize = 32;
const PAIR_DOMAIN: &[u8] = b"neoth-openclaw-file-batch-migration-pair-v1\0";
const CUSTODY_DOMAIN: &[u8] = b"neoth-openclaw-file-batch-migration-custody-v1\0";

/// Private source material. Public status and participant metadata omit tokens;
/// the private recovery record necessarily retains credential file snapshots.
pub(crate) enum FileMigrationInput {
    Slack {
        account: ChannelAccountId,
        allowed_user_id: String,
        bot_token: SecretString,
        app_token: SecretString,
    },
    Telegram {
        account: ChannelAccountId,
        allowed_user_id: u64,
        token: SecretString,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "channel", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum FileMigrationParticipant {
    Slack { account: ChannelAccountId },
    Telegram { account: ChannelAccountId },
}

pub(crate) struct PreparedFileMigrationBatch {
    freedom_path: PathBuf,
    credentials_path: PathBuf,
    operation_id: String,
    plan_binding: String,
    before_freedom: FileSnapshot,
    before_credentials: FileSnapshot,
    config_before: FreedomConfig,
    config: FreedomConfig,
    credentials: Credentials,
    participants: Vec<FileMigrationParticipant>,
    candidate: RuntimeConfigPair,
}

pub(crate) struct FileMigrationBatchCustody {
    path: PathBuf,
    freedom_path: PathBuf,
    credentials_path: PathBuf,
    record: BatchCustodyRecord,
}
pub(crate) enum FileMigrationBatchCustodyLoad {
    Absent,
    Present(Box<FileMigrationBatchCustody>),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FileMigrationBatchState {
    Before,
    After,
    Mixed,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FileMigrationBatchCommit {
    pub(crate) before_sha256: String,
    pub(crate) after_sha256: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct BatchCustodyRecord {
    version: u8,
    operation_id: String,
    plan_binding: String,
    freedom_file: String,
    credentials_file: String,
    participants: Vec<CustodyParticipant>,
    freedom_before: JournalFileSnapshot,
    credentials_before: JournalFileSnapshot,
    freedom_after: JournalFileSnapshot,
    credentials_after: JournalFileSnapshot,
    before_sha256: String,
    after_sha256: String,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "channel", rename_all = "snake_case", deny_unknown_fields)]
enum CustodyParticipant {
    Slack {
        account: String,
        allowed_user_id: String,
        verified_team_id: String,
        incarnation: String,
    },
    Telegram {
        account: String,
        allowed_user_id: u64,
        incarnation: String,
    },
}

impl Credentials {
    pub(crate) fn prepare_file_migration_batch_at(
        freedom_path: &Path,
        credentials_path: &Path,
        inputs: Vec<FileMigrationInput>,
        operation_id: &str,
        plan_binding: &str,
    ) -> Result<PreparedFileMigrationBatch> {
        validate_binding(operation_id, plan_binding)?;
        ensure!(!inputs.is_empty(), "file migration batch is empty");
        ensure!(
            inputs.len() <= MAX_PARTICIPANTS,
            "file migration batch exceeds {MAX_PARTICIPANTS} participants"
        );
        ensure!(
            transaction_directory(freedom_path) == transaction_directory(credentials_path),
            "file migration batch pair paths are not siblings"
        );
        with_dual_file_transaction_lock(freedom_path, || {
            with_config_writer_guard(freedom_path, || {
                with_legacy_pair_locks(freedom_path, credentials_path, || {
                    validate_targets(freedom_path, credentials_path)?;
                    let before_freedom = FileSnapshot::capture(freedom_path)?;
                    let before_credentials = FileSnapshot::capture(credentials_path)?;
                    let config_before =
                        FreedomConfig::load_public_from_path_unlocked(freedom_path)?;
                    ensure!(
                        config_before.secrets_backend == SecretsBackend::File,
                        "file migration batch requires the file secrets backend"
                    );
                    let mut config = config_before.clone();
                    let mut credentials = Self::load_or_default_unlocked(credentials_path)?;
                    ensure!(
                        config.telegram_token.is_none()
                            && config.telegram_user_id.is_none()
                            && credentials.telegram_token.is_none(),
                        "legacy Telegram scalar fields cannot coexist with a file migration batch"
                    );
                    ensure!(
                        credentials.slack_bot_token.is_none()
                            && credentials.slack_app_token.is_none()
                            && credentials.slack_allowed_user_id.is_none(),
                        "legacy Slack scalar fields cannot coexist with a file migration batch"
                    );
                    ensure!(
                        config
                            .channel_accounts
                            .telegram
                            .keys()
                            .eq(credentials.channel_accounts.telegram.keys()),
                        "Telegram policy and credential account keys must match before batch"
                    );
                    ensure!(
                        config
                            .channel_accounts
                            .slack
                            .keys()
                            .eq(credentials.channel_accounts.slack.keys()),
                        "Slack policy and credential account keys must match before batch"
                    );
                    for policy in config.channel_accounts.telegram.values() {
                        ensure!(
                            policy.allowed_user_id != 0,
                            "existing Telegram account has invalid allowed_user_id"
                        );
                    }
                    for (account, policy) in &config.channel_accounts.slack {
                        crate::channels::slack::normalize_allowed_user_id(&policy.allowed_user_id)
                            .with_context(|| {
                                format!(
                                    "existing Slack account `{account}` has invalid allowed_user_id"
                                )
                            })?;
                        let secrets = credentials
                            .channel_accounts
                            .slack
                            .get(account)
                            .context("matched existing Slack credential is absent")?;
                        ensure!(
                            secrets
                                .bot_token
                                .as_ref()
                                .is_some_and(|token| !token.expose().trim().is_empty())
                                && secrets
                                    .app_token
                                    .as_ref()
                                    .is_some_and(|token| !token.expose().trim().is_empty()),
                            "existing Slack account `{account}` has incomplete file credentials"
                        );
                    }
                    let mut seen = BTreeSet::new();
                    let mut participants = Vec::with_capacity(inputs.len());
                    for input in inputs {
                        match input {
                            FileMigrationInput::Telegram {
                                account,
                                allowed_user_id,
                                token,
                            } => {
                                ensure!(
                                    allowed_user_id != 0,
                                    "Telegram account allowed_user_id must be nonzero"
                                );
                                ensure!(
                                    !token.expose().trim().is_empty(),
                                    "Telegram account token must be non-blank"
                                );
                                ensure!(
                                    seen.insert(("telegram", account.to_string())),
                                    "duplicate Telegram target account"
                                );
                                let existing = config.channel_accounts.telegram.get(&account);
                                let policy = TelegramAccountConfig {
                                    allowed_user_id,
                                    incarnation: Some(
                                        existing
                                            .and_then(|p| p.incarnation.clone())
                                            .unwrap_or_else(AccountIncarnation::new_random),
                                    ),
                                    dm_pairing: existing.and_then(|p| p.dm_pairing.clone()),
                                };
                                config
                                    .channel_accounts
                                    .telegram
                                    .insert(account.clone(), policy);
                                credentials.channel_accounts.telegram.insert(
                                    account.clone(),
                                    TelegramAccountCredentials { token: Some(token) },
                                );
                                participants.push(FileMigrationParticipant::Telegram { account });
                            }
                            FileMigrationInput::Slack {
                                account,
                                allowed_user_id,
                                bot_token,
                                app_token,
                            } => {
                                let allowed_user_id =
                                    crate::channels::slack::normalize_allowed_user_id(
                                        &allowed_user_id,
                                    )
                                    .context("Slack account allowed_user_id is invalid")?;
                                ensure!(
                                    !bot_token.expose().trim().is_empty()
                                        && !app_token.expose().trim().is_empty(),
                                    "Slack account tokens must be non-blank"
                                );
                                ensure!(
                                    seen.insert(("slack", account.to_string())),
                                    "duplicate Slack target account"
                                );
                                let team_id = config
                                    .channel_accounts
                                    .slack
                                    .get(&account)
                                    .and_then(|p| p.team_id.clone());
                                config.channel_accounts.slack.insert(
                                    account.clone(),
                                    SlackAccountConfig {
                                        allowed_user_id,
                                        team_id,
                                        incarnation: Some(AccountIncarnation::new_random()),
                                    },
                                );
                                credentials.channel_accounts.slack.insert(
                                    account.clone(),
                                    SlackAccountCredentials {
                                        bot_token: Some(bot_token),
                                        app_token: Some(app_token),
                                    },
                                );
                                participants.push(FileMigrationParticipant::Slack { account });
                            }
                        }
                    }
                    let candidate = RuntimeConfigPair {
                        config: config.clone(),
                        raw_credentials: credentials.clone(),
                        credentials: credentials.clone(),
                    };
                    ensure!(
                        candidate.authenticated_telegram_accounts()?.len()
                            == config.channel_accounts.telegram.len()
                            && candidate.authenticated_slack_accounts()?.len()
                                == config.channel_accounts.slack.len(),
                        "file migration batch candidate authentication is incomplete"
                    );
                    Ok(PreparedFileMigrationBatch {
                        freedom_path: freedom_path.to_path_buf(),
                        credentials_path: credentials_path.to_path_buf(),
                        operation_id: operation_id.to_owned(),
                        plan_binding: plan_binding.to_owned(),
                        before_freedom,
                        before_credentials,
                        config_before,
                        config,
                        credentials,
                        participants,
                        candidate,
                    })
                })
            })
        })
    }
}

impl PreparedFileMigrationBatch {
    pub(crate) fn candidate_pair(&self) -> &RuntimeConfigPair {
        &self.candidate
    }
    pub(crate) fn participants(&self) -> &[FileMigrationParticipant] {
        &self.participants
    }
    pub(crate) fn persist_custody(
        mut self,
        verified_teams: &[Option<String>],
    ) -> Result<FileMigrationBatchCustody> {
        ensure!(
            verified_teams.len() == self.participants.len(),
            "file migration verified-team vector length differs from participants"
        );
        for (participant, verified) in self.participants.iter().zip(verified_teams) {
            match participant {
                FileMigrationParticipant::Slack { account } => {
                    let team = verified
                        .as_deref()
                        .context("Slack batch participant needs verified team id")?;
                    let team = crate::config::normalize_slack_team_id(team)
                        .context("verified Slack team_id is invalid")?;
                    let original = self.config_before.channel_accounts.slack.get(account);
                    let old_team = original
                        .and_then(|p| p.team_id.as_deref())
                        .map(crate::config::normalize_slack_team_id)
                        .transpose()
                        .context("stored Slack team_id is invalid")?;
                    let incarnation = match old_team.as_deref() {
                        Some(old) if old == team.as_str() => original
                            .and_then(|p| p.incarnation.clone())
                            .unwrap_or_else(AccountIncarnation::new_random),
                        _ => AccountIncarnation::new_random(),
                    };
                    let policy = self
                        .config
                        .channel_accounts
                        .slack
                        .get_mut(account)
                        .context("prepared Slack policy absent")?;
                    policy.team_id = Some(team);
                    policy.incarnation = Some(incarnation);
                }
                FileMigrationParticipant::Telegram { .. } => ensure!(
                    verified.is_none(),
                    "Telegram batch participant must not carry a verified team"
                ),
            }
        }
        let after_freedom = FileSnapshot::Present(zeroize::Zeroizing::new(
            render_freedom_preserving_unknown_yaml(
                &self.config,
                &self.before_freedom,
                InlineTelegramTokenPolicy::Preserve,
            )?
            .as_bytes()
            .to_vec(),
        ));
        let after_credentials = self.credentials.rendered_file_snapshot_preserving_unknown(
            &self.credentials_path,
            &self.before_credentials,
        )?;
        FileMigrationBatchCustody::persist(self, after_freedom, after_credentials)
    }
}

impl FileMigrationBatchCustody {
    fn persist(
        prepared: PreparedFileMigrationBatch,
        after_freedom: FileSnapshot,
        after_credentials: FileSnapshot,
    ) -> Result<Self> {
        let path = custody_path(&prepared.freedom_path, &prepared.operation_id)?;
        let participants = custody_participants(&prepared.config, &prepared.participants)?;
        let record = BatchCustodyRecord {
            version: VERSION,
            operation_id: prepared.operation_id,
            plan_binding: prepared.plan_binding,
            freedom_file: "freedom.yaml".into(),
            credentials_file: "credentials.yaml".into(),
            participants,
            freedom_before: JournalFileSnapshot::from_file_snapshot(&prepared.before_freedom),
            credentials_before: JournalFileSnapshot::from_file_snapshot(
                &prepared.before_credentials,
            ),
            freedom_after: JournalFileSnapshot::from_file_snapshot(&after_freedom),
            credentials_after: JournalFileSnapshot::from_file_snapshot(&after_credentials),
            before_sha256: pair_hash(&prepared.before_freedom, &prepared.before_credentials),
            after_sha256: pair_hash(&after_freedom, &after_credentials),
        };
        let freedom = prepared.freedom_path;
        let credentials = prepared.credentials_path;
        with_pair_locks(&freedom, &credentials, || {
            validate_exact_pair_target(&path, "file migration batch custody")?;
            ensure!(
                FileSnapshot::capture(&freedom)?.same_as(&prepared.before_freedom)
                    && FileSnapshot::capture(&credentials)?.same_as(&prepared.before_credentials),
                "file migration batch changed before custody persistence"
            );
            validate_record(&record, &record.operation_id, &record.plan_binding)?;
            persist_record_create_new(&path, &record)?;
            Ok(Self {
                path,
                freedom_path: freedom.clone(),
                credentials_path: credentials.clone(),
                record,
            })
        })
    }

    pub(crate) fn load_optional_at(
        freedom: &Path,
        operation_id: &str,
        plan_binding: &str,
    ) -> Result<FileMigrationBatchCustodyLoad> {
        validate_binding(operation_id, plan_binding)?;
        validate_targets(freedom, &sibling_credentials_path(freedom))?;
        let path = custody_path(freedom, operation_id)?;
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(FileMigrationBatchCustodyLoad::Absent)
            }
            Err(error) => Err(error.into()),
            Ok(_) => Self::load_at(freedom, operation_id, plan_binding)
                .map(Box::new)
                .map(FileMigrationBatchCustodyLoad::Present),
        }
    }

    fn load_at(freedom: &Path, operation_id: &str, plan_binding: &str) -> Result<Self> {
        validate_binding(operation_id, plan_binding)?;
        let credentials = sibling_credentials_path(freedom);
        validate_targets(freedom, &credentials)?;
        let path = custody_path(freedom, operation_id)?;
        validate_exact_pair_target(&path, "file migration batch custody")?;
        let body = read_custody(&path)?.context("file migration batch custody missing")?;
        let record: BatchCustodyRecord =
            serde_yaml::from_slice(&body).context("parse file migration batch custody")?;
        validate_record(&record, operation_id, plan_binding)?;
        Ok(Self {
            path,
            freedom_path: freedom.to_path_buf(),
            credentials_path: credentials,
            record,
        })
    }

    pub(crate) fn before_sha256(&self) -> &str {
        &self.record.before_sha256
    }

    pub(crate) fn after_sha256(&self) -> &str {
        &self.record.after_sha256
    }

    pub(crate) fn custody_sha256(&self) -> String {
        custody_hash(&self.record)
    }

    pub(crate) fn validate_retry(&self, verified_teams: &[Option<String>]) -> Result<()> {
        ensure!(
            verified_teams.len() == self.record.participants.len(),
            "file migration batch retry team vector length differs"
        );
        for (stored, incoming) in self.record.participants.iter().zip(verified_teams) {
            match stored {
                CustodyParticipant::Slack {
                    verified_team_id, ..
                } => {
                    let incoming = incoming
                        .as_deref()
                        .map(crate::config::normalize_slack_team_id)
                        .transpose()?;
                    ensure!(
                        incoming.as_deref() == Some(verified_team_id.as_str()),
                        "verified Slack team changed during batch retry"
                    );
                }
                CustodyParticipant::Telegram { .. } => {
                    ensure!(incoming.is_none(), "Telegram retry carries team");
                }
            }
        }
        Ok(())
    }

    pub(crate) fn inspect_at(
        &self,
        freedom: &Path,
        credentials: &Path,
        operation_id: &str,
        plan_binding: &str,
    ) -> Result<FileMigrationBatchState> {
        self.require_identity(freedom, credentials, operation_id, plan_binding)?;
        with_pair_locks(freedom, credentials, || {
            self.ensure_unchanged()?;
            self.classify()
        })
    }

    pub(crate) fn commit_if_before_at(
        &self,
        freedom: &Path,
        credentials: &Path,
        operation_id: &str,
        plan_binding: &str,
    ) -> Result<FileMigrationBatchCommit> {
        self.publish(
            freedom,
            credentials,
            operation_id,
            plan_binding,
            true,
            |_| Ok(()),
        )?;
        Ok(FileMigrationBatchCommit {
            before_sha256: self.record.before_sha256.clone(),
            after_sha256: self.record.after_sha256.clone(),
        })
    }

    pub(crate) fn rollback_if_exact_at(
        &self,
        freedom: &Path,
        credentials: &Path,
        operation_id: &str,
        plan_binding: &str,
    ) -> Result<FileMigrationBatchState> {
        self.publish(
            freedom,
            credentials,
            operation_id,
            plan_binding,
            false,
            |_| Ok(()),
        )?;
        Ok(FileMigrationBatchState::Before)
    }

    fn require_identity(
        &self,
        freedom: &Path,
        credentials: &Path,
        operation_id: &str,
        plan_binding: &str,
    ) -> Result<()> {
        ensure!(
            freedom == self.freedom_path && credentials == self.credentials_path,
            "file migration batch custody belongs to a different home"
        );
        validate_binding(operation_id, plan_binding)?;
        validate_record(&self.record, operation_id, plan_binding)
    }

    // A previously loaded handle cannot authorize publication after its private
    // record was removed or replaced. Call only while the pair locks are held.
    fn ensure_unchanged(&self) -> Result<()> {
        validate_exact_pair_target(&self.path, "file migration batch custody")?;
        let body = read_custody(&self.path)?.context("file migration batch custody disappeared")?;
        let observed: BatchCustodyRecord = serde_yaml::from_slice(&body)?;
        validate_record(
            &observed,
            &self.record.operation_id,
            &self.record.plan_binding,
        )?;
        ensure!(
            observed == self.record,
            "file migration batch custody changed after loading"
        );
        Ok(())
    }

    fn snapshots(&self) -> Result<(FileSnapshot, FileSnapshot, FileSnapshot, FileSnapshot)> {
        Ok((
            self.record.freedom_before.decode("batch freedom_before")?,
            self.record
                .credentials_before
                .decode("batch credentials_before")?,
            self.record.freedom_after.decode("batch freedom_after")?,
            self.record
                .credentials_after
                .decode("batch credentials_after")?,
        ))
    }

    fn classify(&self) -> Result<FileMigrationBatchState> {
        let (fb, cb, fa, ca) = self.snapshots()?;
        let freedom = FileSnapshot::capture(&self.freedom_path)?;
        let credentials = FileSnapshot::capture(&self.credentials_path)?;
        Ok(if freedom.same_as(&fb) && credentials.same_as(&cb) {
            FileMigrationBatchState::Before
        } else if freedom.same_as(&fa) && credentials.same_as(&ca) {
            FileMigrationBatchState::After
        } else {
            FileMigrationBatchState::Mixed
        })
    }

    fn publish<F>(
        &self,
        freedom: &Path,
        credentials: &Path,
        operation_id: &str,
        plan_binding: &str,
        forward: bool,
        fault: F,
    ) -> Result<()>
    where
        F: FnMut(super::DualFileFaultPoint) -> Result<()>,
    {
        self.require_identity(freedom, credentials, operation_id, plan_binding)?;
        let (fb, cb, fa, ca) = self.snapshots()?;
        let directory = transaction_directory(freedom);
        with_pair_locks(freedom, credentials, || {
            self.ensure_unchanged()?;
            let state = self.classify()?;
            let (from_freedom, to_freedom, from_credentials, to_credentials) =
                match (state, forward) {
                    (FileMigrationBatchState::Mixed, _) => {
                        anyhow::bail!("file migration batch raw pair drifted")
                    }
                    (FileMigrationBatchState::Before, true) => (&fb, &fa, &cb, &ca),
                    (FileMigrationBatchState::After, false) => (&fa, &fb, &ca, &cb),
                    _ => return Ok(()),
                };
            publish_prepared_file_pair(
                freedom,
                credentials,
                &directory,
                from_freedom,
                to_freedom,
                from_credentials,
                to_credentials,
                (),
                Some(|path: &Path, body: &[u8]| {
                    crate::util::atomic_write::atomic_write_private(path, body)
                        .with_context(|| format!("atomically write {}", path.display()))
                }),
                fault,
            )
        })
    }
}

fn with_pair_locks<T>(
    freedom: &Path,
    credentials: &Path,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    with_dual_file_transaction_lock(freedom, || {
        with_config_writer_guard(freedom, || {
            with_legacy_pair_locks(freedom, credentials, || {
                validate_targets(freedom, credentials)?;
                action()
            })
        })
    })
}

#[cfg(test)]
impl FileMigrationBatchCustody {
    fn publish_with_test_fault<F>(
        &self,
        freedom: &Path,
        credentials: &Path,
        operation_id: &str,
        plan_binding: &str,
        forward: bool,
        fault: F,
    ) -> Result<()>
    where
        F: FnMut(super::DualFileFaultPoint) -> Result<()>,
    {
        self.publish(
            freedom,
            credentials,
            operation_id,
            plan_binding,
            forward,
            fault,
        )
    }
}
fn custody_participants(
    config: &FreedomConfig,
    participants: &[FileMigrationParticipant],
) -> Result<Vec<CustodyParticipant>> {
    participants
        .iter()
        .map(|p| match p {
            FileMigrationParticipant::Slack { account } => {
                let x = config
                    .channel_accounts
                    .slack
                    .get(account)
                    .context("prepared Slack policy absent")?;
                Ok(CustodyParticipant::Slack {
                    account: account.to_string(),
                    allowed_user_id: x.allowed_user_id.clone(),
                    verified_team_id: x.team_id.clone().context("final Slack team absent")?,
                    incarnation: x
                        .incarnation
                        .clone()
                        .context("final Slack incarnation absent")?
                        .to_string(),
                })
            }
            FileMigrationParticipant::Telegram { account } => {
                let x = config
                    .channel_accounts
                    .telegram
                    .get(account)
                    .context("prepared Telegram policy absent")?;
                Ok(CustodyParticipant::Telegram {
                    account: account.to_string(),
                    allowed_user_id: x.allowed_user_id,
                    incarnation: x
                        .incarnation
                        .clone()
                        .context("final Telegram incarnation absent")?
                        .to_string(),
                })
            }
        })
        .collect()
}
fn validate_targets(freedom: &Path, credentials: &Path) -> Result<()> {
    ensure!(
        freedom.file_name().is_some_and(|x| x == "freedom.yaml")
            && credentials == sibling_credentials_path(freedom),
        "file migration batch requires canonical pair targets"
    );
    validate_exact_pair_target(freedom, "file migration batch freedom")?;
    validate_exact_pair_target(credentials, "file migration batch credentials")
}
fn custody_path(freedom: &Path, operation_id: &str) -> Result<PathBuf> {
    let parsed = uuid::Uuid::parse_str(operation_id)
        .context("file migration batch operation id must be UUID")?;
    ensure!(
        parsed.hyphenated().to_string() == operation_id,
        "file migration batch operation id noncanonical"
    );
    Ok(transaction_directory(freedom).join(format!("{PREFIX}{operation_id}{SUFFIX}")))
}
fn validate_binding(operation_id: &str, plan_binding: &str) -> Result<()> {
    let parsed = uuid::Uuid::parse_str(operation_id)?;
    ensure!(
        parsed.hyphenated().to_string() == operation_id,
        "file migration batch operation id must be canonical lowercase UUID"
    );
    ensure!(
        plan_binding.len() == 64
            && plan_binding
                .bytes()
                .all(|x| x.is_ascii_hexdigit() && !x.is_ascii_uppercase()),
        "file migration batch plan binding must be lowercase SHA-256"
    );
    Ok(())
}

fn validate_record(r: &BatchCustodyRecord, operation_id: &str, plan_binding: &str) -> Result<()> {
    ensure!(
        r.version == VERSION && r.operation_id == operation_id && r.plan_binding == plan_binding,
        "file migration batch custody binding invalid"
    );
    ensure!(
        r.freedom_file == "freedom.yaml" && r.credentials_file == "credentials.yaml",
        "file migration batch custody targets are noncanonical"
    );
    ensure!(
        !r.participants.is_empty() && r.participants.len() <= MAX_PARTICIPANTS,
        "file migration batch custody participant count invalid"
    );
    let mut seen = BTreeSet::new();
    for participant in &r.participants {
        match participant {
            CustodyParticipant::Slack {
                account,
                allowed_user_id,
                verified_team_id,
                incarnation,
            } => {
                let canonical = ChannelAccountId::new(account.clone())?;
                ensure!(
                    canonical.to_string() == *account && seen.insert(("slack", account)),
                    "invalid or duplicate Slack custody account"
                );
                let _ = crate::channels::slack::normalize_allowed_user_id(allowed_user_id)?;
                let _ = crate::config::normalize_slack_team_id(verified_team_id)?;
                let _ = AccountIncarnation::parse(incarnation)?;
            }
            CustodyParticipant::Telegram {
                account,
                allowed_user_id,
                incarnation,
            } => {
                let canonical = ChannelAccountId::new(account.clone())?;
                ensure!(
                    canonical.to_string() == *account
                        && *allowed_user_id != 0
                        && seen.insert(("telegram", account)),
                    "invalid or duplicate Telegram custody account"
                );
                let _ = AccountIncarnation::parse(incarnation)?;
            }
        }
    }
    let (fb, cb, fa, ca) = (
        r.freedom_before.decode("batch freedom_before")?,
        r.credentials_before.decode("batch credentials_before")?,
        r.freedom_after.decode("batch freedom_after")?,
        r.credentials_after.decode("batch credentials_after")?,
    );
    ensure!(
        r.before_sha256 == pair_hash(&fb, &cb) && r.after_sha256 == pair_hash(&fa, &ca),
        "file migration batch custody pair commitment invalid"
    );
    Ok(())
}
fn pair_hash(f: &FileSnapshot, c: &FileSnapshot) -> String {
    let mut h = Sha256::new();
    h.update(PAIR_DOMAIN);
    for (name, s) in [("freedom.yaml", f), ("credentials.yaml", c)] {
        h.update(name.as_bytes());
        h.update([0]);
        match s {
            FileSnapshot::Missing => h.update([0]),
            FileSnapshot::Present(b) => {
                h.update([1]);
                h.update((b.len() as u64).to_le_bytes());
                h.update(b.as_slice());
            }
        }
    }
    format!("{:x}", h.finalize())
}
fn custody_hash(r: &BatchCustodyRecord) -> String {
    let mut body = zeroize::Zeroizing::new(
        serde_yaml::to_string(r).expect("validated batch custody serializes"),
    );
    let mut h = Sha256::new();
    h.update(CUSTODY_DOMAIN);
    h.update(body.as_bytes());
    let out = format!("{:x}", h.finalize());
    body.zeroize();
    out
}
fn persist_record_create_new(path: &Path, r: &BatchCustodyRecord) -> Result<()> {
    let mut body = zeroize::Zeroizing::new(serde_yaml::to_string(r)?);
    ensure!(
        body.len() as u64 <= super::MAX_DUAL_FILE_JOURNAL_BYTES,
        "file migration batch custody exceeds limit"
    );
    let result = crate::util::atomic_write::write_private_create_new_durable(path, body.as_bytes())
        .with_context(|| format!("create file migration batch custody {}", path.display()));
    body.zeroize();
    result
}
fn read_custody(path: &Path) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
    let parent = path.parent().context("batch custody parent absent")?;
    let bound = crate::skills::store::open_bound_directory(
        parent,
        false,
        "file migration batch custody parent",
    )?
    .context("file migration batch custody parent absent")?;
    let name = path.file_name().context("batch custody leaf absent")?;
    match bound.dir.symlink_metadata(name) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
        Ok(m) => {
            ensure!(
                m.file_type().is_file() && !m.file_type().is_symlink(),
                "file migration batch custody is not regular"
            );
            let bytes = crate::skills::store::read_regular_file_bounded(
                &bound.dir,
                name,
                &bound.physical_display_path.join(name),
                super::MAX_DUAL_FILE_JOURNAL_BYTES as usize,
            )?;
            Ok(Some(zeroize::Zeroizing::new(bytes)))
        }
    }
}

#[cfg(test)]
mod tests;
