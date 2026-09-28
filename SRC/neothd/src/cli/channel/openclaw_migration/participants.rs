//! Concrete channel participants for the shared migration coordinator.
//! Slack v1 custody and plan serialization remain unchanged.

use super::super::{
    ChannelTestResult, TelegramProbeBinding, probe_telegram_account_binding_with,
    resolve_telegram_probe_binding,
};
use super::*;
use crate::config::credentials::{
    FileMigrationBatchCustody, FileMigrationBatchCustodyLoad, FileMigrationBatchState,
    FileMigrationInput, FileMigrationParticipant, PreparedFileMigrationBatch,
    PreparedSlackMigration, PreparedTelegramMigration, SlackMigrationCustody,
    SlackMigrationCustodyLoad, SlackMigrationState, TelegramMigrationCustody,
    TelegramMigrationCustodyLoad, TelegramMigrationState,
};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(super) enum ParticipantKind {
    Slack,
    Telegram,
    Batch,
}

impl ParticipantKind {
    pub(super) fn pair_domain(self) -> &'static [u8] {
        match self {
            Self::Slack => b"neoth-openclaw-slack-migration-pair-v1\0",
            Self::Telegram => b"neoth-openclaw-telegram-migration-pair-v1\0",
            Self::Batch => b"neoth-openclaw-file-batch-migration-pair-v1\0",
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "channel", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum PrivateRequest {
    Slack {
        schema_version: u8,
        source_account: String,
        account: ChannelAccountId,
        allowed_user_id: String,
    },
    Telegram {
        schema_version: u8,
        source_account: String,
        account: ChannelAccountId,
        allowed_user_id: u64,
    },
    Batch {
        schema_version: u8,
        participants: Vec<PrivateRequest>,
    },
}

impl PrivateRequest {
    pub(super) fn kind(&self) -> ParticipantKind {
        match self {
            Self::Slack { .. } => ParticipantKind::Slack,
            Self::Telegram { .. } => ParticipantKind::Telegram,
            Self::Batch { .. } => ParticipantKind::Batch,
        }
    }
    pub(super) fn source_account(&self) -> Option<&str> {
        match self {
            Self::Slack { source_account, .. } | Self::Telegram { source_account, .. } => {
                Some(source_account)
            }
            Self::Batch { .. } => None,
        }
    }
    pub(super) fn validate(&self) -> Result<()> {
        let version = match self {
            Self::Slack {
                schema_version,
                allowed_user_id,
                ..
            } => {
                ensure!(
                    !allowed_user_id.trim().is_empty()
                        && !allowed_user_id.chars().any(char::is_control),
                    "invalid allowed member"
                );
                *schema_version
            }
            Self::Telegram {
                schema_version,
                allowed_user_id,
                ..
            } => {
                ensure!(
                    *allowed_user_id != 0,
                    "Telegram allowed user must be nonzero"
                );
                *schema_version
            }
            Self::Batch {
                schema_version,
                participants,
            } => {
                ensure!(
                    *schema_version == 3,
                    "unsupported batch migration request version"
                );
                ensure!(
                    (1..=32).contains(&participants.len()),
                    "batch migration must contain 1 through 32 participants"
                );
                let mut destinations = std::collections::BTreeSet::new();
                let mut sources = std::collections::BTreeSet::new();
                for participant in participants {
                    ensure!(
                        participant.kind() != ParticipantKind::Batch,
                        "nested batch migrations are unsupported"
                    );
                    participant.validate()?;
                    let destination = match participant {
                        Self::Slack { account, .. } => (ParticipantKind::Slack, account.as_str()),
                        Self::Telegram { account, .. } => {
                            (ParticipantKind::Telegram, account.as_str())
                        }
                        Self::Batch { .. } => unreachable!(),
                    };
                    ensure!(
                        destinations.insert(destination),
                        "batch migration repeats a channel destination account"
                    );
                    let source = match participant {
                        Self::Slack { source_account, .. } => {
                            (ParticipantKind::Slack, source_account.as_str())
                        }
                        Self::Telegram { source_account, .. } => {
                            (ParticipantKind::Telegram, source_account.as_str())
                        }
                        Self::Batch { .. } => unreachable!(),
                    };
                    ensure!(
                        sources.insert(source),
                        "batch migration repeats a channel source account"
                    );
                }
                return Ok(());
            }
        };
        ensure!(
            version == 1,
            "unsupported private migration request version"
        );
        ensure!(
            self.source_account().is_some_and(
                |source| !source.trim().is_empty() && !source.chars().any(char::is_control)
            ),
            "invalid source account"
        );
        Ok(())
    }
    pub(super) fn binding(&self) -> Result<String> {
        // The Slack tuple and domain are byte-for-byte compatible with v1.
        match self {
            Self::Slack {
                schema_version,
                source_account,
                account,
                allowed_user_id,
            } => Ok(hash(
                b"neoth-openclaw-migration-request-v1\0",
                &serde_json::to_vec(&(
                    schema_version,
                    "slack",
                    source_account,
                    account.as_str(),
                    allowed_user_id,
                ))?,
            )),
            Self::Telegram {
                schema_version,
                source_account,
                account,
                allowed_user_id,
            } => Ok(hash(
                b"neoth-openclaw-migration-request-v2\0",
                &serde_json::to_vec(&(
                    schema_version,
                    "telegram",
                    source_account,
                    account.as_str(),
                    allowed_user_id,
                ))?,
            )),
            Self::Batch {
                schema_version,
                participants,
            } => {
                ensure!(
                    *schema_version == 3,
                    "unsupported batch migration request version"
                );
                let mut bindings = Vec::with_capacity(participants.len());
                for participant in participants {
                    bindings.push(participant.binding()?);
                }
                Ok(hash(
                    b"neoth-openclaw-migration-request-v3\0",
                    &serde_json::to_vec(&(schema_version, "batch", bindings))?,
                ))
            }
        }
    }
}

pub(super) enum SelectedSource {
    Slack(neoth_openclaw_custody::SelectedSlackAccount),
    Telegram(neoth_openclaw_custody::SelectedTelegramAccount),
    Batch(Vec<SelectedSource>),
}
impl SelectedSource {
    pub(super) fn source_set(&self) -> &neoth_openclaw_custody::SourceSetBinding {
        match self {
            Self::Slack(value) => value.source_set(),
            Self::Telegram(value) => value.source_set(),
            Self::Batch(values) => {
                let first = values
                    .first()
                    .expect("validated batch source is nonempty")
                    .source_set();
                assert!(
                    values.iter().all(|value| value.source_set() == first),
                    "batch source bindings were not validated"
                );
                first
            }
        }
    }
    pub(super) fn select(config: &Path, request: &PrivateRequest) -> Result<Self> {
        let inventory = neoth_openclaw_custody::canonical_known_channel_inventory_sha256();
        match request.kind() {
            ParticipantKind::Slack => {
                Ok(Self::Slack(neoth_openclaw_custody::select_slack_account(
                    config,
                    request
                        .source_account()
                        .expect("Slack request has source account"),
                    &inventory,
                )?))
            }
            ParticipantKind::Telegram => Ok(Self::Telegram(
                neoth_openclaw_custody::select_telegram_account(
                    config,
                    request
                        .source_account()
                        .expect("Telegram request has source account"),
                    &inventory,
                )?,
            )),
            ParticipantKind::Batch => {
                let PrivateRequest::Batch { participants, .. } = request else {
                    unreachable!()
                };
                let selected = participants
                    .iter()
                    .map(|participant| Self::select(config, participant))
                    .collect::<Result<Vec<_>>>()?;
                ensure!(!selected.is_empty(), "batch source is empty");
                let first = selected[0].source_set();
                ensure!(
                    selected.iter().all(|value| value.source_set() == first),
                    "batch participants must resolve from one identical OpenClaw source set"
                );
                Ok(Self::Batch(selected))
            }
        }
    }
    pub(super) fn prepare(
        self,
        home: &Path,
        plan: &Plan,
        request: &PrivateRequest,
    ) -> Result<PreparedParticipant> {
        ensure!(
            source_binding(self.source_set())? == plan.source_binding
                && request.kind() == plan.kind(),
            "selected source differs from plan"
        );
        let freedom = home.join("freedom.yaml");
        let credentials = home.join("credentials.yaml");
        let binding = plan_binding(plan)?;
        match (self, request) {
            (
                Self::Slack(selected),
                PrivateRequest::Slack {
                    account,
                    allowed_user_id,
                    ..
                },
            ) => {
                let (bot, app) = selected.into_tokens();
                Ok(PreparedParticipant::Slack(Box::new(
                    Credentials::prepare_slack_migration_upsert_at(
                        &freedom,
                        &credentials,
                        account.clone(),
                        allowed_user_id.clone(),
                        bot.with_exposed(|token| SecretString::from(token)),
                        app.with_exposed(|token| SecretString::from(token)),
                        &plan.id,
                        &binding,
                    )?,
                )))
            }
            (
                Self::Telegram(selected),
                PrivateRequest::Telegram {
                    account,
                    allowed_user_id,
                    ..
                },
            ) => {
                let token = selected
                    .into_token()
                    .with_exposed(|token| SecretString::from(token));
                Ok(PreparedParticipant::Telegram(Box::new(
                    Credentials::prepare_telegram_migration_upsert_at(
                        &freedom,
                        &credentials,
                        account.clone(),
                        *allowed_user_id,
                        token,
                        &plan.id,
                        &binding,
                    )?,
                )))
            }
            (Self::Batch(selected), PrivateRequest::Batch { participants, .. }) => {
                ensure!(
                    selected.len() == participants.len(),
                    "batch selection/request length differs"
                );
                let mut inputs = Vec::with_capacity(selected.len());
                for (selected, request) in selected.into_iter().zip(participants) {
                    match (selected, request) {
                        (
                            Self::Slack(selected),
                            PrivateRequest::Slack {
                                account,
                                allowed_user_id,
                                ..
                            },
                        ) => {
                            let (bot_token, app_token) = selected.into_tokens();
                            inputs.push(FileMigrationInput::Slack {
                                account: account.clone(),
                                allowed_user_id: allowed_user_id.clone(),
                                bot_token: bot_token
                                    .with_exposed(|token| SecretString::from(token)),
                                app_token: app_token
                                    .with_exposed(|token| SecretString::from(token)),
                            });
                        }
                        (
                            Self::Telegram(selected),
                            PrivateRequest::Telegram {
                                account,
                                allowed_user_id,
                                ..
                            },
                        ) => {
                            inputs.push(FileMigrationInput::Telegram {
                                account: account.clone(),
                                allowed_user_id: *allowed_user_id,
                                token: selected
                                    .into_token()
                                    .with_exposed(|token| SecretString::from(token)),
                            });
                        }
                        _ => anyhow::bail!("batch selected source differs from request"),
                    }
                }
                Ok(PreparedParticipant::Batch(Box::new(
                    Credentials::prepare_file_migration_batch_at(
                        &freedom,
                        &credentials,
                        inputs,
                        &plan.id,
                        &binding,
                    )?,
                )))
            }
            _ => anyhow::bail!("source participant differs from request"),
        }
    }
}

pub(super) enum ProbeBinding {
    Slack(SlackProbeBinding),
    Telegram(TelegramProbeBinding),
}
impl ProbeBinding {
    pub(super) fn kind(&self) -> ParticipantKind {
        match self {
            Self::Slack(_) => ParticipantKind::Slack,
            Self::Telegram(_) => ParticipantKind::Telegram,
        }
    }
}
pub(super) enum ProbeOutcome {
    Slack(SlackProbeOutcome),
    Telegram(ChannelTestResult),
}
pub(super) enum ProbeEvidence {
    Slack(String),
    Telegram,
    Batch(Vec<ProbeEvidence>),
}
impl ProbeEvidence {
    pub(super) fn from_outcomes(
        kind: ParticipantKind,
        evidence: Vec<ProbeEvidence>,
    ) -> Result<Self> {
        match kind {
            ParticipantKind::Slack => {
                ensure!(
                    evidence.len() == 1 && matches!(evidence.first(), Some(Self::Slack(_))),
                    "Slack probe evidence differs from participant"
                );
                Ok(evidence.into_iter().next().expect("one evidence"))
            }
            ParticipantKind::Telegram => {
                ensure!(
                    evidence.len() == 1 && matches!(evidence.first(), Some(Self::Telegram)),
                    "Telegram probe evidence differs from participant"
                );
                Ok(evidence.into_iter().next().expect("one evidence"))
            }
            ParticipantKind::Batch => {
                ensure!(
                    (1..=32).contains(&evidence.len())
                        && evidence.iter().all(|item| !matches!(item, Self::Batch(_))),
                    "batch probe evidence is invalid"
                );
                Ok(Self::Batch(evidence))
            }
        }
    }
}
impl ProbeOutcome {
    pub(super) fn evidence(self, kind: ParticipantKind) -> Result<ProbeEvidence> {
        match (self, kind) {
            (Self::Slack(value), ParticipantKind::Slack) => {
                ensure!(value.report.status == "ok", "Slack candidate probe failed");
                Ok(ProbeEvidence::Slack(
                    value
                        .verified_team_id
                        .context("Slack probe returned no workspace")?,
                ))
            }
            (Self::Telegram(value), ParticipantKind::Telegram) => {
                ensure!(value.status == "ok", "Telegram candidate probe failed");
                Ok(ProbeEvidence::Telegram)
            }
            (_, ParticipantKind::Batch) => {
                anyhow::bail!("batch evidence must be assembled from child probe outcomes")
            }
            _ => anyhow::bail!("probe participant differs from plan"),
        }
    }
}
pub(super) async fn probe(binding: ProbeBinding) -> Result<ProbeOutcome> {
    match binding {
        ProbeBinding::Slack(binding) => Ok(ProbeOutcome::Slack(
            probe_slack_account_binding_with(binding, |token| async move {
                crate::channels::slack_api::auth_test(&token).await
            })
            .await?,
        )),
        ProbeBinding::Telegram(binding) => Ok(ProbeOutcome::Telegram(
            probe_telegram_account_binding_with(binding, |token, user| async move {
                crate::channels::telegram::TelegramChannel::new(token, Some(user))
                    .validate()
                    .await
            })
            .await?,
        )),
    }
}

pub(super) enum PreparedParticipant {
    Slack(Box<PreparedSlackMigration>),
    Telegram(Box<PreparedTelegramMigration>),
    Batch(Box<PreparedFileMigrationBatch>),
}
impl PreparedParticipant {
    pub(super) fn probe_bindings(&self) -> Result<Vec<ProbeBinding>> {
        match self {
            Self::Slack(value) => Ok(vec![ProbeBinding::Slack(resolve_slack_probe_binding(
                value.candidate_pair(),
                value.account_id(),
            )?)]),
            Self::Telegram(value) => Ok(vec![ProbeBinding::Telegram(
                resolve_telegram_probe_binding(value.candidate_pair(), Some(value.account_id()))?,
            )]),
            Self::Batch(value) => value
                .participants()
                .iter()
                .map(|participant| match participant {
                    FileMigrationParticipant::Slack { account } => Ok(ProbeBinding::Slack(
                        resolve_slack_probe_binding(value.candidate_pair(), account)?,
                    )),
                    FileMigrationParticipant::Telegram { account } => Ok(ProbeBinding::Telegram(
                        resolve_telegram_probe_binding(value.candidate_pair(), Some(account))?,
                    )),
                })
                .collect(),
        }
    }
    pub(super) fn persist(self, evidence: &ProbeEvidence) -> Result<ParticipantCustody> {
        match (self, evidence) {
            (Self::Slack(value), ProbeEvidence::Slack(team)) => Ok(ParticipantCustody::Slack(
                Box::new(value.persist_slack_migration_custody_at(team)?),
            )),
            (Self::Telegram(value), ProbeEvidence::Telegram) => Ok(ParticipantCustody::Telegram(
                Box::new(value.persist_telegram_migration_custody_at()?),
            )),
            (Self::Batch(value), ProbeEvidence::Batch(evidence)) => {
                ensure!(
                    value.participants().len() == evidence.len(),
                    "batch probe evidence length differs from candidate"
                );
                let teams = value
                    .participants()
                    .iter()
                    .zip(evidence)
                    .map(|(participant, evidence)| match (participant, evidence) {
                        (FileMigrationParticipant::Slack { .. }, ProbeEvidence::Slack(team)) => {
                            Ok(Some(team.clone()))
                        }
                        (FileMigrationParticipant::Telegram { .. }, ProbeEvidence::Telegram) => {
                            Ok(None)
                        }
                        _ => anyhow::bail!("batch probe evidence differs from participant"),
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(ParticipantCustody::Batch(Box::new(
                    value.persist_custody(&teams)?,
                )))
            }
            _ => anyhow::bail!("probe participant differs from candidate"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PairState {
    Before,
    After,
    Mixed,
}
impl From<SlackMigrationState> for PairState {
    fn from(value: SlackMigrationState) -> Self {
        match value {
            SlackMigrationState::Before => Self::Before,
            SlackMigrationState::After => Self::After,
            SlackMigrationState::Mixed => Self::Mixed,
        }
    }
}
impl From<TelegramMigrationState> for PairState {
    fn from(value: TelegramMigrationState) -> Self {
        match value {
            TelegramMigrationState::Before => Self::Before,
            TelegramMigrationState::After => Self::After,
            TelegramMigrationState::Mixed => Self::Mixed,
        }
    }
}
impl From<FileMigrationBatchState> for PairState {
    fn from(value: FileMigrationBatchState) -> Self {
        match value {
            FileMigrationBatchState::Before => Self::Before,
            FileMigrationBatchState::After => Self::After,
            FileMigrationBatchState::Mixed => Self::Mixed,
        }
    }
}
pub(super) struct ParticipantCommit {
    pub(super) before_sha256: String,
    pub(super) after_sha256: String,
}
pub(super) enum ParticipantCustody {
    Slack(Box<SlackMigrationCustody>),
    Telegram(Box<TelegramMigrationCustody>),
    Batch(Box<FileMigrationBatchCustody>),
}
impl ParticipantCustody {
    pub(super) fn load_optional_at(
        kind: ParticipantKind,
        freedom: &Path,
        id: &str,
        binding: &str,
    ) -> Result<Option<Self>> {
        match kind {
            ParticipantKind::Slack => Ok(
                match SlackMigrationCustody::load_optional_at(freedom, id, binding)? {
                    SlackMigrationCustodyLoad::Absent => None,
                    SlackMigrationCustodyLoad::Present(value) => Some(Self::Slack(value)),
                },
            ),
            ParticipantKind::Telegram => Ok(
                match TelegramMigrationCustody::load_optional_at(freedom, id, binding)? {
                    TelegramMigrationCustodyLoad::Absent => None,
                    TelegramMigrationCustodyLoad::Present(value) => Some(Self::Telegram(value)),
                },
            ),
            ParticipantKind::Batch => Ok(
                match FileMigrationBatchCustody::load_optional_at(freedom, id, binding)? {
                    FileMigrationBatchCustodyLoad::Absent => None,
                    FileMigrationBatchCustodyLoad::Present(value) => Some(Self::Batch(value)),
                },
            ),
        }
    }
    pub(super) fn before_sha256(&self) -> &str {
        match self {
            Self::Slack(value) => value.before_sha256(),
            Self::Telegram(value) => value.before_sha256(),
            Self::Batch(value) => value.before_sha256(),
        }
    }
    pub(super) fn after_sha256(&self) -> &str {
        match self {
            Self::Slack(value) => value.after_sha256(),
            Self::Telegram(value) => value.after_sha256(),
            Self::Batch(value) => value.after_sha256(),
        }
    }
    pub(super) fn custody_sha256(&self) -> String {
        match self {
            Self::Slack(value) => value.custody_sha256(),
            Self::Telegram(value) => value.custody_sha256(),
            Self::Batch(value) => value.custody_sha256(),
        }
    }
    pub(super) fn validate_retry(
        &self,
        request: &PrivateRequest,
        evidence: &ProbeEvidence,
    ) -> Result<()> {
        match (self, request, evidence) {
            (
                Self::Slack(value),
                PrivateRequest::Slack { account, .. },
                ProbeEvidence::Slack(team),
            ) => ensure!(
                value.account_id() == account.as_str() && value.verified_team_id() == team,
                "Slack workspace differs from custody"
            ),
            (
                Self::Telegram(value),
                PrivateRequest::Telegram {
                    account,
                    allowed_user_id,
                    ..
                },
                ProbeEvidence::Telegram,
            ) => ensure!(
                value.account_id() == account.as_str()
                    && value.allowed_user_id() == *allowed_user_id,
                "Telegram policy differs from custody"
            ),
            (Self::Batch(value), PrivateRequest::Batch { .. }, ProbeEvidence::Batch(evidence)) => {
                let teams = evidence
                    .iter()
                    .map(|item| match item {
                        ProbeEvidence::Slack(team) => Ok(Some(team.clone())),
                        ProbeEvidence::Telegram => Ok(None),
                        ProbeEvidence::Batch(_) => {
                            anyhow::bail!("nested batch evidence is invalid")
                        }
                    })
                    .collect::<Result<Vec<_>>>()?;
                value.validate_retry(&teams)?;
            }
            _ => anyhow::bail!("custody participant differs from request/probe"),
        }
        Ok(())
    }
    pub(super) fn inspect_at(
        &self,
        freedom: &Path,
        credentials: &Path,
        id: &str,
        binding: &str,
    ) -> Result<PairState> {
        match self {
            Self::Slack(value) => Ok(value.inspect_at(freedom, credentials, id, binding)?.into()),
            Self::Telegram(value) => {
                Ok(value.inspect_at(freedom, credentials, id, binding)?.into())
            }
            Self::Batch(value) => Ok(value.inspect_at(freedom, credentials, id, binding)?.into()),
        }
    }
    pub(super) fn commit_if_before_at(
        &self,
        freedom: &Path,
        credentials: &Path,
        id: &str,
        binding: &str,
    ) -> Result<ParticipantCommit> {
        let (before_sha256, after_sha256) = match self {
            Self::Slack(value) => {
                let result = value.commit_if_before_at(freedom, credentials, id, binding)?;
                (result.before_sha256, result.after_sha256)
            }
            Self::Telegram(value) => {
                let result = value.commit_if_before_at(freedom, credentials, id, binding)?;
                (result.before_sha256, result.after_sha256)
            }
            Self::Batch(value) => {
                let result = value.commit_if_before_at(freedom, credentials, id, binding)?;
                (result.before_sha256, result.after_sha256)
            }
        };
        Ok(ParticipantCommit {
            before_sha256,
            after_sha256,
        })
    }
    pub(super) fn rollback_if_exact_at(
        &self,
        freedom: &Path,
        credentials: &Path,
        id: &str,
        binding: &str,
    ) -> Result<PairState> {
        match self {
            Self::Slack(value) => Ok(value
                .rollback_if_exact_at(freedom, credentials, id, binding)?
                .into()),
            Self::Telegram(value) => Ok(value
                .rollback_if_exact_at(freedom, credentials, id, binding)?
                .into()),
            Self::Batch(value) => Ok(value
                .rollback_if_exact_at(freedom, credentials, id, binding)?
                .into()),
        }
    }
}
