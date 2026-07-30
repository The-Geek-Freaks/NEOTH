//! Request-bound authority core for concrete updater leaves.
//!
//! This module deliberately does not grant recurring updater work by itself.
//! A caller must first build an exact [`UpdaterLeafRequest`], then execute the
//! concrete leaf through [`UpdaterLeafAuthorizer::execute_http`] or
//! [`UpdaterLeafAuthorizer::execute_stage`]. The effect future becomes
//! executable only after a durable intent ACK and exact sink-argument binding,
//! and cannot return through this boundary before a matching terminal result
//! is durably acknowledged.

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use futures_util::FutureExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::reload::{GenerationRetired, UpdaterLeafGate, UpdaterLeafLease};
use crate::permissions::gate::{ConfirmStrategy, Gate, GateError, PermissionAuditSink};
use crate::permissions::{Action, AutonomyPolicySnapshot};
use crate::wal::events::{EVENT_TYPE_EXTENDED, ExtendedSubtype};
use crate::wal::writer::WalWriterHandle;

const AUDIT_SCHEMA_VERSION: u8 = 1;
const MAX_AUDIT_ID_BYTES: usize = 128;
const INTERRUPTED_ERROR_DOMAIN: &[u8] = b"updater_leaf_interrupted_without_terminal";

/// High-level updater task owning a concrete effect.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UpdaterAuthorityTask {
    NeothSelf,
    CliVersions,
    SkillPlugin,
}

impl UpdaterAuthorityTask {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NeothSelf => "neoth_self",
            Self::CliVersions => "cli_versions",
            Self::SkillPlugin => "skill_plugin",
        }
    }
}

/// Reload-owned lane that admitted the concrete updater effect.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UpdaterAuthorityLane {
    NeothSelfProbe,
    #[allow(dead_code)] // R3-18: lane stays denied until its process leaves are sealed.
    CliVersionProbe,
    #[allow(dead_code)] // R3-18: lane stays denied until its Git leaf consumes authority.
    SkillPluginProbe,
    #[allow(dead_code)] // R3-18: lane stays denied until scan/install leaves are sealed.
    CliAutoApply,
    SelfStage,
}

impl UpdaterAuthorityLane {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NeothSelfProbe => "neoth_self_probe",
            Self::CliVersionProbe => "cli_version_probe",
            Self::SkillPluginProbe => "skill_plugin_probe",
            Self::CliAutoApply => "cli_auto_apply",
            Self::SelfStage => "self_stage",
        }
    }

    const fn task(self) -> UpdaterAuthorityTask {
        match self {
            Self::NeothSelfProbe | Self::SelfStage => UpdaterAuthorityTask::NeothSelf,
            Self::CliVersionProbe | Self::CliAutoApply => UpdaterAuthorityTask::CliVersions,
            Self::SkillPluginProbe => UpdaterAuthorityTask::SkillPlugin,
        }
    }
}

/// Concrete component whose updater leaf is about to run.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UpdaterAuthorityComponent {
    Neoth,
    #[allow(dead_code)] // Constructed when the denied CLI lane is adopted.
    ClaudeCli,
    #[allow(dead_code)] // Constructed when the denied CLI lane is adopted.
    AntigravityCli,
    #[allow(dead_code)] // Constructed when the denied CLI lane is adopted.
    Codex,
    #[allow(dead_code)] // Constructed when the denied skill lane is adopted.
    SkillPlugin {
        identity_sha256: String,
    },
}

impl UpdaterAuthorityComponent {
    #[allow(dead_code)] // R3-18 CLI lane adoption checkpoint.
    pub(crate) fn cli(component: super::Component) -> Self {
        match component {
            super::Component::ClaudeCli => Self::ClaudeCli,
            super::Component::AntigravityCli => Self::AntigravityCli,
            super::Component::Codex => Self::Codex,
        }
    }

    #[allow(dead_code)] // R3-18 skill/plugin lane adoption checkpoint.
    pub(crate) fn skill_plugin(identity: &[u8]) -> Self {
        Self::SkillPlugin {
            identity_sha256: sha256_hex(identity),
        }
    }

    const fn kind_str(&self) -> &'static str {
        match self {
            Self::Neoth => "neoth",
            Self::ClaudeCli => "claude_cli",
            Self::AntigravityCli => "antigravity_cli",
            Self::Codex => "codex",
            Self::SkillPlugin { .. } => "skill_plugin",
        }
    }

    fn identity_sha256(&self) -> Option<&str> {
        match self {
            Self::SkillPlugin { identity_sha256 } => Some(identity_sha256),
            _ => None,
        }
    }

    fn task(&self) -> UpdaterAuthorityTask {
        match self {
            Self::Neoth => UpdaterAuthorityTask::NeothSelf,
            Self::ClaudeCli | Self::AntigravityCli | Self::Codex => {
                UpdaterAuthorityTask::CliVersions
            }
            Self::SkillPlugin { .. } => UpdaterAuthorityTask::SkillPlugin,
        }
    }

    fn validate(&self) -> Result<()> {
        if let Some(identity) = self.identity_sha256() {
            validate_sha256(identity).context("invalid Skill/plugin component identity")?;
        }
        Ok(())
    }
}

/// Exact effect class. Each variant is restricted to one task/lane and one
/// concrete target kind below; callers cannot relabel a process as a harmless
/// metadata fetch.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UpdaterLeafEffect {
    ReleaseMetadataFetch,
    ReleaseChecksumFetch,
    ReleaseArchiveFetch,
    ReleaseSignatureFetch,
    VerifiedStageWrite,
    #[allow(dead_code)] // R3-18 CLI probe lane is still fail-closed.
    CliInstalledVersionProbe,
    #[allow(dead_code)] // R3-18 CLI probe lane is still fail-closed.
    CliLatestVersionProbe,
    #[allow(dead_code)] // R3-18 auto-apply lane is still fail-closed.
    OsvScan,
    #[allow(dead_code)] // R3-18 auto-apply lane is still fail-closed.
    RegistryHealthProbe,
    #[allow(dead_code)] // R3-18 vendor installer lane is still fail-closed.
    VendorInstallerFetch,
    #[allow(dead_code)] // R3-18 auto-apply lane is still fail-closed.
    CliInstall,
    #[allow(dead_code)] // R3-18 skill/plugin lane is still fail-closed.
    SkillGitProbe,
}

impl UpdaterLeafEffect {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ReleaseMetadataFetch => "release_metadata_fetch",
            Self::ReleaseChecksumFetch => "release_checksum_fetch",
            Self::ReleaseArchiveFetch => "release_archive_fetch",
            Self::ReleaseSignatureFetch => "release_signature_fetch",
            Self::VerifiedStageWrite => "verified_stage_write",
            Self::CliInstalledVersionProbe => "cli_installed_version_probe",
            Self::CliLatestVersionProbe => "cli_latest_version_probe",
            Self::OsvScan => "osv_scan",
            Self::RegistryHealthProbe => "registry_health_probe",
            Self::VendorInstallerFetch => "vendor_installer_fetch",
            Self::CliInstall => "cli_install",
            Self::SkillGitProbe => "skill_git_probe",
        }
    }

    const fn lane_allowed(self, lane: UpdaterAuthorityLane) -> bool {
        match self {
            Self::ReleaseMetadataFetch => {
                matches!(
                    lane,
                    UpdaterAuthorityLane::NeothSelfProbe | UpdaterAuthorityLane::SelfStage
                )
            }
            Self::ReleaseChecksumFetch
            | Self::ReleaseArchiveFetch
            | Self::ReleaseSignatureFetch
            | Self::VerifiedStageWrite => matches!(lane, UpdaterAuthorityLane::SelfStage),
            Self::CliInstalledVersionProbe | Self::CliLatestVersionProbe => {
                matches!(lane, UpdaterAuthorityLane::CliVersionProbe)
            }
            Self::OsvScan
            | Self::RegistryHealthProbe
            | Self::VendorInstallerFetch
            | Self::CliInstall => matches!(lane, UpdaterAuthorityLane::CliAutoApply),
            Self::SkillGitProbe => matches!(lane, UpdaterAuthorityLane::SkillPluginProbe),
        }
    }

    const fn target_kind(self) -> UpdaterLeafTargetKind {
        match self {
            Self::ReleaseMetadataFetch
            | Self::ReleaseChecksumFetch
            | Self::ReleaseArchiveFetch
            | Self::ReleaseSignatureFetch
            | Self::OsvScan
            | Self::RegistryHealthProbe
            | Self::VendorInstallerFetch => UpdaterLeafTargetKind::Http,
            Self::VerifiedStageWrite => UpdaterLeafTargetKind::Stage,
            Self::CliInstalledVersionProbe
            | Self::CliLatestVersionProbe
            | Self::CliInstall
            | Self::SkillGitProbe => UpdaterLeafTargetKind::Process,
        }
    }

    const fn expected_method(self) -> Option<UpdaterHttpMethod> {
        match self {
            Self::ReleaseMetadataFetch
            | Self::ReleaseChecksumFetch
            | Self::ReleaseArchiveFetch
            | Self::ReleaseSignatureFetch
            | Self::RegistryHealthProbe
            | Self::VendorInstallerFetch => Some(UpdaterHttpMethod::Get),
            Self::OsvScan => Some(UpdaterHttpMethod::Post),
            _ => None,
        }
    }

    fn allows_outcome(self, outcome: UpdaterLeafOutcomeCode) -> bool {
        match self {
            Self::ReleaseMetadataFetch => {
                matches!(
                    outcome,
                    UpdaterLeafOutcomeCode::Completed | UpdaterLeafOutcomeCode::NotModified
                )
            }
            Self::ReleaseChecksumFetch | Self::ReleaseSignatureFetch => {
                matches!(
                    outcome,
                    UpdaterLeafOutcomeCode::Completed | UpdaterLeafOutcomeCode::Redirected
                )
            }
            Self::ReleaseArchiveFetch | Self::VendorInstallerFetch => {
                matches!(
                    outcome,
                    UpdaterLeafOutcomeCode::Verified | UpdaterLeafOutcomeCode::Redirected
                )
            }
            Self::VerifiedStageWrite => outcome == UpdaterLeafOutcomeCode::Prepared,
            Self::CliInstalledVersionProbe => outcome == UpdaterLeafOutcomeCode::Completed,
            Self::CliLatestVersionProbe | Self::SkillGitProbe => {
                matches!(
                    outcome,
                    UpdaterLeafOutcomeCode::Completed | UpdaterLeafOutcomeCode::UpdateAvailable
                )
            }
            Self::OsvScan => outcome == UpdaterLeafOutcomeCode::Clean,
            Self::RegistryHealthProbe => {
                matches!(
                    outcome,
                    UpdaterLeafOutcomeCode::Completed | UpdaterLeafOutcomeCode::Clean
                )
            }
            Self::CliInstall => outcome == UpdaterLeafOutcomeCode::Installed,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UpdaterLeafTargetKind {
    Http,
    Process,
    Stage,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum UpdaterHttpMethod {
    Get,
    Post,
    #[allow(dead_code)] // Reserved for a future conditional health probe descriptor.
    Head,
}

impl UpdaterHttpMethod {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Head => "HEAD",
        }
    }
}

/// Typed executable identity. Arguments are never placed in the WAL.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UpdaterProgram {
    #[allow(dead_code)] // R3-18 denied process lanes are adopted separately.
    ManagedCli,
    #[allow(dead_code)] // R3-18 denied process lanes are adopted separately.
    Npm,
    #[allow(dead_code)] // R3-18 denied process lanes are adopted separately.
    Git,
    #[allow(dead_code)] // R3-18 denied process lanes are adopted separately.
    PowerShell,
    #[allow(dead_code)] // R3-18 denied process lanes are adopted separately.
    Curl,
}

impl UpdaterProgram {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ManagedCli => "managed_cli",
            Self::Npm => "npm",
            Self::Git => "git",
            Self::PowerShell => "powershell",
            Self::Curl => "curl",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct HttpBinding {
    method: UpdaterHttpMethod,
    origin: String,
    path: String,
    query_sha256: Option<String>,
    body_sha256: String,
    body_size_bytes: u64,
    expected_content_sha256: Option<String>,
    max_response_bytes: u64,
}

impl HttpBinding {
    fn for_request(
        method: UpdaterHttpMethod,
        url: &str,
        body: &[u8],
        expected_content_sha256: Option<&str>,
        max_response_bytes: u64,
    ) -> Result<Self> {
        let parsed = url::Url::parse(url).context("parse updater HTTP URL")?;
        anyhow::ensure!(
            parsed.scheme() == "https",
            "remote updater HTTP URL must use HTTPS"
        );
        anyhow::ensure!(
            parsed.username().is_empty() && parsed.password().is_none(),
            "updater HTTP URL credentials are forbidden"
        );
        anyhow::ensure!(
            parsed.fragment().is_none(),
            "updater HTTP URL fragments are forbidden"
        );
        anyhow::ensure!(
            !parsed.cannot_be_a_base(),
            "updater HTTP URL must be hierarchical"
        );
        anyhow::ensure!(
            max_response_bytes > 0,
            "max response bytes must be non-zero"
        );
        if !matches!(method, UpdaterHttpMethod::Post) {
            anyhow::ensure!(
                body.is_empty(),
                "{} updater request cannot carry a body",
                method.as_str()
            );
        }

        let origin = parsed.origin().ascii_serialization();
        anyhow::ensure!(origin != "null", "updater HTTP URL has no canonical origin");
        let path = if parsed.path().is_empty() {
            "/".to_string()
        } else {
            parsed.path().to_string()
        };
        let query_sha256 = parsed.query().map(|query| sha256_hex(query.as_bytes()));
        let body_size_bytes =
            u64::try_from(body.len()).context("updater HTTP body length overflow")?;
        let expected_content_sha256 = expected_content_sha256
            .map(normalize_sha256)
            .transpose()
            .context("invalid expected updater content hash")?;

        Ok(Self {
            method,
            origin,
            path,
            query_sha256,
            body_sha256: sha256_hex(body),
            body_size_bytes,
            expected_content_sha256,
            max_response_bytes,
        })
    }

    fn validate(&self) -> Result<()> {
        let origin = url::Url::parse(&self.origin).context("parse updater HTTP audit origin")?;
        anyhow::ensure!(
            origin.scheme() == "https"
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.query().is_none()
                && origin.fragment().is_none()
                && origin.origin().ascii_serialization() == self.origin,
            "invalid updater HTTP audit origin"
        );
        anyhow::ensure!(
            self.path.starts_with('/'),
            "invalid updater HTTP audit path"
        );
        anyhow::ensure!(
            self.max_response_bytes > 0,
            "updater HTTP response bound is zero"
        );
        validate_sha256(&self.body_sha256)?;
        if let Some(hash) = self.query_sha256.as_deref() {
            validate_sha256(hash)?;
        }
        if let Some(hash) = self.expected_content_sha256.as_deref() {
            validate_sha256(hash)?;
        }
        if !matches!(self.method, UpdaterHttpMethod::Post) {
            anyhow::ensure!(
                self.body_size_bytes == 0 && self.body_sha256 == sha256_hex(&[]),
                "{} updater audit target cannot carry a body",
                self.method.as_str()
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProcessBinding {
    program: UpdaterProgram,
    argv_sha256: String,
    argv_count: u32,
    stdin_sha256: String,
    stdin_size_bytes: u64,
    max_output_bytes: u64,
}

impl ProcessBinding {
    fn validate(&self) -> Result<()> {
        validate_sha256(&self.argv_sha256)?;
        validate_sha256(&self.stdin_sha256)?;
        anyhow::ensure!(
            self.max_output_bytes > 0,
            "updater process output bound is zero"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct StageBinding {
    neoth_home_sha256: String,
    destination_sha256: String,
    content_sha256: String,
    content_size_bytes: u64,
}

impl StageBinding {
    fn for_request(
        neoth_home: &Path,
        destination: &Path,
        content_sha256: &str,
        content_size_bytes: u64,
    ) -> Result<Self> {
        let content_sha256 =
            normalize_sha256(content_sha256).context("invalid staged content hash")?;
        anyhow::ensure!(content_size_bytes > 0, "staged content must be non-empty");
        validate_stage_destination(neoth_home, destination)?;

        Ok(Self {
            neoth_home_sha256: path_sha256(neoth_home),
            destination_sha256: path_sha256(destination),
            content_sha256,
            content_size_bytes,
        })
    }

    fn validate(&self) -> Result<()> {
        validate_sha256(&self.neoth_home_sha256)?;
        validate_sha256(&self.destination_sha256)?;
        validate_sha256(&self.content_sha256)?;
        anyhow::ensure!(
            self.content_size_bytes > 0,
            "updater stage content bound is zero"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum UpdaterLeafTarget {
    Http(HttpBinding),
    #[allow(dead_code)] // No recurring process lane is authorized yet.
    Process(ProcessBinding),
    Stage(StageBinding),
}

impl UpdaterLeafTarget {
    const fn kind(&self) -> UpdaterLeafTargetKind {
        match self {
            Self::Http(_) => UpdaterLeafTargetKind::Http,
            Self::Process(_) => UpdaterLeafTargetKind::Process,
            Self::Stage(_) => UpdaterLeafTargetKind::Stage,
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Http(binding) => binding.validate(),
            Self::Process(binding) => binding.validate(),
            Self::Stage(binding) => binding.validate(),
        }
    }
}

/// Immutable exact request bound to the accepted reload epoch.
///
/// HTTP URLs are split into a credential-free origin and path. Query bytes are
/// represented only by SHA-256; request bodies, process arguments/stdin, and
/// local destination paths likewise never enter the WAL in plaintext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UpdaterLeafRequest {
    operation_id: String,
    request_id: String,
    accepted_epoch: u64,
    task: UpdaterAuthorityTask,
    lane: UpdaterAuthorityLane,
    component: UpdaterAuthorityComponent,
    effect: UpdaterLeafEffect,
    target: UpdaterLeafTarget,
    binding_sha256: String,
}

impl UpdaterLeafRequest {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn http(
        operation_id: impl Into<String>,
        request_id: impl Into<String>,
        accepted_epoch: u64,
        task: UpdaterAuthorityTask,
        lane: UpdaterAuthorityLane,
        component: UpdaterAuthorityComponent,
        effect: UpdaterLeafEffect,
        method: UpdaterHttpMethod,
        url: &str,
        body: &[u8],
        expected_content_sha256: Option<&str>,
        max_response_bytes: u64,
    ) -> Result<Self> {
        let binding = HttpBinding::for_request(
            method,
            url,
            body,
            expected_content_sha256,
            max_response_bytes,
        )?;

        Self::build(
            operation_id.into(),
            request_id.into(),
            accepted_epoch,
            task,
            lane,
            component,
            effect,
            UpdaterLeafTarget::Http(binding),
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)] // R3-18 process-lane adoption checkpoint.
    pub(crate) fn process(
        operation_id: impl Into<String>,
        request_id: impl Into<String>,
        accepted_epoch: u64,
        task: UpdaterAuthorityTask,
        lane: UpdaterAuthorityLane,
        component: UpdaterAuthorityComponent,
        effect: UpdaterLeafEffect,
        program: UpdaterProgram,
        argv: &[String],
        stdin: &[u8],
        max_output_bytes: u64,
    ) -> Result<Self> {
        anyhow::ensure!(max_output_bytes > 0, "max process output must be non-zero");
        let argv_count = u32::try_from(argv.len()).context("updater argv count overflow")?;
        let stdin_size_bytes =
            u64::try_from(stdin.len()).context("updater process stdin length overflow")?;

        let mut argv_digest = Sha256::new();
        for arg in argv {
            digest_field(&mut argv_digest, b"arg", arg.as_bytes());
        }

        Self::build(
            operation_id.into(),
            request_id.into(),
            accepted_epoch,
            task,
            lane,
            component,
            effect,
            UpdaterLeafTarget::Process(ProcessBinding {
                program,
                argv_sha256: hex::encode(argv_digest.finalize()),
                argv_count,
                stdin_sha256: sha256_hex(stdin),
                stdin_size_bytes,
                max_output_bytes,
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verified_stage(
        operation_id: impl Into<String>,
        request_id: impl Into<String>,
        accepted_epoch: u64,
        task: UpdaterAuthorityTask,
        lane: UpdaterAuthorityLane,
        component: UpdaterAuthorityComponent,
        effect: UpdaterLeafEffect,
        neoth_home: &Path,
        destination: &Path,
        content_sha256: &str,
        content_size_bytes: u64,
    ) -> Result<Self> {
        let binding =
            StageBinding::for_request(neoth_home, destination, content_sha256, content_size_bytes)?;

        Self::build(
            operation_id.into(),
            request_id.into(),
            accepted_epoch,
            task,
            lane,
            component,
            effect,
            UpdaterLeafTarget::Stage(binding),
        )
    }

    fn build(
        operation_id: String,
        request_id: String,
        accepted_epoch: u64,
        task: UpdaterAuthorityTask,
        lane: UpdaterAuthorityLane,
        component: UpdaterAuthorityComponent,
        effect: UpdaterLeafEffect,
        target: UpdaterLeafTarget,
    ) -> Result<Self> {
        validate_audit_id(&operation_id, "operation")?;
        validate_audit_id(&request_id, "request")?;
        anyhow::ensure!(
            lane.task() == task,
            "updater lane {} does not belong to task {}",
            lane.as_str(),
            task.as_str()
        );
        component.validate()?;
        target.validate()?;
        anyhow::ensure!(
            component.task() == task,
            "updater component {} does not belong to task {}",
            component.kind_str(),
            task.as_str()
        );
        anyhow::ensure!(
            effect.lane_allowed(lane),
            "updater effect {} is forbidden in lane {}",
            effect.as_str(),
            lane.as_str()
        );
        anyhow::ensure!(
            effect.target_kind() == target.kind(),
            "updater effect {} has the wrong concrete target kind",
            effect.as_str()
        );

        if let (UpdaterLeafTarget::Http(http), Some(expected)) = (&target, effect.expected_method())
        {
            anyhow::ensure!(
                http.method == expected,
                "updater effect {} requires {}",
                effect.as_str(),
                expected.as_str()
            );
        }
        validate_process_binding(effect, &target)?;

        let mut request = Self {
            operation_id,
            request_id,
            accepted_epoch,
            task,
            lane,
            component,
            effect,
            target,
            binding_sha256: String::new(),
        };
        request.binding_sha256 = request.compute_binding_sha256();
        Ok(request)
    }

    pub(crate) fn binding_sha256(&self) -> &str {
        &self.binding_sha256
    }

    fn permission_action(&self) -> Action {
        match &self.target {
            UpdaterLeafTarget::Http(http) => Action::ExternalHttpRequest {
                method: http.method.as_str().to_string(),
                destination: http.origin.clone(),
                surface: format!("updater_{}", self.effect.as_str()),
                request_id: self.request_id.clone(),
                request_binding_sha256: self.binding_sha256.clone(),
            },
            // The exact command/argv binding remains in the mandatory updater
            // intent. The autonomy policy sees the conservative executable
            // class and can never downgrade an installer process to a read.
            UpdaterLeafTarget::Process(_) => Action::ExecArbitrary,
            // `verified_stage` proves lexical containment beneath the trusted
            // NEOTH home root before this mapping is constructible.
            UpdaterLeafTarget::Stage(_) => Action::WriteNeothHome,
        }
    }

    fn compute_binding_sha256(&self) -> String {
        let mut digest = Sha256::new();
        digest_field(&mut digest, b"schema_version", &[AUDIT_SCHEMA_VERSION]);
        digest_field(&mut digest, b"operation_id", self.operation_id.as_bytes());
        digest_field(&mut digest, b"request_id", self.request_id.as_bytes());
        digest_field(
            &mut digest,
            b"accepted_epoch",
            &self.accepted_epoch.to_be_bytes(),
        );
        digest_field(&mut digest, b"task", self.task.as_str().as_bytes());
        digest_field(&mut digest, b"lane", self.lane.as_str().as_bytes());
        digest_field(
            &mut digest,
            b"component",
            self.component.kind_str().as_bytes(),
        );
        digest_optional(
            &mut digest,
            b"component_identity_sha256",
            self.component.identity_sha256().map(str::as_bytes),
        );
        digest_field(&mut digest, b"effect", self.effect.as_str().as_bytes());

        match &self.target {
            UpdaterLeafTarget::Http(http) => {
                digest_field(&mut digest, b"target_kind", b"http");
                digest_field(&mut digest, b"method", http.method.as_str().as_bytes());
                digest_field(&mut digest, b"origin", http.origin.as_bytes());
                digest_field(&mut digest, b"path", http.path.as_bytes());
                digest_optional(
                    &mut digest,
                    b"query_sha256",
                    http.query_sha256.as_deref().map(str::as_bytes),
                );
                digest_field(&mut digest, b"body_sha256", http.body_sha256.as_bytes());
                digest_field(
                    &mut digest,
                    b"body_size_bytes",
                    &http.body_size_bytes.to_be_bytes(),
                );
                digest_optional(
                    &mut digest,
                    b"expected_content_sha256",
                    http.expected_content_sha256.as_deref().map(str::as_bytes),
                );
                digest_field(
                    &mut digest,
                    b"max_response_bytes",
                    &http.max_response_bytes.to_be_bytes(),
                );
            }
            UpdaterLeafTarget::Process(process) => {
                digest_field(&mut digest, b"target_kind", b"process");
                digest_field(&mut digest, b"program", process.program.as_str().as_bytes());
                digest_field(&mut digest, b"argv_sha256", process.argv_sha256.as_bytes());
                digest_field(
                    &mut digest,
                    b"argv_count",
                    &process.argv_count.to_be_bytes(),
                );
                digest_field(
                    &mut digest,
                    b"stdin_sha256",
                    process.stdin_sha256.as_bytes(),
                );
                digest_field(
                    &mut digest,
                    b"stdin_size_bytes",
                    &process.stdin_size_bytes.to_be_bytes(),
                );
                digest_field(
                    &mut digest,
                    b"max_output_bytes",
                    &process.max_output_bytes.to_be_bytes(),
                );
            }
            UpdaterLeafTarget::Stage(stage) => {
                digest_field(&mut digest, b"target_kind", b"stage");
                digest_field(
                    &mut digest,
                    b"neoth_home_sha256",
                    stage.neoth_home_sha256.as_bytes(),
                );
                digest_field(
                    &mut digest,
                    b"destination_sha256",
                    stage.destination_sha256.as_bytes(),
                );
                digest_field(
                    &mut digest,
                    b"content_sha256",
                    stage.content_sha256.as_bytes(),
                );
                digest_field(
                    &mut digest,
                    b"content_size_bytes",
                    &stage.content_size_bytes.to_be_bytes(),
                );
            }
        }
        hex::encode(digest.finalize())
    }

    fn validate_success<T>(&self, success: &UpdaterLeafSuccess<T>) -> Result<()> {
        anyhow::ensure!(
            self.effect.allows_outcome(success.outcome),
            "updater effect {} forbids outcome {}",
            self.effect.as_str(),
            success.outcome.as_str()
        );
        match &self.target {
            UpdaterLeafTarget::Http(http) => {
                if success.outcome == UpdaterLeafOutcomeCode::Redirected {
                    anyhow::ensure!(
                        success.observed_sha256.is_none() && success.observed_size_bytes.is_none(),
                        "redirect result cannot claim an observed response artifact"
                    );
                    return Ok(());
                }
                if success.outcome == UpdaterLeafOutcomeCode::NotModified {
                    anyhow::ensure!(
                        success.observed_sha256.is_none() && success.observed_size_bytes.is_none(),
                        "not-modified result cannot claim an observed response artifact"
                    );
                    return Ok(());
                }
                let observed_sha256 = success
                    .observed_sha256
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("HTTP success omitted observed SHA-256"))?;
                validate_sha256(observed_sha256)?;
                let observed_size = success
                    .observed_size_bytes
                    .ok_or_else(|| anyhow::anyhow!("HTTP success omitted observed size"))?;
                anyhow::ensure!(
                    observed_size <= http.max_response_bytes,
                    "HTTP success exceeded its bound response size"
                );
                if let Some(expected) = http.expected_content_sha256.as_deref() {
                    anyhow::ensure!(
                        observed_sha256.eq_ignore_ascii_case(expected),
                        "HTTP success did not match its bound content SHA-256"
                    );
                    anyhow::ensure!(
                        success.outcome == UpdaterLeafOutcomeCode::Verified,
                        "content-bound HTTP success must use the verified outcome"
                    );
                }
            }
            UpdaterLeafTarget::Process(_) => {
                anyhow::ensure!(
                    success.observed_sha256.is_none() && success.observed_size_bytes.is_none(),
                    "process result cannot claim an HTTP/stage artifact"
                );
            }
            UpdaterLeafTarget::Stage(stage) => {
                anyhow::ensure!(
                    success.outcome == UpdaterLeafOutcomeCode::Prepared,
                    "verified stage write must use the prepared outcome"
                );
                anyhow::ensure!(
                    success
                        .observed_sha256
                        .as_deref()
                        .is_some_and(|hash| hash.eq_ignore_ascii_case(&stage.content_sha256)),
                    "stage success did not match its bound content SHA-256"
                );
                anyhow::ensure!(
                    success.observed_size_bytes == Some(stage.content_size_bytes),
                    "stage success did not match its bound content size"
                );
            }
        }
        Ok(())
    }
}

fn validate_process_binding(effect: UpdaterLeafEffect, target: &UpdaterLeafTarget) -> Result<()> {
    let UpdaterLeafTarget::Process(process) = target else {
        return Ok(());
    };
    let allowed = match effect {
        UpdaterLeafEffect::CliInstalledVersionProbe => {
            matches!(process.program, UpdaterProgram::ManagedCli)
        }
        UpdaterLeafEffect::CliLatestVersionProbe => {
            matches!(process.program, UpdaterProgram::Npm)
        }
        UpdaterLeafEffect::CliInstall => matches!(
            process.program,
            UpdaterProgram::Npm | UpdaterProgram::PowerShell
        ),
        UpdaterLeafEffect::SkillGitProbe => matches!(process.program, UpdaterProgram::Git),
        _ => false,
    };
    anyhow::ensure!(
        allowed,
        "updater effect {} forbids process program {}",
        effect.as_str(),
        process.program.as_str()
    );
    Ok(())
}

/// Sanitized success classification recorded in the terminal frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UpdaterLeafOutcomeCode {
    Completed,
    Redirected,
    NotModified,
    #[allow(dead_code)] // R3-18 version/Git probes remain fail-closed.
    UpdateAvailable,
    Verified,
    Installed,
    Prepared,
    #[allow(dead_code)] // Retained for recovery/legacy WAL classifications.
    Staged,
    Clean,
}

impl UpdaterLeafOutcomeCode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Redirected => "redirected",
            Self::NotModified => "not_modified",
            Self::UpdateAvailable => "update_available",
            Self::Verified => "verified",
            Self::Installed => "installed",
            Self::Prepared => "prepared",
            Self::Staged => "staged",
            Self::Clean => "clean",
        }
    }
}

fn parse_updater_leaf_outcome(value: &str) -> Result<UpdaterLeafOutcomeCode> {
    match value {
        "completed" => Ok(UpdaterLeafOutcomeCode::Completed),
        "redirected" => Ok(UpdaterLeafOutcomeCode::Redirected),
        "not_modified" => Ok(UpdaterLeafOutcomeCode::NotModified),
        "update_available" => Ok(UpdaterLeafOutcomeCode::UpdateAvailable),
        "verified" => Ok(UpdaterLeafOutcomeCode::Verified),
        "installed" => Ok(UpdaterLeafOutcomeCode::Installed),
        "prepared" => Ok(UpdaterLeafOutcomeCode::Prepared),
        "staged" => Ok(UpdaterLeafOutcomeCode::Staged),
        "clean" => Ok(UpdaterLeafOutcomeCode::Clean),
        _ => anyhow::bail!("updater success has invalid outcome"),
    }
}

/// Successful typed leaf value plus optional verified artifact metadata.
#[derive(Debug)]
pub(crate) struct UpdaterLeafSuccess<T> {
    value: T,
    outcome: UpdaterLeafOutcomeCode,
    observed_sha256: Option<String>,
    observed_size_bytes: Option<u64>,
}

impl<T> UpdaterLeafSuccess<T> {
    pub(crate) fn new(value: T, outcome: UpdaterLeafOutcomeCode) -> Self {
        Self {
            value,
            outcome,
            observed_sha256: None,
            observed_size_bytes: None,
        }
    }

    pub(crate) fn with_observed_artifact(mut self, sha256: &str, size_bytes: u64) -> Result<Self> {
        self.observed_sha256 =
            Some(normalize_sha256(sha256).context("invalid observed artifact hash")?);
        self.observed_size_bytes = Some(size_bytes);
        Ok(self)
    }

    pub(crate) fn map_value<U>(self, map: impl FnOnce(T) -> U) -> UpdaterLeafSuccess<U> {
        UpdaterLeafSuccess {
            value: map(self.value),
            outcome: self.outcome,
            observed_sha256: self.observed_sha256,
            observed_size_bytes: self.observed_size_bytes,
        }
    }
}

/// Sanitized failure class. The full source is returned to the caller but only
/// its digest is written to the WAL.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UpdaterLeafFailureKind {
    Transport,
    Timeout,
    Integrity,
    Protocol,
    #[allow(dead_code)] // R3-18 process leaves remain fail-closed.
    Process,
    Io,
    Panic,
    #[allow(dead_code)] // Cancellation terminals use the sealed terminal constructor.
    Cancelled,
    #[allow(dead_code)] // Policy refusals are represented by the gate error boundary.
    Policy,
}

impl UpdaterLeafFailureKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::Timeout => "timeout",
            Self::Integrity => "integrity",
            Self::Protocol => "protocol",
            Self::Process => "process",
            Self::Io => "io",
            Self::Panic => "panic",
            Self::Cancelled => "cancelled",
            Self::Policy => "policy",
        }
    }
}

#[derive(Debug)]
pub(crate) struct UpdaterLeafFailure {
    kind: UpdaterLeafFailureKind,
    source: anyhow::Error,
}

impl UpdaterLeafFailure {
    pub(crate) fn new(kind: UpdaterLeafFailureKind, source: anyhow::Error) -> Self {
        Self { kind, source }
    }

    fn error_sha256(&self) -> String {
        sha256_hex(format!("{:#}", self.source).as_bytes())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UpdaterLeafAuditPhase {
    Intent,
    Result,
}

impl UpdaterLeafAuditPhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::Result => "result",
        }
    }
}

impl std::fmt::Display for UpdaterLeafAuditPhase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Typed boundary error. Raw effect text is never part of `Display`; callers
/// can still inspect the source chain locally.
#[derive(Debug, Error)]
pub(crate) enum UpdaterLeafExecutionError {
    #[error(
        "updater leaf accepted epoch mismatch (authority {authority_epoch}, request {request_epoch})"
    )]
    EpochMismatch {
        authority_epoch: u64,
        request_epoch: u64,
    },
    #[error(transparent)]
    GenerationRetired(#[from] GenerationRetired),
    #[error("updater leaf permission gate refused the exact effect")]
    Permission(#[source] GateError),
    #[error("mandatory updater leaf {phase} audit failed")]
    Audit {
        phase: UpdaterLeafAuditPhase,
        effect_error_sha256: Option<String>,
        #[source]
        source: anyhow::Error,
    },
    #[error("updater leaf permit/request mismatch")]
    PermitMismatch,
    #[error("updater leaf effect failed ({kind}; digest {error_sha256})")]
    Effect {
        kind: &'static str,
        error_sha256: String,
        #[source]
        source: anyhow::Error,
    },
}

impl UpdaterLeafExecutionError {
    /// A normal policy refusal is an honest skipped recurring pass. Audit
    /// unavailability, epoch drift, permit mismatches, effect failures and
    /// terminal WAL failures remain operational errors and must reach the
    /// reload-owned supervisor.
    pub(crate) fn is_policy_refusal(&self) -> bool {
        matches!(
            self,
            Self::Permission(GateError::Denied(_) | GateError::Aborted(_))
        )
    }

    pub(crate) fn is_generation_retired(&self) -> bool {
        matches!(self, Self::GenerationRetired(_))
    }
}

pub(crate) fn error_is_policy_refusal(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<UpdaterLeafExecutionError>()
        .is_some_and(UpdaterLeafExecutionError::is_policy_refusal)
}

pub(crate) fn error_is_generation_retired(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<UpdaterLeafExecutionError>()
        .is_some_and(UpdaterLeafExecutionError::is_generation_retired)
}

#[derive(Serialize)]
struct IntentPayload<'a> {
    schema_version: u8,
    operation_id: &'a str,
    request_id: &'a str,
    accepted_epoch: u64,
    task: UpdaterAuthorityTask,
    lane: UpdaterAuthorityLane,
    component: &'a UpdaterAuthorityComponent,
    effect: UpdaterLeafEffect,
    request_binding_sha256: &'a str,
    phase: &'static str,
    target: &'a UpdaterLeafTarget,
    ts_unix: u64,
}

#[derive(Serialize)]
struct ResultPayload<'a> {
    schema_version: u8,
    operation_id: &'a str,
    request_id: &'a str,
    accepted_epoch: u64,
    task: UpdaterAuthorityTask,
    lane: UpdaterAuthorityLane,
    component: &'a UpdaterAuthorityComponent,
    effect: UpdaterLeafEffect,
    request_binding_sha256: &'a str,
    phase: &'static str,
    status: &'static str,
    outcome: Option<&'static str>,
    observed_sha256: Option<&'a str>,
    observed_size_bytes: Option<u64>,
    error_kind: Option<&'static str>,
    error_sha256: Option<&'a str>,
    ts_unix: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveredIntentPayload {
    schema_version: u8,
    operation_id: String,
    request_id: String,
    accepted_epoch: u64,
    task: UpdaterAuthorityTask,
    lane: UpdaterAuthorityLane,
    component: UpdaterAuthorityComponent,
    effect: UpdaterLeafEffect,
    request_binding_sha256: String,
    phase: String,
    target: UpdaterLeafTarget,
    ts_unix: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveredResultPayload {
    schema_version: u8,
    operation_id: String,
    request_id: String,
    accepted_epoch: u64,
    task: UpdaterAuthorityTask,
    lane: UpdaterAuthorityLane,
    component: UpdaterAuthorityComponent,
    effect: UpdaterLeafEffect,
    request_binding_sha256: String,
    phase: String,
    status: String,
    outcome: Option<String>,
    observed_sha256: Option<String>,
    observed_size_bytes: Option<u64>,
    error_kind: Option<String>,
    error_sha256: Option<String>,
    ts_unix: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct RecoveredUpdaterLeafIdentity {
    pub(super) operation_id: String,
    pub(super) request_id: String,
}

#[derive(Clone, Debug)]
pub(super) struct RecoveredUpdaterLeafIntent {
    request: UpdaterLeafRequest,
}

impl RecoveredUpdaterLeafIntent {
    pub(super) fn identity(&self) -> RecoveredUpdaterLeafIdentity {
        RecoveredUpdaterLeafIdentity {
            operation_id: self.request.operation_id.clone(),
            request_id: self.request.request_id.clone(),
        }
    }
}

#[derive(Clone, Debug)]
enum RecoveredUpdaterLeafResultKind {
    Success {
        outcome: UpdaterLeafOutcomeCode,
        observed_sha256: Option<String>,
        observed_size_bytes: Option<u64>,
    },
    Failure {
        error_kind: String,
        error_sha256: String,
    },
}

#[derive(Clone, Debug)]
pub(super) struct RecoveredUpdaterLeafResult {
    schema_version: u8,
    operation_id: String,
    request_id: String,
    accepted_epoch: u64,
    task: UpdaterAuthorityTask,
    lane: UpdaterAuthorityLane,
    component: UpdaterAuthorityComponent,
    effect: UpdaterLeafEffect,
    request_binding_sha256: String,
    kind: RecoveredUpdaterLeafResultKind,
}

impl RecoveredUpdaterLeafResult {
    pub(super) fn identity(&self) -> RecoveredUpdaterLeafIdentity {
        RecoveredUpdaterLeafIdentity {
            operation_id: self.operation_id.clone(),
            request_id: self.request_id.clone(),
        }
    }

    pub(super) fn is_canonical_interrupted_failure(&self) -> bool {
        matches!(
            &self.kind,
            RecoveredUpdaterLeafResultKind::Failure {
                error_kind,
                error_sha256,
            } if error_kind == "interrupted"
                && error_sha256 == &sha256_hex(INTERRUPTED_ERROR_DOMAIN)
        )
    }

    pub(super) fn is_interrupted_failure(&self) -> bool {
        matches!(
            &self.kind,
            RecoveredUpdaterLeafResultKind::Failure { error_kind, .. }
                if error_kind == "interrupted"
        )
    }

    pub(super) fn validate_matches(&self, intent: &RecoveredUpdaterLeafIntent) -> Result<()> {
        let request = &intent.request;
        anyhow::ensure!(
            self.schema_version == AUDIT_SCHEMA_VERSION
                && self.operation_id == request.operation_id
                && self.request_id == request.request_id
                && self.accepted_epoch == request.accepted_epoch
                && self.task == request.task
                && self.lane == request.lane
                && self.component == request.component
                && self.effect == request.effect
                && self.request_binding_sha256 == request.binding_sha256,
            "updater result conflicts with its intent"
        );
        if let RecoveredUpdaterLeafResultKind::Success {
            outcome,
            observed_sha256,
            observed_size_bytes,
        } = &self.kind
        {
            request.validate_success(&UpdaterLeafSuccess {
                value: (),
                outcome: *outcome,
                observed_sha256: observed_sha256.clone(),
                observed_size_bytes: *observed_size_bytes,
            })?;
        }
        Ok(())
    }
}

pub(super) fn decode_and_validate_updater_leaf_intent(
    payload: &[u8],
) -> Result<RecoveredUpdaterLeafIntent> {
    let payload: RecoveredIntentPayload =
        serde_json::from_slice(payload).context("decode updater intent")?;
    anyhow::ensure!(
        payload.schema_version == AUDIT_SCHEMA_VERSION,
        "unsupported updater intent schema version {}",
        payload.schema_version
    );
    anyhow::ensure!(payload.phase == "intent", "updater intent has wrong phase");
    let _ = payload.ts_unix;

    let recorded_binding = payload.request_binding_sha256;
    validate_sha256(&recorded_binding)?;
    let request = UpdaterLeafRequest::build(
        payload.operation_id,
        payload.request_id,
        payload.accepted_epoch,
        payload.task,
        payload.lane,
        payload.component,
        payload.effect,
        payload.target,
    )?;
    anyhow::ensure!(
        request.binding_sha256 == recorded_binding,
        "updater intent request binding does not match its payload"
    );
    Ok(RecoveredUpdaterLeafIntent { request })
}

pub(super) fn decode_and_validate_updater_leaf_result(
    payload: &[u8],
) -> Result<RecoveredUpdaterLeafResult> {
    let payload: RecoveredResultPayload =
        serde_json::from_slice(payload).context("decode updater result")?;
    anyhow::ensure!(
        payload.schema_version == AUDIT_SCHEMA_VERSION,
        "unsupported updater result schema version {}",
        payload.schema_version
    );
    anyhow::ensure!(payload.phase == "result", "updater result has wrong phase");
    validate_audit_id(&payload.operation_id, "operation")?;
    validate_audit_id(&payload.request_id, "request")?;
    validate_sha256(&payload.request_binding_sha256)?;
    payload.component.validate()?;
    anyhow::ensure!(
        payload.lane.task() == payload.task,
        "updater result lane/task mismatch"
    );
    anyhow::ensure!(
        payload.component.task() == payload.task,
        "updater result component/task mismatch"
    );
    anyhow::ensure!(
        payload.effect.lane_allowed(payload.lane),
        "updater result effect/lane mismatch"
    );
    anyhow::ensure!(
        payload.observed_sha256.is_some() == payload.observed_size_bytes.is_some(),
        "updater result observed artifact is incomplete"
    );
    if let Some(hash) = payload.observed_sha256.as_deref() {
        validate_sha256(hash)?;
    }
    let _ = payload.ts_unix;

    let kind = match payload.status.as_str() {
        "success" => {
            let outcome = parse_updater_leaf_outcome(
                payload
                    .outcome
                    .as_deref()
                    .context("updater success omitted outcome")?,
            )?;
            anyhow::ensure!(
                payload.error_kind.is_none() && payload.error_sha256.is_none(),
                "updater success carries failure fields"
            );
            RecoveredUpdaterLeafResultKind::Success {
                outcome,
                observed_sha256: payload.observed_sha256,
                observed_size_bytes: payload.observed_size_bytes,
            }
        }
        "failure" => {
            anyhow::ensure!(
                payload.outcome.is_none()
                    && payload.observed_sha256.is_none()
                    && payload.observed_size_bytes.is_none(),
                "updater failure carries success fields"
            );
            let error_kind = payload
                .error_kind
                .as_deref()
                .context("updater failure omitted error kind")?;
            anyhow::ensure!(
                !error_kind.is_empty()
                    && error_kind.len() <= 64
                    && error_kind
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
                "updater failure has invalid error kind"
            );
            validate_sha256(
                payload
                    .error_sha256
                    .as_deref()
                    .context("updater failure omitted error digest")?,
            )?;
            RecoveredUpdaterLeafResultKind::Failure {
                error_kind: error_kind.to_string(),
                error_sha256: payload
                    .error_sha256
                    .expect("validated updater failure digest is present"),
            }
        }
        _ => anyhow::bail!("updater result has invalid status"),
    };

    Ok(RecoveredUpdaterLeafResult {
        schema_version: payload.schema_version,
        operation_id: payload.operation_id,
        request_id: payload.request_id,
        accepted_epoch: payload.accepted_epoch,
        task: payload.task,
        lane: payload.lane,
        component: payload.component,
        effect: payload.effect,
        request_binding_sha256: payload.request_binding_sha256,
        kind,
    })
}

pub(super) fn synthetic_interrupted_result_payload(
    intent: &RecoveredUpdaterLeafIntent,
    ts_unix: u64,
) -> Result<Vec<u8>> {
    serialize_result_payload(
        &intent.request,
        &UpdaterLeafTerminal::Failure {
            error_kind: "interrupted",
            error_sha256: sha256_hex(INTERRUPTED_ERROR_DOMAIN),
        },
        ts_unix,
    )
    .context("serialize recovered updater leaf result")
}

pub(super) fn serialize_updater_leaf_intent_payload(
    request: &UpdaterLeafRequest,
    ts_unix: u64,
) -> Result<Vec<u8>> {
    serde_json::to_vec(&IntentPayload {
        schema_version: AUDIT_SCHEMA_VERSION,
        operation_id: &request.operation_id,
        request_id: &request.request_id,
        accepted_epoch: request.accepted_epoch,
        task: request.task,
        lane: request.lane,
        component: &request.component,
        effect: request.effect,
        request_binding_sha256: &request.binding_sha256,
        phase: "intent",
        target: &request.target,
        ts_unix,
    })
    .context("serialize mandatory updater leaf intent")
}

fn serialize_result_payload(
    request: &UpdaterLeafRequest,
    terminal: &UpdaterLeafTerminal,
    ts_unix: u64,
) -> Result<Vec<u8>> {
    let payload = match terminal {
        UpdaterLeafTerminal::Success {
            outcome,
            observed_sha256,
            observed_size_bytes,
        } => ResultPayload {
            schema_version: AUDIT_SCHEMA_VERSION,
            operation_id: &request.operation_id,
            request_id: &request.request_id,
            accepted_epoch: request.accepted_epoch,
            task: request.task,
            lane: request.lane,
            component: &request.component,
            effect: request.effect,
            request_binding_sha256: &request.binding_sha256,
            phase: "result",
            status: "success",
            outcome: Some(outcome.as_str()),
            observed_sha256: observed_sha256.as_deref(),
            observed_size_bytes: *observed_size_bytes,
            error_kind: None,
            error_sha256: None,
            ts_unix,
        },
        UpdaterLeafTerminal::Failure {
            error_kind,
            error_sha256,
        } => ResultPayload {
            schema_version: AUDIT_SCHEMA_VERSION,
            operation_id: &request.operation_id,
            request_id: &request.request_id,
            accepted_epoch: request.accepted_epoch,
            task: request.task,
            lane: request.lane,
            component: &request.component,
            effect: request.effect,
            request_binding_sha256: &request.binding_sha256,
            phase: "result",
            status: "failure",
            outcome: None,
            observed_sha256: None,
            observed_size_bytes: None,
            error_kind: Some(error_kind),
            error_sha256: Some(error_sha256),
            ts_unix,
        },
    };
    serde_json::to_vec(&payload).context("serialize mandatory updater leaf result")
}

#[async_trait::async_trait]
trait UpdaterLeafAuditSink: Send + Sync {
    async fn append_updater_leaf(&self, subtype: ExtendedSubtype, payload: Vec<u8>) -> Result<()>;
}

#[async_trait::async_trait]
impl UpdaterLeafAuditSink for WalWriterHandle {
    async fn append_updater_leaf(&self, subtype: ExtendedSubtype, payload: Vec<u8>) -> Result<()> {
        let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
            .event_subtype(subtype as u8)
            .build();
        self.append(header, payload)
            .await
            .context("append mandatory updater leaf audit frame")?;
        Ok(())
    }
}

#[derive(Debug)]
enum UpdaterLeafTerminal {
    Success {
        outcome: UpdaterLeafOutcomeCode,
        observed_sha256: Option<String>,
        observed_size_bytes: Option<u64>,
    },
    Failure {
        error_kind: &'static str,
        error_sha256: String,
    },
}

impl UpdaterLeafTerminal {
    fn cancelled() -> Self {
        Self::Failure {
            error_kind: "cancelled",
            error_sha256: sha256_hex(b"updater_leaf_cancelled"),
        }
    }

    fn error_sha256(&self) -> Option<&str> {
        match self {
            Self::Success { .. } => None,
            Self::Failure { error_sha256, .. } => Some(error_sha256),
        }
    }
}

struct UpdaterLeafAuditTicket {
    request: UpdaterLeafRequest,
    sink: Arc<dyn UpdaterLeafAuditSink>,
    clock: fn() -> u64,
    generation_lease: UpdaterLeafLease,
}

impl UpdaterLeafAuditTicket {
    fn intent_payload(&self) -> Result<Vec<u8>> {
        serialize_updater_leaf_intent_payload(&self.request, (self.clock)())
    }

    async fn append_terminal(&self, terminal: UpdaterLeafTerminal) -> Result<()> {
        let payload = serialize_result_payload(&self.request, &terminal, (self.clock)())?;
        self.sink
            .append_updater_leaf(ExtendedSubtype::UpdaterLeafResult, payload)
            .await
            .context("append mandatory updater leaf result")
    }
}

enum UpdaterIntentState {
    Pending(tokio::task::JoinHandle<Result<()>>),
    Durable,
    NotDurable,
    Disarmed,
}

/// Owns the gap between enqueueing the intent and installing the post-intent
/// guard. The append task survives cancellation of the caller's future.
struct UpdaterIntentLifecycle {
    ticket: Option<UpdaterLeafAuditTicket>,
    state: UpdaterIntentState,
}

impl UpdaterIntentLifecycle {
    fn start(
        ticket: UpdaterLeafAuditTicket,
    ) -> std::result::Result<Self, UpdaterLeafExecutionError> {
        let payload =
            ticket
                .intent_payload()
                .map_err(|source| UpdaterLeafExecutionError::Audit {
                    phase: UpdaterLeafAuditPhase::Intent,
                    effect_error_sha256: None,
                    source,
                })?;
        let sink = Arc::clone(&ticket.sink);
        let runtime = tokio::runtime::Handle::try_current().map_err(|source| {
            UpdaterLeafExecutionError::Audit {
                phase: UpdaterLeafAuditPhase::Intent,
                effect_error_sha256: None,
                source: source.into(),
            }
        })?;
        let state = UpdaterIntentState::Pending(runtime.spawn(async move {
            sink.append_updater_leaf(ExtendedSubtype::UpdaterLeafIntent, payload)
                .await
                .context("append mandatory updater leaf intent")
        }));
        Ok(Self {
            ticket: Some(ticket),
            state,
        })
    }

    async fn wait_for_durability(&mut self) -> std::result::Result<(), UpdaterLeafExecutionError> {
        let result = match &mut self.state {
            UpdaterIntentState::Pending(task) => match task.await {
                Ok(result) => result,
                Err(source) => Err(source.into()),
            },
            UpdaterIntentState::Durable
            | UpdaterIntentState::NotDurable
            | UpdaterIntentState::Disarmed => {
                unreachable!("updater intent durability may be awaited only once")
            }
        };
        self.state = if result.is_ok() {
            UpdaterIntentState::Durable
        } else {
            UpdaterIntentState::NotDurable
        };
        result.map_err(|source| UpdaterLeafExecutionError::Audit {
            phase: UpdaterLeafAuditPhase::Intent,
            effect_error_sha256: None,
            source,
        })
    }

    fn into_guard(mut self) -> UpdaterLeafAuditGuard {
        debug_assert!(matches!(self.state, UpdaterIntentState::Durable));
        self.state = UpdaterIntentState::Disarmed;
        UpdaterLeafAuditGuard {
            ticket: self.ticket.take(),
        }
    }
}

impl Drop for UpdaterIntentLifecycle {
    fn drop(&mut self) {
        let Some(ticket) = self.ticket.take() else {
            return;
        };
        let state = std::mem::replace(&mut self.state, UpdaterIntentState::Disarmed);
        let cleanup = async move {
            let durable = match state {
                UpdaterIntentState::Pending(task) => match task.await {
                    Ok(Ok(())) => true,
                    Ok(Err(error)) => {
                        tracing::error!(
                            error = %error,
                            "cancelled updater intent did not become durable"
                        );
                        false
                    }
                    Err(error) => {
                        tracing::error!(
                            error = %error,
                            "cancelled updater intent task failed before durability"
                        );
                        false
                    }
                },
                UpdaterIntentState::Durable => true,
                UpdaterIntentState::NotDurable | UpdaterIntentState::Disarmed => false,
            };
            if durable
                && let Err(error) = ticket
                    .append_terminal(UpdaterLeafTerminal::cancelled())
                    .await
            {
                tracing::error!(
                    error = %error,
                    "updater pre-effect cancellation terminal audit failed"
                );
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(cleanup);
            }
            Err(error) => tracing::error!(
                error = %error,
                "updater intent lifecycle dropped outside a Tokio runtime"
            ),
        }
    }
}

/// Pending one-shot capability. It is intentionally neither `Clone` nor
/// `Copy`; [`Self::execute`] consumes it while checking the exact request.
#[derive(Debug)]
struct UpdaterLeafPermit {
    operation_id: String,
    request_id: String,
    accepted_epoch: u64,
    request_binding_sha256: String,
    effect: UpdaterLeafEffect,
    target: UpdaterLeafTarget,
}

impl UpdaterLeafPermit {
    fn for_request(request: &UpdaterLeafRequest) -> Self {
        Self {
            operation_id: request.operation_id.clone(),
            request_id: request.request_id.clone(),
            accepted_epoch: request.accepted_epoch,
            request_binding_sha256: request.binding_sha256.clone(),
            effect: request.effect,
            target: request.target.clone(),
        }
    }

    async fn execute<F, Fut, T>(
        self,
        request: &UpdaterLeafRequest,
        effect: F,
    ) -> std::result::Result<
        std::result::Result<UpdaterLeafSuccess<T>, UpdaterLeafFailure>,
        UpdaterLeafExecutionError,
    >
    where
        F: FnOnce(UpdaterLeafAuthority) -> Fut,
        Fut: Future<Output = std::result::Result<UpdaterLeafSuccess<T>, UpdaterLeafFailure>>,
    {
        if self.operation_id != request.operation_id
            || self.request_id != request.request_id
            || self.accepted_epoch != request.accepted_epoch
            || self.request_binding_sha256 != request.binding_sha256
        {
            return Err(UpdaterLeafExecutionError::PermitMismatch);
        }
        let authority = UpdaterLeafAuthority {
            operation_id: self.operation_id,
            request_id: self.request_id,
            accepted_epoch: self.accepted_epoch,
            request_binding_sha256: self.request_binding_sha256,
            effect: self.effect,
            target: self.target,
        };
        let future = match std::panic::catch_unwind(AssertUnwindSafe(|| effect(authority))) {
            Ok(future) => future,
            Err(_) => {
                return Ok(Err(UpdaterLeafFailure::new(
                    UpdaterLeafFailureKind::Panic,
                    anyhow::anyhow!("updater leaf panicked before its future was created"),
                )));
            }
        };
        Ok(match AssertUnwindSafe(future).catch_unwind().await {
            Ok(outcome) => outcome,
            Err(_) => Err(UpdaterLeafFailure::new(
                UpdaterLeafFailureKind::Panic,
                anyhow::anyhow!("updater leaf panicked while executing"),
            )),
        })
    }
}

/// Owns the mandatory terminal edge after the intent became durable.
struct UpdaterLeafAuditGuard {
    ticket: Option<UpdaterLeafAuditTicket>,
}

impl UpdaterLeafAuditGuard {
    async fn finish(
        &mut self,
        terminal: UpdaterLeafTerminal,
    ) -> std::result::Result<UpdaterLeafLease, UpdaterLeafExecutionError> {
        let effect_error_sha256 = terminal.error_sha256().map(str::to_string);
        let Some(ticket) = self.ticket.take() else {
            unreachable!("updater terminal audit can finish only once");
        };
        // The terminal append survives cancellation while this method awaits.
        tokio::spawn(async move {
            ticket.append_terminal(terminal).await?;
            Ok::<_, anyhow::Error>(ticket.generation_lease)
        })
        .await
        .map_err(|source| UpdaterLeafExecutionError::Audit {
            phase: UpdaterLeafAuditPhase::Result,
            effect_error_sha256: effect_error_sha256.clone(),
            source: source.into(),
        })?
        .map_err(|source| UpdaterLeafExecutionError::Audit {
            phase: UpdaterLeafAuditPhase::Result,
            effect_error_sha256,
            source,
        })
    }
}

impl Drop for UpdaterLeafAuditGuard {
    fn drop(&mut self) {
        let Some(ticket) = self.ticket.take() else {
            return;
        };
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(async move {
                    if let Err(error) = ticket
                        .append_terminal(UpdaterLeafTerminal::cancelled())
                        .await
                    {
                        tracing::error!(
                            error = %error,
                            "updater effect cancellation terminal audit failed"
                        );
                    }
                });
            }
            Err(error) => tracing::error!(
                error = %error,
                "updater leaf audit guard dropped outside a Tokio runtime"
            ),
        }
    }
}

/// Owned authority delivered to the concrete effect closure after the intent
/// ACK and exact permit/request match. This type never leaves this module:
/// target-specific executors validate their concrete sink arguments before
/// invoking the caller's effect factory.
#[derive(Debug)]
struct UpdaterLeafAuthority {
    operation_id: String,
    request_id: String,
    accepted_epoch: u64,
    request_binding_sha256: String,
    effect: UpdaterLeafEffect,
    target: UpdaterLeafTarget,
}

impl UpdaterLeafAuthority {
    #[cfg(test)]
    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[cfg(test)]
    pub(crate) fn request_id(&self) -> &str {
        &self.request_id
    }

    #[cfg(test)]
    pub(crate) const fn accepted_epoch(&self) -> u64 {
        self.accepted_epoch
    }

    #[cfg(test)]
    pub(crate) fn request_binding_sha256(&self) -> &str {
        &self.request_binding_sha256
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_http(
        self,
        expected_effect: UpdaterLeafEffect,
        method: UpdaterHttpMethod,
        url: &str,
        body: &[u8],
        expected_content_sha256: Option<&str>,
        max_response_bytes: u64,
    ) -> std::result::Result<(), UpdaterLeafFailure> {
        let expected = HttpBinding::for_request(
            method,
            url,
            body,
            expected_content_sha256,
            max_response_bytes,
        )
        .map_err(|source| UpdaterLeafFailure::new(UpdaterLeafFailureKind::Protocol, source))?;
        let UpdaterLeafTarget::Http(binding) = self.target else {
            return Err(UpdaterLeafFailure::new(
                UpdaterLeafFailureKind::Protocol,
                anyhow::anyhow!("HTTP executor received a non-HTTP updater request"),
            ));
        };
        if self.effect != expected_effect || binding != expected {
            return Err(UpdaterLeafFailure::new(
                UpdaterLeafFailureKind::Protocol,
                anyhow::anyhow!("HTTP leaf arguments do not match the admitted updater request"),
            ));
        }
        let _ = (
            self.operation_id,
            self.request_id,
            self.accepted_epoch,
            self.request_binding_sha256,
        );
        Ok(())
    }

    fn validate_stage(
        self,
        neoth_home: &Path,
        destination: &Path,
        content_sha256: &str,
        content_size_bytes: u64,
    ) -> std::result::Result<(), UpdaterLeafFailure> {
        let expected =
            StageBinding::for_request(neoth_home, destination, content_sha256, content_size_bytes)
                .map_err(|source| {
                    UpdaterLeafFailure::new(UpdaterLeafFailureKind::Protocol, source)
                })?;
        let UpdaterLeafTarget::Stage(binding) = self.target else {
            return Err(UpdaterLeafFailure::new(
                UpdaterLeafFailureKind::Protocol,
                anyhow::anyhow!("stage executor received a non-stage updater request"),
            ));
        };
        if self.effect != UpdaterLeafEffect::VerifiedStageWrite || binding != expected {
            return Err(UpdaterLeafFailure::new(
                UpdaterLeafFailureKind::Protocol,
                anyhow::anyhow!("stage leaf arguments do not match the admitted updater request"),
            ));
        }
        let _ = (
            self.operation_id,
            self.request_id,
            self.accepted_epoch,
            self.request_binding_sha256,
        );
        Ok(())
    }
}

/// Successful verified-stage effect whose generation lease remains live until
/// the caller consumes the prepared value inside the completion closure.
///
/// This prevents a reload from retiring the admitted generation between the
/// durable `prepared` terminal frame and the visibility commit.
#[must_use = "the verified stage must be completed while its generation lease is held"]
pub(crate) struct UpdaterStageCompletion<T> {
    value: T,
    generation_lease: UpdaterLeafLease,
}

impl<T> UpdaterStageCompletion<T> {
    pub(crate) fn publish_with<F, R>(self, publish: F) -> R
    where
        F: FnOnce(T) -> R,
    {
        let Self {
            value,
            generation_lease,
        } = self;
        let result = publish(value);
        drop(generation_lease);
        result
    }
}

/// Mandatory intent/effect/result boundary for a concrete updater leaf.
pub(crate) struct UpdaterLeafAuthorizer {
    accepted_epoch: u64,
    updater_leaf_gate: Arc<UpdaterLeafGate>,
    policy: AutonomyPolicySnapshot,
    confirm: ConfirmStrategy,
    permission_writer: Option<WalWriterHandle>,
    sink: Arc<dyn UpdaterLeafAuditSink>,
    clock: fn() -> u64,
}

impl UpdaterLeafAuthorizer {
    /// Bind authority to one immutable accepted reload generation. Recurring
    /// callers pass [`ConfirmStrategy::FailClosed`].
    pub(crate) fn for_snapshot(
        writer: WalWriterHandle,
        snapshot: Arc<crate::config::reload::AcceptedConfigSnapshot>,
        confirm: ConfirmStrategy,
    ) -> Self {
        let accepted_epoch = snapshot.epoch();
        let policy = snapshot.config().autonomy_policy();
        let updater_leaf_gate = snapshot.updater_leaf_gate();
        Self {
            accepted_epoch,
            updater_leaf_gate,
            policy,
            confirm,
            permission_writer: Some(writer.clone()),
            sink: Arc::new(writer),
            clock: crate::time::now_unix_secs,
        }
    }

    #[cfg(test)]
    fn with_sink(
        accepted_epoch: u64,
        policy: AutonomyPolicySnapshot,
        confirm: ConfirmStrategy,
        sink: Arc<dyn UpdaterLeafAuditSink>,
        clock: fn() -> u64,
    ) -> Self {
        Self::with_sink_and_gate(
            accepted_epoch,
            Arc::new(UpdaterLeafGate::new(accepted_epoch)),
            policy,
            confirm,
            sink,
            clock,
        )
    }

    #[cfg(test)]
    pub(super) fn for_reconciliation_test(writer: WalWriterHandle, accepted_epoch: u64) -> Self {
        Self {
            accepted_epoch,
            updater_leaf_gate: Arc::new(UpdaterLeafGate::new(accepted_epoch)),
            policy: AutonomyPolicySnapshot::test_level(crate::permissions::AutonomyLevel::Standard),
            confirm: ConfirmStrategy::AlwaysAllow,
            permission_writer: None,
            sink: Arc::new(writer),
            clock: crate::time::now_unix_secs,
        }
    }

    #[cfg(test)]
    fn with_sink_and_gate(
        accepted_epoch: u64,
        updater_leaf_gate: Arc<UpdaterLeafGate>,
        policy: AutonomyPolicySnapshot,
        confirm: ConfirmStrategy,
        sink: Arc<dyn UpdaterLeafAuditSink>,
        clock: fn() -> u64,
    ) -> Self {
        Self {
            accepted_epoch,
            updater_leaf_gate,
            policy,
            confirm,
            permission_writer: None,
            sink,
            clock,
        }
    }

    /// Execute one HTTP leaf through the only crate-visible network authority
    /// surface. The effect factory is not invoked until the concrete sink
    /// arguments exactly match the admitted request.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn execute_http<F, Fut, T>(
        &self,
        request: UpdaterLeafRequest,
        expected_effect: UpdaterLeafEffect,
        method: UpdaterHttpMethod,
        url: &str,
        body: &[u8],
        expected_content_sha256: Option<&str>,
        max_response_bytes: u64,
        run: F,
    ) -> std::result::Result<T, UpdaterLeafExecutionError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = std::result::Result<UpdaterLeafSuccess<T>, UpdaterLeafFailure>>,
    {
        self.execute(request, move |authority| async move {
            authority.validate_http(
                expected_effect,
                method,
                url,
                body,
                expected_content_sha256,
                max_response_bytes,
            )?;
            run().await
        })
        .await
    }

    /// Execute one verified-stage leaf through the only crate-visible local
    /// stage authority surface.
    pub(crate) async fn execute_stage<F, Fut, T>(
        &self,
        request: UpdaterLeafRequest,
        neoth_home: &Path,
        destination: &Path,
        content_sha256: &str,
        content_size_bytes: u64,
        run: F,
    ) -> std::result::Result<UpdaterStageCompletion<T>, UpdaterLeafExecutionError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = std::result::Result<UpdaterLeafSuccess<T>, UpdaterLeafFailure>>,
    {
        let (value, generation_lease) = self
            .execute_with_lease(request, move |authority| async move {
                authority.validate_stage(
                    neoth_home,
                    destination,
                    content_sha256,
                    content_size_bytes,
                )?;
                run().await
            })
            .await?;
        Ok(UpdaterStageCompletion {
            value,
            generation_lease,
        })
    }

    /// Shared audit lifecycle. Kept module-private so crate callers cannot
    /// receive and ignore a generic authority token.
    async fn execute<F, Fut, T>(
        &self,
        request: UpdaterLeafRequest,
        effect: F,
    ) -> std::result::Result<T, UpdaterLeafExecutionError>
    where
        F: FnOnce(UpdaterLeafAuthority) -> Fut,
        Fut: Future<Output = std::result::Result<UpdaterLeafSuccess<T>, UpdaterLeafFailure>>,
    {
        let (value, generation_lease) = self.execute_with_lease(request, effect).await?;
        drop(generation_lease);
        Ok(value)
    }

    async fn execute_with_lease<F, Fut, T>(
        &self,
        request: UpdaterLeafRequest,
        effect: F,
    ) -> std::result::Result<(T, UpdaterLeafLease), UpdaterLeafExecutionError>
    where
        F: FnOnce(UpdaterLeafAuthority) -> Fut,
        Fut: Future<Output = std::result::Result<UpdaterLeafSuccess<T>, UpdaterLeafFailure>>,
    {
        if request.accepted_epoch != self.accepted_epoch {
            return Err(UpdaterLeafExecutionError::EpochMismatch {
                authority_epoch: self.accepted_epoch,
                request_epoch: request.accepted_epoch,
            });
        }
        let generation_lease = self
            .updater_leaf_gate
            .acquire()
            .map_err(UpdaterLeafExecutionError::GenerationRetired)?;
        let gate = Gate::for_policy(self.policy.clone()).with_confirm(self.confirm);
        let permission = match self.permission_writer.as_ref() {
            Some(writer) => {
                gate.check_with_audit_sink(
                    &request.permission_action(),
                    PermissionAuditSink::Writer(writer),
                    true,
                    Some(request.binding_sha256()),
                )
                .await
            }
            // `with_sink` exists only for focused unit tests of the updater
            // intent/result boundary. Every production constructor carries a
            // real writer and takes the mandatory-audit branch above.
            None => gate.check(&request.permission_action(), None).await,
        };
        permission.map_err(UpdaterLeafExecutionError::Permission)?;

        let ticket = UpdaterLeafAuditTicket {
            request: request.clone(),
            sink: Arc::clone(&self.sink),
            clock: self.clock,
            generation_lease,
        };
        let mut intent = UpdaterIntentLifecycle::start(ticket)?;
        intent.wait_for_durability().await?;
        let mut audit = intent.into_guard();

        let permit = UpdaterLeafPermit::for_request(&request);
        let mut outcome = permit.execute(&request, effect).await?;
        if let Ok(success) = &outcome
            && let Err(source) = request.validate_success(success)
        {
            outcome = Err(UpdaterLeafFailure::new(
                UpdaterLeafFailureKind::Protocol,
                source.context("updater leaf returned a result outside its request binding"),
            ));
        }
        let error_sha256 = outcome.as_ref().err().map(UpdaterLeafFailure::error_sha256);
        let terminal = match &outcome {
            Ok(success) => UpdaterLeafTerminal::Success {
                outcome: success.outcome,
                observed_sha256: success.observed_sha256.clone(),
                observed_size_bytes: success.observed_size_bytes,
            },
            Err(failure) => UpdaterLeafTerminal::Failure {
                error_kind: failure.kind.as_str(),
                error_sha256: error_sha256
                    .clone()
                    .expect("failure digest is always present"),
            },
        };
        let generation_lease = audit.finish(terminal).await?;

        match outcome {
            Ok(success) => Ok((success.value, generation_lease)),
            Err(failure) => {
                drop(generation_lease);
                Err(UpdaterLeafExecutionError::Effect {
                    kind: failure.kind.as_str(),
                    error_sha256: error_sha256.expect("failure digest is always present"),
                    source: failure.source,
                })
            }
        }
    }
}

fn validate_audit_id(value: &str, kind: &str) -> Result<()> {
    anyhow::ensure!(!value.is_empty(), "updater {kind} id is empty");
    anyhow::ensure!(
        value.len() <= MAX_AUDIT_ID_BYTES,
        "updater {kind} id exceeds {MAX_AUDIT_ID_BYTES} bytes"
    );
    anyhow::ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')),
        "updater {kind} id contains unsafe characters"
    );
    Ok(())
}

fn normalize_sha256(value: &str) -> Result<String> {
    validate_sha256(value)?;
    Ok(value.to_ascii_lowercase())
}

fn validate_sha256(value: &str) -> Result<()> {
    anyhow::ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "expected 64 hexadecimal SHA-256 characters"
    );
    Ok(())
}

fn sha256_hex(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn digest_field(digest: &mut Sha256, name: &[u8], value: &[u8]) {
    digest.update((name.len() as u64).to_be_bytes());
    digest.update(name);
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn digest_optional(digest: &mut Sha256, name: &[u8], value: Option<&[u8]>) {
    match value {
        Some(value) => {
            digest.update([1]);
            digest_field(digest, name, value);
        }
        None => {
            digest.update([0]);
            digest_field(digest, name, &[]);
        }
    }
}

fn validate_stage_destination(neoth_home: &Path, destination: &Path) -> Result<()> {
    anyhow::ensure!(
        neoth_home.is_absolute(),
        "trusted NEOTH home must be an absolute path"
    );
    anyhow::ensure!(
        destination.is_absolute(),
        "updater stage destination must be an absolute path"
    );
    anyhow::ensure!(
        !neoth_home
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir)),
        "trusted NEOTH home cannot contain parent traversal"
    );
    anyhow::ensure!(
        !destination
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir)),
        "updater stage destination cannot contain parent traversal"
    );
    let relative = destination.strip_prefix(neoth_home).with_context(|| {
        format!(
            "updater stage destination is outside the trusted NEOTH home (root digest {}, destination digest {})",
            path_sha256(neoth_home),
            path_sha256(destination)
        )
    })?;
    anyhow::ensure!(
        !relative.as_os_str().is_empty(),
        "updater stage destination must be a descendant, not the NEOTH home root"
    );
    anyhow::ensure!(
        relative
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_))),
        "updater stage destination must be a clean lexical descendant"
    );
    Ok(())
}

fn path_sha256(path: &Path) -> String {
    let mut digest = Sha256::new();
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        digest.update(path.as_os_str().as_bytes());
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        for unit in path.as_os_str().encode_wide() {
            digest.update(unit.to_le_bytes());
        }
    }
    #[cfg(not(any(unix, windows)))]
    digest.update(path.to_string_lossy().as_bytes());
    hex::encode(digest.finalize())
}

#[cfg(test)]
mod tests {
    use std::future::pending;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;

    const TEST_EPOCH: u64 = 41;
    const TEST_TS: u64 = 1_900_000_000;

    fn test_clock() -> u64 {
        TEST_TS
    }

    fn authorizer(sink: Arc<dyn UpdaterLeafAuditSink>) -> UpdaterLeafAuthorizer {
        UpdaterLeafAuthorizer::with_sink(
            TEST_EPOCH,
            AutonomyPolicySnapshot::test_level(crate::permissions::AutonomyLevel::Standard),
            ConfirmStrategy::AlwaysAllow,
            sink,
            test_clock,
        )
    }

    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<(ExtendedSubtype, serde_json::Value)>>,
        fail: Option<ExtendedSubtype>,
    }

    #[async_trait::async_trait]
    impl UpdaterLeafAuditSink for RecordingSink {
        async fn append_updater_leaf(
            &self,
            subtype: ExtendedSubtype,
            payload: Vec<u8>,
        ) -> Result<()> {
            if self.fail == Some(subtype) {
                anyhow::bail!("injected updater leaf audit failure");
            }
            self.events
                .lock()
                .expect("recording sink lock")
                .push((subtype, serde_json::from_slice(&payload)?));
            Ok(())
        }
    }

    struct BlockingIntentSink {
        events: Mutex<Vec<(ExtendedSubtype, serde_json::Value)>>,
        intent_started: tokio::sync::Notify,
        release_intent: tokio::sync::Notify,
    }

    impl Default for BlockingIntentSink {
        fn default() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
                intent_started: tokio::sync::Notify::new(),
                release_intent: tokio::sync::Notify::new(),
            }
        }
    }

    #[async_trait::async_trait]
    impl UpdaterLeafAuditSink for BlockingIntentSink {
        async fn append_updater_leaf(
            &self,
            subtype: ExtendedSubtype,
            payload: Vec<u8>,
        ) -> Result<()> {
            if subtype == ExtendedSubtype::UpdaterLeafIntent {
                self.intent_started.notify_one();
                self.release_intent.notified().await;
            }
            self.events
                .lock()
                .expect("blocking sink lock")
                .push((subtype, serde_json::from_slice(&payload)?));
            Ok(())
        }
    }

    struct BlockingResultSink {
        events: Mutex<Vec<(ExtendedSubtype, serde_json::Value)>>,
        result_started: tokio::sync::Notify,
        release_result: tokio::sync::Notify,
    }

    impl Default for BlockingResultSink {
        fn default() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
                result_started: tokio::sync::Notify::new(),
                release_result: tokio::sync::Notify::new(),
            }
        }
    }

    #[async_trait::async_trait]
    impl UpdaterLeafAuditSink for BlockingResultSink {
        async fn append_updater_leaf(
            &self,
            subtype: ExtendedSubtype,
            payload: Vec<u8>,
        ) -> Result<()> {
            if subtype == ExtendedSubtype::UpdaterLeafResult {
                self.result_started.notify_one();
                self.release_result.notified().await;
            }
            self.events
                .lock()
                .expect("blocking result sink lock")
                .push((subtype, serde_json::from_slice(&payload)?));
            Ok(())
        }
    }

    async fn wait_for_event_count(
        events: &Mutex<Vec<(ExtendedSubtype, serde_json::Value)>>,
        expected: usize,
    ) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if events.lock().expect("event lock").len() >= expected {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached terminal audit timed out");
    }

    fn metadata_request(id: &str, url: &str) -> UpdaterLeafRequest {
        UpdaterLeafRequest::http(
            "op-self-update",
            id,
            TEST_EPOCH,
            UpdaterAuthorityTask::NeothSelf,
            UpdaterAuthorityLane::NeothSelfProbe,
            UpdaterAuthorityComponent::Neoth,
            UpdaterLeafEffect::ReleaseMetadataFetch,
            UpdaterHttpMethod::Get,
            url,
            &[],
            None,
            128 * 1024,
        )
        .expect("valid metadata request")
    }

    fn metadata_success<T>(value: T) -> UpdaterLeafSuccess<T> {
        UpdaterLeafSuccess::new(value, UpdaterLeafOutcomeCode::Completed)
            .with_observed_artifact(&sha256_hex(&[]), 0)
            .expect("valid metadata observation")
    }

    #[tokio::test]
    async fn intent_failure_prevents_effect() {
        let called = Arc::new(AtomicBool::new(false));
        let authorizer = authorizer(Arc::new(RecordingSink {
            fail: Some(ExtendedSubtype::UpdaterLeafIntent),
            ..RecordingSink::default()
        }));
        let called_in_effect = Arc::clone(&called);
        let result = authorizer
            .execute(
                metadata_request(
                    "req-intent-fail",
                    "https://api.example.test/releases/latest",
                ),
                move |_authority| async move {
                    called_in_effect.store(true, Ordering::SeqCst);
                    Ok(metadata_success(()))
                },
            )
            .await;

        assert!(matches!(
            result,
            Err(UpdaterLeafExecutionError::Audit {
                phase: UpdaterLeafAuditPhase::Intent,
                ..
            })
        ));
        assert!(!called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn permit_rejects_request_mismatch_before_effect() {
        let approved = metadata_request(
            "req-mismatch",
            "https://api.example.test/releases/latest?channel=stable",
        );
        let actual = metadata_request(
            "req-mismatch",
            "https://api.example.test/releases/latest?channel=nightly",
        );
        let permit = UpdaterLeafPermit::for_request(&approved);
        let called = AtomicBool::new(false);
        let result = permit
            .execute(&actual, |_authority| async {
                called.store(true, Ordering::SeqCst);
                Ok(metadata_success(()))
            })
            .await;

        assert!(matches!(
            result,
            Err(UpdaterLeafExecutionError::PermitMismatch)
        ));
        assert!(!called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn permit_and_effect_authority_are_owned_one_shot_values() {
        fn consume_authority(_authority: UpdaterLeafAuthority) {}

        let request =
            metadata_request("req-owned-once", "https://api.example.test/releases/latest");
        let permit = UpdaterLeafPermit::for_request(&request);
        let result = permit
            .execute(&request, |authority| async move {
                // Both this closure and `UpdaterLeafPermit::execute` take their
                // capabilities by value. Neither type implements Clone/Copy;
                // a second invocation is rejected by the Rust type checker.
                consume_authority(authority);
                Ok(metadata_success(()))
            })
            .await;
        assert!(result.expect("matching permit").is_ok());
    }

    #[tokio::test]
    async fn success_and_failure_frames_keep_the_same_request_binding_and_epoch() {
        for (id, should_fail) in [("req-success", false), ("req-failure", true)] {
            let sink = Arc::new(RecordingSink::default());
            let authorizer = authorizer(sink.clone());
            let request = metadata_request(
                id,
                "https://api.example.test/releases/latest?token=must-not-enter-wal",
            );
            let expected_binding = request.binding_sha256().to_string();
            let authority_binding = expected_binding.clone();
            let result = authorizer
                .execute(request, move |authority| async move {
                    assert_eq!(authority.operation_id(), "op-self-update");
                    assert_eq!(authority.request_id(), id);
                    assert_eq!(authority.accepted_epoch(), TEST_EPOCH);
                    assert_eq!(authority.request_binding_sha256(), authority_binding);
                    if should_fail {
                        Err(UpdaterLeafFailure::new(
                            UpdaterLeafFailureKind::Transport,
                            anyhow::anyhow!("secret transport detail"),
                        ))
                    } else {
                        Ok(metadata_success(7_u8))
                    }
                })
                .await;

            assert_eq!(result.is_err(), should_fail);
            let events = sink.events.lock().expect("recorded events");
            assert_eq!(events.len(), 2);
            assert_eq!(events[0].0, ExtendedSubtype::UpdaterLeafIntent);
            assert_eq!(events[1].0, ExtendedSubtype::UpdaterLeafResult);
            for (_, payload) in events.iter() {
                assert_eq!(payload["operation_id"], "op-self-update");
                assert_eq!(payload["request_id"], id);
                assert_eq!(payload["accepted_epoch"], TEST_EPOCH);
                assert_eq!(payload["request_binding_sha256"], expected_binding);
                let serialized = serde_json::to_string(payload).unwrap();
                assert!(!serialized.contains("must-not-enter-wal"));
                assert!(!serialized.contains("secret transport detail"));
            }
            assert_eq!(events[0].1["phase"], "intent");
            assert_eq!(events[1].1["phase"], "result");
            assert_eq!(
                events[1].1["status"],
                if should_fail { "failure" } else { "success" }
            );
            assert!(events[0].1["target"]["query_sha256"].is_string());
            if should_fail {
                assert_eq!(events[1].1["error_kind"], "transport");
                assert!(events[1].1["error_sha256"].is_string());
            }
        }
    }

    #[tokio::test]
    async fn result_audit_failure_propagates_after_effect() {
        let called = Arc::new(AtomicBool::new(false));
        let authorizer = authorizer(Arc::new(RecordingSink {
            fail: Some(ExtendedSubtype::UpdaterLeafResult),
            ..RecordingSink::default()
        }));
        let called_in_effect = Arc::clone(&called);
        let result = authorizer
            .execute(
                metadata_request(
                    "req-result-fail",
                    "https://api.example.test/releases/latest",
                ),
                move |_authority| async move {
                    called_in_effect.store(true, Ordering::SeqCst);
                    Ok(metadata_success(()))
                },
            )
            .await;

        assert!(called.load(Ordering::SeqCst));
        assert!(matches!(
            result,
            Err(UpdaterLeafExecutionError::Audit {
                phase: UpdaterLeafAuditPhase::Result,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn fixed_epoch_and_fail_closed_permission_gate_run_before_intent() {
        let sink = Arc::new(RecordingSink::default());
        let denied = UpdaterLeafAuthorizer::with_sink(
            TEST_EPOCH,
            AutonomyPolicySnapshot::test_level(crate::permissions::AutonomyLevel::Strict),
            ConfirmStrategy::FailClosed,
            sink.clone(),
            test_clock,
        );
        let called = AtomicBool::new(false);
        let result = denied
            .execute(
                metadata_request("req-gate-deny", "https://api.example.test/releases/latest"),
                |_authority| async {
                    called.store(true, Ordering::SeqCst);
                    Ok(metadata_success(()))
                },
            )
            .await;
        assert!(matches!(
            result,
            Err(UpdaterLeafExecutionError::Permission(_))
        ));
        assert!(!called.load(Ordering::SeqCst));
        assert!(sink.events.lock().unwrap().is_empty());

        let wrong_epoch = UpdaterLeafAuthorizer::with_sink(
            TEST_EPOCH + 1,
            AutonomyPolicySnapshot::test_level(crate::permissions::AutonomyLevel::Full),
            ConfirmStrategy::AlwaysAllow,
            sink.clone(),
            test_clock,
        );
        let result = wrong_epoch
            .execute(
                metadata_request(
                    "req-epoch-mismatch",
                    "https://api.example.test/releases/latest",
                ),
                |_authority| async { Ok(metadata_success(())) },
            )
            .await;
        assert!(matches!(
            result,
            Err(UpdaterLeafExecutionError::EpochMismatch { .. })
        ));
        assert!(sink.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn retired_generation_is_typed_and_refused_before_permission_or_intent() {
        let sink = Arc::new(RecordingSink::default());
        let updater_gate = Arc::new(UpdaterLeafGate::new(TEST_EPOCH));
        updater_gate.retire_and_wait();
        let authorizer = UpdaterLeafAuthorizer::with_sink_and_gate(
            TEST_EPOCH,
            updater_gate,
            AutonomyPolicySnapshot::test_level(crate::permissions::AutonomyLevel::Strict),
            ConfirmStrategy::FailClosed,
            sink.clone(),
            test_clock,
        );
        let called = AtomicBool::new(false);
        let error = authorizer
            .execute(
                metadata_request(
                    "req-retired-generation",
                    "https://api.example.test/releases/latest",
                ),
                |_authority| async {
                    called.store(true, Ordering::SeqCst);
                    Ok(metadata_success(()))
                },
            )
            .await
            .unwrap_err();

        let UpdaterLeafExecutionError::GenerationRetired(retired) = &error else {
            panic!("retired generation must win before strict permission: {error:?}");
        };
        assert_eq!(retired.accepted_epoch(), TEST_EPOCH);
        assert!(error.is_generation_retired());
        let wrapped = anyhow::Error::new(error).context("recurring updater pass failed");
        assert!(error_is_generation_retired(&wrapped));
        assert!(!called.load(Ordering::SeqCst));
        assert!(
            sink.events.lock().unwrap().is_empty(),
            "retired generation emitted an updater intent"
        );
    }

    #[tokio::test]
    async fn updater_generation_lease_is_held_through_terminal_wal_append() {
        let sink = Arc::new(BlockingResultSink::default());
        let updater_gate = Arc::new(UpdaterLeafGate::new(TEST_EPOCH));
        let authorizer = Arc::new(UpdaterLeafAuthorizer::with_sink_and_gate(
            TEST_EPOCH,
            Arc::clone(&updater_gate),
            AutonomyPolicySnapshot::test_level(crate::permissions::AutonomyLevel::Standard),
            ConfirmStrategy::AlwaysAllow,
            sink.clone(),
            test_clock,
        ));
        let task_authorizer = Arc::clone(&authorizer);
        let task = tokio::spawn(async move {
            task_authorizer
                .execute(
                    metadata_request(
                        "req-terminal-lease",
                        "https://api.example.test/releases/latest",
                    ),
                    |_authority| async { Ok(metadata_success("done")) },
                )
                .await
        });
        sink.result_started.notified().await;

        let retire_gate = Arc::clone(&updater_gate);
        let retire = std::thread::spawn(move || retire_gate.retire_and_wait());
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while updater_gate.acquire().is_ok() {
            if std::time::Instant::now() >= deadline {
                sink.release_result.notify_one();
                let _ = task.await;
                retire.join().unwrap();
                panic!("updater generation did not close admission");
            }
            std::thread::yield_now();
        }
        assert!(
            !retire.is_finished(),
            "generation drained before terminal WAL acknowledgement"
        );

        sink.release_result.notify_one();
        assert_eq!(task.await.unwrap().unwrap(), "done");
        retire.join().unwrap();
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].0, ExtendedSubtype::UpdaterLeafResult);
    }

    #[tokio::test]
    async fn dropping_effect_future_appends_exactly_one_cancelled_result() {
        let sink = Arc::new(RecordingSink::default());
        let authorizer = Arc::new(authorizer(sink.clone()));
        let effect_started = Arc::new(tokio::sync::Notify::new());
        let effect_started_in_task = Arc::clone(&effect_started);
        let task = tokio::spawn(async move {
            authorizer
                .execute(
                    metadata_request(
                        "req-effect-cancel",
                        "https://api.example.test/releases/latest",
                    ),
                    move |_authority| async move {
                        effect_started_in_task.notify_one();
                        pending::<std::result::Result<UpdaterLeafSuccess<()>, UpdaterLeafFailure>>()
                            .await
                    },
                )
                .await
        });
        effect_started.notified().await;
        task.abort();
        let _ = task.await;
        wait_for_event_count(&sink.events, 2).await;

        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].0, ExtendedSubtype::UpdaterLeafIntent);
        assert_eq!(events[1].0, ExtendedSubtype::UpdaterLeafResult);
        assert_eq!(events[1].1["request_id"], "req-effect-cancel");
        assert_eq!(events[1].1["status"], "failure");
        assert_eq!(events[1].1["error_kind"], "cancelled");
    }

    #[tokio::test]
    async fn dropping_while_intent_pending_preserves_ack_then_closes_it() {
        let sink = Arc::new(BlockingIntentSink::default());
        let authorizer = Arc::new(authorizer(sink.clone()));
        let task = tokio::spawn(async move {
            authorizer
                .execute(
                    metadata_request(
                        "req-intent-cancel",
                        "https://api.example.test/releases/latest",
                    ),
                    |_authority| async { Ok(metadata_success(())) },
                )
                .await
        });
        sink.intent_started.notified().await;
        task.abort();
        let _ = task.await;
        sink.release_intent.notify_one();
        wait_for_event_count(&sink.events, 2).await;

        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].0, ExtendedSubtype::UpdaterLeafIntent);
        assert_eq!(events[1].0, ExtendedSubtype::UpdaterLeafResult);
        assert_eq!(events[1].1["request_id"], "req-intent-cancel");
        assert_eq!(events[1].1["error_kind"], "cancelled");
    }

    #[tokio::test]
    async fn panic_is_converted_to_one_durable_terminal_failure() {
        let sink = Arc::new(RecordingSink::default());
        let authorizer = authorizer(sink.clone());
        let result: std::result::Result<(), UpdaterLeafExecutionError> = authorizer
            .execute(
                metadata_request("req-panic", "https://api.example.test/releases/latest"),
                |_authority| async move {
                    panic!("sensitive panic payload must not enter the WAL");
                    #[allow(unreachable_code)]
                    Ok(metadata_success(()))
                },
            )
            .await;

        assert!(matches!(
            result,
            Err(UpdaterLeafExecutionError::Effect { kind: "panic", .. })
        ));
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].0, ExtendedSubtype::UpdaterLeafIntent);
        assert_eq!(events[1].0, ExtendedSubtype::UpdaterLeafResult);
        assert_eq!(events[1].1["status"], "failure");
        assert_eq!(events[1].1["error_kind"], "panic");
        assert!(
            !serde_json::to_string(&events[1].1)
                .unwrap()
                .contains("sensitive panic payload")
        );
    }

    #[tokio::test]
    async fn concrete_http_leaf_rejects_arguments_outside_the_admitted_descriptor() {
        let sink = Arc::new(RecordingSink::default());
        let authorizer = authorizer(sink.clone());
        let called = Arc::new(AtomicBool::new(false));
        let called_in_effect = Arc::clone(&called);
        let result: std::result::Result<(), UpdaterLeafExecutionError> = authorizer
            .execute_http(
                metadata_request(
                    "req-http-binding",
                    "https://api.example.test/releases/latest?channel=stable",
                ),
                UpdaterLeafEffect::ReleaseMetadataFetch,
                UpdaterHttpMethod::Get,
                "https://api.example.test/releases/latest?channel=nightly",
                &[],
                None,
                128 * 1024,
                move || {
                    called_in_effect.store(true, Ordering::SeqCst);
                    async move { Ok(metadata_success(())) }
                },
            )
            .await;

        assert!(matches!(
            result,
            Err(UpdaterLeafExecutionError::Effect {
                kind: "protocol",
                ..
            })
        ));
        assert!(!called.load(Ordering::SeqCst));
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].1["error_kind"], "protocol");
    }

    #[tokio::test]
    async fn typed_http_executor_polls_only_an_exactly_bound_sink_future() {
        let sink = Arc::new(RecordingSink::default());
        let authorizer = authorizer(sink.clone());
        let called = Arc::new(AtomicBool::new(false));
        let called_in_effect = Arc::clone(&called);
        let url = "https://api.example.test/releases/latest?channel=stable";
        let result: std::result::Result<&'static str, UpdaterLeafExecutionError> = authorizer
            .execute_http(
                metadata_request("req-http-exact", url),
                UpdaterLeafEffect::ReleaseMetadataFetch,
                UpdaterHttpMethod::Get,
                url,
                &[],
                None,
                128 * 1024,
                move || async move {
                    called_in_effect.store(true, Ordering::SeqCst);
                    Ok(metadata_success("executed"))
                },
            )
            .await;

        assert_eq!(result.unwrap(), "executed");
        assert!(called.load(Ordering::SeqCst));
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].1["status"], "success");
    }

    #[tokio::test]
    async fn concrete_stage_leaf_rejects_a_different_destination_before_polling() {
        let sink = Arc::new(RecordingSink::default());
        let authorizer = authorizer(sink.clone());
        let called = Arc::new(AtomicBool::new(false));
        let called_in_effect = Arc::clone(&called);
        let home = std::env::temp_dir().join("neoth-authority-stage-home");
        let admitted_destination = home.join("staged");
        let different_destination = home.join("other-stage");
        let content = b"verified-stage-transaction";
        let content_sha256 = sha256_hex(content);
        let request = UpdaterLeafRequest::verified_stage(
            "op-self-stage",
            "req-stage-binding",
            TEST_EPOCH,
            UpdaterAuthorityTask::NeothSelf,
            UpdaterAuthorityLane::SelfStage,
            UpdaterAuthorityComponent::Neoth,
            UpdaterLeafEffect::VerifiedStageWrite,
            &home,
            &admitted_destination,
            &content_sha256,
            content.len() as u64,
        )
        .expect("valid stage request");
        let result: std::result::Result<UpdaterStageCompletion<()>, UpdaterLeafExecutionError> =
            authorizer
                .execute_stage(
                    request,
                    &home,
                    &different_destination,
                    &content_sha256,
                    content.len() as u64,
                    move || async move {
                        called_in_effect.store(true, Ordering::SeqCst);
                        UpdaterLeafSuccess::new((), UpdaterLeafOutcomeCode::Prepared)
                            .with_observed_artifact(&sha256_hex(content), content.len() as u64)
                            .map_err(|source| {
                                UpdaterLeafFailure::new(UpdaterLeafFailureKind::Protocol, source)
                            })
                    },
                )
                .await;

        assert!(matches!(
            result,
            Err(UpdaterLeafExecutionError::Effect {
                kind: "protocol",
                ..
            })
        ));
        assert!(!called.load(Ordering::SeqCst));
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].1["error_kind"], "protocol");
    }

    #[tokio::test]
    async fn verified_stage_terminal_records_prepared_before_external_publication() {
        let sink = Arc::new(RecordingSink::default());
        let authorizer = authorizer(sink.clone());
        let home = std::env::temp_dir().join("neoth-authority-prepared-home");
        let destination = home.join("stage");
        let content = b"prepared-stage-transaction";
        let content_sha256 = sha256_hex(content);
        let request = UpdaterLeafRequest::verified_stage(
            "op-self-stage",
            "req-stage-prepared",
            TEST_EPOCH,
            UpdaterAuthorityTask::NeothSelf,
            UpdaterAuthorityLane::SelfStage,
            UpdaterAuthorityComponent::Neoth,
            UpdaterLeafEffect::VerifiedStageWrite,
            &home,
            &destination,
            &content_sha256,
            content.len() as u64,
        )
        .unwrap();
        let observed_sha256 = content_sha256.clone();
        let result = authorizer
            .execute_stage(
                request,
                &home,
                &destination,
                &content_sha256,
                content.len() as u64,
                move || async move {
                    UpdaterLeafSuccess::new("prepared", UpdaterLeafOutcomeCode::Prepared)
                        .with_observed_artifact(&observed_sha256, content.len() as u64)
                        .map_err(|source| {
                            UpdaterLeafFailure::new(UpdaterLeafFailureKind::Protocol, source)
                        })
                },
            )
            .await;

        assert_eq!(
            result.unwrap().publish_with(|prepared| prepared),
            "prepared"
        );
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].1["status"], "success");
        assert_eq!(events[1].1["outcome"], "prepared");
    }

    #[tokio::test]
    async fn verified_stage_completion_holds_generation_lease_through_publication() {
        let sink = Arc::new(RecordingSink::default());
        let updater_gate = Arc::new(UpdaterLeafGate::new(TEST_EPOCH));
        let authorizer = UpdaterLeafAuthorizer::with_sink_and_gate(
            TEST_EPOCH,
            Arc::clone(&updater_gate),
            AutonomyPolicySnapshot::test_level(crate::permissions::AutonomyLevel::Standard),
            ConfirmStrategy::AlwaysAllow,
            sink,
            test_clock,
        );
        let home = std::env::temp_dir().join("neoth-authority-publish-lease-home");
        let destination = home.join("stage");
        let content = b"prepared-stage-publication";
        let content_sha256 = sha256_hex(content);
        let request = UpdaterLeafRequest::verified_stage(
            "op-self-stage",
            "req-stage-publish-lease",
            TEST_EPOCH,
            UpdaterAuthorityTask::NeothSelf,
            UpdaterAuthorityLane::SelfStage,
            UpdaterAuthorityComponent::Neoth,
            UpdaterLeafEffect::VerifiedStageWrite,
            &home,
            &destination,
            &content_sha256,
            content.len() as u64,
        )
        .unwrap();
        let observed_sha256 = content_sha256.clone();
        let completion = authorizer
            .execute_stage(
                request,
                &home,
                &destination,
                &content_sha256,
                content.len() as u64,
                move || async move {
                    UpdaterLeafSuccess::new("prepared", UpdaterLeafOutcomeCode::Prepared)
                        .with_observed_artifact(&observed_sha256, content.len() as u64)
                        .map_err(|source| {
                            UpdaterLeafFailure::new(UpdaterLeafFailureKind::Protocol, source)
                        })
                },
            )
            .await
            .unwrap();

        let retire_gate = Arc::clone(&updater_gate);
        let retire = std::thread::spawn(move || retire_gate.retire_and_wait());
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while updater_gate.acquire().is_ok() {
            if std::time::Instant::now() >= deadline {
                panic!("updater generation did not close admission");
            }
            std::thread::yield_now();
        }

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let publish = tokio::task::spawn_blocking(move || {
            completion.publish_with(|prepared| {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                prepared
            })
        });
        started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("publication closure did not start");
        assert!(
            !retire.is_finished(),
            "generation drained while the publication closure still held authority"
        );

        release_tx.send(()).unwrap();
        assert_eq!(publish.await.unwrap(), "prepared");
        retire.join().unwrap();
    }

    #[tokio::test]
    async fn effect_rejects_a_semantically_impossible_success_outcome() {
        let sink = Arc::new(RecordingSink::default());
        let authorizer = authorizer(sink.clone());
        let result: std::result::Result<(), UpdaterLeafExecutionError> = authorizer
            .execute(
                metadata_request(
                    "req-outcome-binding",
                    "https://api.example.test/releases/latest",
                ),
                |_authority| async move {
                    UpdaterLeafSuccess::new((), UpdaterLeafOutcomeCode::Installed)
                        .with_observed_artifact(&sha256_hex(&[]), 0)
                        .map_err(|source| {
                            UpdaterLeafFailure::new(UpdaterLeafFailureKind::Protocol, source)
                        })
                },
            )
            .await;

        assert!(matches!(
            result,
            Err(UpdaterLeafExecutionError::Effect {
                kind: "protocol",
                ..
            })
        ));
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].1["error_kind"], "protocol");
    }

    #[test]
    fn constructor_enforces_task_lane_effect_target_and_secret_hygiene() {
        assert!(
            UpdaterLeafRequest::http(
                "op-invalid",
                "plain-http",
                TEST_EPOCH,
                UpdaterAuthorityTask::NeothSelf,
                UpdaterAuthorityLane::NeothSelfProbe,
                UpdaterAuthorityComponent::Neoth,
                UpdaterLeafEffect::ReleaseMetadataFetch,
                UpdaterHttpMethod::Get,
                "http://api.example.test/releases",
                &[],
                None,
                1024,
            )
            .is_err()
        );
        assert!(
            UpdaterLeafRequest::http(
                "op-invalid",
                "bad-credentials",
                TEST_EPOCH,
                UpdaterAuthorityTask::NeothSelf,
                UpdaterAuthorityLane::NeothSelfProbe,
                UpdaterAuthorityComponent::Neoth,
                UpdaterLeafEffect::ReleaseMetadataFetch,
                UpdaterHttpMethod::Get,
                "https://user:password@example.test/releases",
                &[],
                None,
                1024,
            )
            .is_err()
        );
        assert!(
            UpdaterLeafRequest::http(
                "unsafe?operation",
                "bad-operation",
                TEST_EPOCH,
                UpdaterAuthorityTask::NeothSelf,
                UpdaterAuthorityLane::NeothSelfProbe,
                UpdaterAuthorityComponent::Neoth,
                UpdaterLeafEffect::ReleaseMetadataFetch,
                UpdaterHttpMethod::Get,
                "https://example.test/releases",
                &[],
                None,
                1024,
            )
            .is_err()
        );
        assert!(
            UpdaterLeafRequest::http(
                "op-invalid",
                "bad-method",
                TEST_EPOCH,
                UpdaterAuthorityTask::NeothSelf,
                UpdaterAuthorityLane::NeothSelfProbe,
                UpdaterAuthorityComponent::Neoth,
                UpdaterLeafEffect::ReleaseMetadataFetch,
                UpdaterHttpMethod::Post,
                "https://example.test/releases",
                b"{}",
                None,
                1024,
            )
            .is_err()
        );
        assert!(
            UpdaterLeafRequest::http(
                "op-invalid",
                "bad-lane",
                TEST_EPOCH,
                UpdaterAuthorityTask::NeothSelf,
                UpdaterAuthorityLane::CliVersionProbe,
                UpdaterAuthorityComponent::Neoth,
                UpdaterLeafEffect::ReleaseMetadataFetch,
                UpdaterHttpMethod::Get,
                "https://example.test/releases",
                &[],
                None,
                1024,
            )
            .is_err()
        );
    }

    #[test]
    fn verified_stage_accepts_only_clean_neoth_home_descendants() {
        let home = if cfg!(windows) {
            PathBuf::from(r"C:\Users\operator\.neoth")
        } else {
            PathBuf::from("/home/operator/.neoth")
        };
        let valid = home.join("updates").join("staged").join("neoth");
        let sibling = home
            .parent()
            .expect("home parent")
            .join(".neoth-evil")
            .join("staged");
        let outside = if cfg!(windows) {
            PathBuf::from(r"C:\Temp\neoth-stage")
        } else {
            PathBuf::from("/tmp/neoth-stage")
        };
        let content_sha256 = sha256_hex(b"verified artifact");
        let build = |id: &str, destination: &Path| {
            UpdaterLeafRequest::verified_stage(
                "op-self-stage",
                id,
                TEST_EPOCH,
                UpdaterAuthorityTask::NeothSelf,
                UpdaterAuthorityLane::SelfStage,
                UpdaterAuthorityComponent::Neoth,
                UpdaterLeafEffect::VerifiedStageWrite,
                &home,
                destination,
                &content_sha256,
                17,
            )
        };

        assert!(build("stage-valid", &valid).is_ok());
        assert!(build("stage-sibling", &sibling).is_err());
        assert!(build("stage-outside", &outside).is_err());
        assert!(
            build(
                "stage-parent",
                &home.join("updates").join("..").join("escape")
            )
            .is_err()
        );
    }

    #[test]
    fn verified_stage_terminal_matrix_accepts_only_prepared() {
        let home = if cfg!(windows) {
            PathBuf::from(r"C:\Users\operator\.neoth")
        } else {
            PathBuf::from("/home/operator/.neoth")
        };
        let destination = home.join("updates").join("staged");
        let content = b"prepared but not yet published";
        let content_sha256 = sha256_hex(content);
        let request = UpdaterLeafRequest::verified_stage(
            "op-stage-matrix",
            "req-stage-matrix",
            TEST_EPOCH,
            UpdaterAuthorityTask::NeothSelf,
            UpdaterAuthorityLane::SelfStage,
            UpdaterAuthorityComponent::Neoth,
            UpdaterLeafEffect::VerifiedStageWrite,
            &home,
            &destination,
            &content_sha256,
            content.len() as u64,
        )
        .unwrap();
        let observed = |outcome| {
            UpdaterLeafSuccess::new((), outcome)
                .with_observed_artifact(&content_sha256, content.len() as u64)
                .unwrap()
        };

        assert_eq!(UpdaterLeafOutcomeCode::Prepared.as_str(), "prepared");
        assert!(
            request
                .validate_success(&observed(UpdaterLeafOutcomeCode::Prepared))
                .is_ok()
        );
        assert!(
            request
                .validate_success(&observed(UpdaterLeafOutcomeCode::Staged))
                .is_err()
        );
        assert!(
            !UpdaterLeafEffect::VerifiedStageWrite.allows_outcome(UpdaterLeafOutcomeCode::Staged)
        );
    }
}
