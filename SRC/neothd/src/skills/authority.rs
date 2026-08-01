//! Persistent activation authority for installed Skills.
//!
//! Package integrity and activation authority are separate contracts. The
//! installer proves which package generation was published; this module proves
//! whether that exact generation may participate in runtime routing.
//!
//! Authority lives outside `<home>/skills/<id>`:
//!
//! ```text
//! <home>/skill-authority/
//!   records/<skill-id>/record-<sha256>.json
//!   current/<skill-id>.json      # authenticated current-anchor commit marker
//!   authority.key                # private authority identity, independent of WAL rotation
//!   authority.lock               # cross-process publication/validation lock
//! ```
//!
//! A dedicated private authority key authenticates both files and an
//! independent monotonic authority-head event under distinct protocol
//! domains. WAL HMAC rotation therefore cannot invalidate authority and a
//! retired WAL key never remains an authority signer. Runtime validation only
//! loads the existing authority key; first publication creates it.
//! Publication is ordered record, authority WAL head, then current anchor; the
//! final anchor rename is the sole activation commit point, while the WAL head
//! prevents a retained old anchor plus deleted decision tail from reactivating.
//! A rollback of the entire instance home, including a valid older WAL prefix,
//! is outside this local trust boundary and requires an external monotonic
//! witness (for example TPM-backed state or a remote append-only witness).

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _};
#[cfg(unix)]
use cap_std::fs::DirBuilder;
use cap_std::fs::{Dir, OpenOptions};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::schema::SkillManifest;
use super::store::{
    BoundDirectory, cap_metadata_is_link_like, open_bound_directory,
    open_bound_directory_from_trusted_anchor, open_real_child_dir, remove_child_file, rename_child,
    sync_parent_directory,
};
use crate::config::SkillVisibility;
use crate::providers::effort_override::EffortBudget;

pub const SKILL_AUTHORITY_RECORD_VERSION: u32 = 1;
pub const SKILL_CURRENT_ANCHOR_VERSION: u32 = 1;

const AUTHORITY_ROOT_NAME: &str = "skill-authority";
const AUTHORITY_RECORDS_NAME: &str = "records";
const AUTHORITY_CURRENT_NAME: &str = "current";
const AUTHORITY_LOCK_NAME: &str = "authority.lock";
const AUTHORITY_KEY_NAME: &str = "authority.key";
const AUTHORITY_RECORD_PREFIX: &str = "record-";
const AUTHORITY_JSON_SUFFIX: &str = ".json";
const AUTHORITY_STAGE_PREFIX: &str = ".stage-";
const WAL_DIRECTORY_NAME: &str = "wal";
#[cfg(test)]
const WAL_HMAC_KEY_NAME: &str = "hmac.key";

const RECORD_HMAC_DOMAIN: &[u8] = b"neoth.skill.authority.record.v1";
const ANCHOR_HMAC_DOMAIN: &[u8] = b"neoth.skill.authority.current-anchor.v1";
const AUTHORITY_WAL_HMAC_DOMAIN: &[u8] = b"neoth:skill-authority:wal-head:v1\0";

const MAX_AUTHORITY_RECORD_BYTES: usize = 64 * 1024;
const MAX_CURRENT_ANCHOR_BYTES: usize = 8 * 1024;
const MAX_AUTHORITY_KEY_BYTES: usize = 4 * 1024;
const MAX_INSTALLED_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_AUTHORITY_RECORDS_PER_SKILL: usize = 4_096;
const MAX_AUTHORITY_ROOT_ENTRIES: usize = 8;
const MAX_EFFECTIVE_TOOLS: usize = 256;
const MAX_TOOL_NAME_BYTES: usize = 256;
const MAX_BEHAVIOR_STRING_BYTES: usize = 4_096;
const MAX_DECISION_REASON_BYTES: usize = 512;
const DECISION_ID_HEX_BYTES: usize = 16;

type AuthorityMac = Hmac<Sha256>;

#[cfg(test)]
thread_local! {
    static TEST_FAIL_RECORD_SYNC_AFTER_RENAME: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    static TEST_FAIL_ANCHOR_BEFORE_RENAME: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    static TEST_FAIL_ANCHOR_SYNC_AFTER_RENAME: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    static TEST_FAIL_ANCHOR_READBACK_AFTER_RENAME: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

/// Origin of the package bytes. This is deliberately distinct from who made
/// the later activation decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillProvenance {
    Bundled,
    LocalInstall,
    CommunityImport,
    ProactiveAccept,
    ProactiveCurator,
    Teacher,
    SelfImprove,
    LegacyUnverified,
}

/// Surface or explicit policy that made the activation decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillAuthorityDecisionSource {
    OperatorCli,
    OperatorGui,
    OperatorBuddy,
    OperatorFullAutoPolicy,
    AuthenticatedProposal,
    Migration,
    SecurityRevocation,
    Recovery,
}

/// Current decision for the exact package generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillAuthorityState {
    Active,
    Inactive,
    Revoked,
}

/// Every manifest-derived claim that changes runtime behavior after a Skill
/// has matched. The full manifest digest and package generation bind all other
/// bytes; this projection makes the operator-visible grant explicit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillBehaviorClaimsV1 {
    /// Exact effective MCP allowlist. Empty is an explicit deny-all grant.
    pub effective_tools: Vec<String>,
    pub effective_enabled: bool,
    pub skills_policy_sha256: String,
    pub system_prompt_sha256: String,
    pub trigger_keywords_sha256: String,
    pub paths_sha256: String,
    pub modes_sha256: String,
    pub delegate_to: Option<String>,
    pub model: Option<String>,
    pub effort: Option<EffortBudget>,
    pub loop_trigger: bool,
    pub visibility: SkillVisibility,
    pub source: Option<String>,
}

impl SkillBehaviorClaimsV1 {
    /// Project the effective manifest after operator policy has been applied.
    pub fn from_effective_manifest(
        manifest: &SkillManifest,
        skills_policy_sha256: impl Into<String>,
    ) -> Result<Self> {
        let mut claims = Self {
            effective_tools: manifest.tool_allowlist.clone(),
            effective_enabled: manifest.enabled,
            skills_policy_sha256: skills_policy_sha256.into(),
            system_prompt_sha256: sha256_hex(manifest.system_prompt.as_bytes()),
            trigger_keywords_sha256: canonical_value_sha256(&manifest.trigger_keywords)
                .context("hash Skill trigger routing claims")?,
            paths_sha256: canonical_value_sha256(&manifest.paths)
                .context("hash Skill path routing claims")?,
            modes_sha256: canonical_value_sha256(&manifest.modes)
                .context("hash Skill mode routing claims")?,
            delegate_to: manifest.delegate_to.clone(),
            model: manifest.model.clone(),
            effort: manifest.effort,
            loop_trigger: manifest.loop_trigger,
            visibility: manifest.visibility,
            source: manifest.source.clone(),
        };
        claims.canonicalize();
        claims.validate()?;
        Ok(claims)
    }

    fn canonicalize(&mut self) {
        self.effective_tools.sort();
        self.effective_tools.dedup();
    }

    fn validate(&self) -> Result<()> {
        validate_sha256(&self.skills_policy_sha256, "accepted Skill policy claim")?;
        validate_sha256(&self.system_prompt_sha256, "Skill system-prompt claim")?;
        validate_sha256(
            &self.trigger_keywords_sha256,
            "Skill trigger-keywords claim",
        )?;
        validate_sha256(&self.paths_sha256, "Skill path-routing claim")?;
        validate_sha256(&self.modes_sha256, "Skill mode-routing claim")?;
        if self.effective_tools.len() > MAX_EFFECTIVE_TOOLS {
            anyhow::bail!(
                "effective Skill tool grant exceeds the {MAX_EFFECTIVE_TOOLS}-entry limit"
            );
        }
        let mut previous: Option<&str> = None;
        for tool in &self.effective_tools {
            validate_behavior_string(tool, MAX_TOOL_NAME_BYTES, "effective tool")?;
            if previous.is_some_and(|known| known >= tool.as_str()) {
                anyhow::bail!("effective Skill tools must be strictly sorted and unique");
            }
            previous = Some(tool);
        }
        validate_optional_behavior_string(&self.delegate_to, "delegation")?;
        validate_optional_behavior_string(&self.model, "model override")?;
        validate_optional_behavior_string(&self.source, "upstream source")?;
        Ok(())
    }
}

/// Canonical, immutable activation decision for one exact package generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillAuthorityRecordV1 {
    pub version: u32,
    pub skill_id: String,
    pub package_generation_sha256: String,
    pub manifest_sha256: String,
    pub install_incarnation: u64,
    pub install_terminal_receipt_sha256: String,
    pub authority_sequence: u64,
    pub previous_record_sha256: Option<String>,
    pub provenance: SkillProvenance,
    pub decision_source: SkillAuthorityDecisionSource,
    pub state: SkillAuthorityState,
    /// Required for Inactive/Revoked; forbidden for Active.
    pub decision_reason: Option<String>,
    pub claims: SkillBehaviorClaimsV1,
    /// Random 128-bit identifier, encoded as lowercase hex.
    pub decision_id: String,
    pub decided_at_unix_ms: u64,
}

impl SkillAuthorityRecordV1 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        skill_id: impl Into<String>,
        package_generation_sha256: impl Into<String>,
        manifest_sha256: impl Into<String>,
        install_incarnation: u64,
        install_terminal_receipt_sha256: impl Into<String>,
        provenance: SkillProvenance,
        decision_source: SkillAuthorityDecisionSource,
        state: SkillAuthorityState,
        decision_reason: Option<String>,
        mut claims: SkillBehaviorClaimsV1,
    ) -> Result<Self> {
        let mut nonce = [0_u8; DECISION_ID_HEX_BYTES];
        getrandom::getrandom(&mut nonce).context("generate Skill authority decision id")?;
        let decided_at_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock predates Unix epoch")?
            .as_millis()
            .try_into()
            .context("Skill authority decision timestamp overflow")?;
        claims.canonicalize();
        let record = Self {
            version: SKILL_AUTHORITY_RECORD_VERSION,
            skill_id: skill_id.into(),
            package_generation_sha256: package_generation_sha256.into(),
            manifest_sha256: manifest_sha256.into(),
            install_incarnation,
            install_terminal_receipt_sha256: install_terminal_receipt_sha256.into(),
            authority_sequence: 1,
            previous_record_sha256: None,
            provenance,
            decision_source,
            state,
            decision_reason,
            claims,
            decision_id: hex::encode(nonce),
            decided_at_unix_ms,
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<()> {
        if self.version != SKILL_AUTHORITY_RECORD_VERSION {
            anyhow::bail!("unsupported Skill authority record version");
        }
        super::creator::validate_skill_id(&self.skill_id).context("invalid Skill authority id")?;
        validate_sha256(&self.package_generation_sha256, "Skill package generation")?;
        validate_sha256(&self.manifest_sha256, "Skill manifest digest")?;
        if self.install_incarnation == 0 {
            anyhow::bail!("Skill install incarnation must be non-zero");
        }
        validate_sha256(
            &self.install_terminal_receipt_sha256,
            "Skill install terminal receipt",
        )?;
        if self.authority_sequence == 0 {
            anyhow::bail!("Skill authority sequence must be non-zero");
        }
        match (
            self.authority_sequence,
            self.previous_record_sha256.as_deref(),
        ) {
            (1, None) => {}
            (1, Some(_)) => {
                anyhow::bail!("first Skill authority record must not have a predecessor")
            }
            (_, Some(previous)) => {
                validate_sha256(previous, "previous Skill authority record")?;
            }
            (_, None) => {
                anyhow::bail!("non-first Skill authority record requires a predecessor")
            }
        }
        validate_lower_hex(
            &self.decision_id,
            DECISION_ID_HEX_BYTES * 2,
            "Skill authority decision id",
        )?;
        if self.decided_at_unix_ms == 0 {
            anyhow::bail!("Skill authority decision timestamp must be non-zero");
        }
        match self.state {
            SkillAuthorityState::Active if self.decision_reason.is_some() => {
                anyhow::bail!("active Skill authority must not carry a denial reason");
            }
            SkillAuthorityState::Inactive | SkillAuthorityState::Revoked => {
                let reason = self
                    .decision_reason
                    .as_deref()
                    .context("inactive or revoked Skill authority requires a reason")?;
                validate_behavior_string(reason, MAX_DECISION_REASON_BYTES, "decision reason")?;
            }
            SkillAuthorityState::Active => {}
        }
        self.claims.validate()
    }
}

/// Operator or policy decision applied to the exact installed package snapshot
/// resolved inside the activation or reduction publication transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkillAuthorityDecision {
    pub decision_source: SkillAuthorityDecisionSource,
    pub state: SkillAuthorityState,
    pub decision_reason: Option<String>,
    force_new_revision: bool,
}

impl SkillAuthorityDecision {
    pub fn new(
        decision_source: SkillAuthorityDecisionSource,
        state: SkillAuthorityState,
        decision_reason: Option<String>,
    ) -> Result<Self> {
        match state {
            SkillAuthorityState::Active if decision_reason.is_some() => {
                anyhow::bail!("active Skill authority must not carry a denial reason");
            }
            SkillAuthorityState::Inactive | SkillAuthorityState::Revoked => {
                let reason = decision_reason
                    .as_deref()
                    .context("inactive or revoked Skill authority requires a reason")?;
                validate_behavior_string(reason, MAX_DECISION_REASON_BYTES, "decision reason")?;
            }
            SkillAuthorityState::Active => {}
        }
        Ok(Self {
            decision_source,
            state,
            decision_reason,
            force_new_revision: false,
        })
    }

    /// Force a new immutable audit revision even when the effective decision
    /// is identical to the current head. Normal retries remain idempotent.
    pub fn requiring_new_revision(mut self) -> Self {
        self.force_new_revision = true;
        self
    }
}

/// Expected current bytes and effective behavior at the runtime admission
/// boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SkillAuthorityExpectation {
    skill_id: String,
    package_generation_sha256: String,
    manifest_sha256: String,
    install_incarnation: u64,
    install_terminal_receipt_sha256: String,
    provenance: SkillProvenance,
    claims: SkillBehaviorClaimsV1,
}

impl SkillAuthorityExpectation {
    #[cfg(test)]
    pub fn from_record(record: &SkillAuthorityRecordV1) -> Self {
        Self {
            skill_id: record.skill_id.clone(),
            package_generation_sha256: record.package_generation_sha256.clone(),
            manifest_sha256: record.manifest_sha256.clone(),
            install_incarnation: record.install_incarnation,
            install_terminal_receipt_sha256: record.install_terminal_receipt_sha256.clone(),
            provenance: record.provenance,
            claims: record.claims.clone(),
        }
    }

    fn validate(&self) -> Result<()> {
        super::creator::validate_skill_id(&self.skill_id)
            .context("invalid expected Skill authority id")?;
        validate_sha256(
            &self.package_generation_sha256,
            "expected Skill package generation",
        )?;
        validate_sha256(&self.manifest_sha256, "expected Skill manifest digest")?;
        if self.install_incarnation == 0 {
            anyhow::bail!("expected Skill install incarnation must be non-zero");
        }
        validate_sha256(
            &self.install_terminal_receipt_sha256,
            "expected Skill install terminal receipt",
        )?;
        self.claims.validate()
    }
}

/// A capability-bound installed package snapshot held under the shared Skill
/// mutation lock. Keeping the handles and lock alive prevents a cooperating
/// installer from replacing the package between hashing and authority
/// validation/publication.
struct BoundInstalledAuthoritySnapshot {
    expectation: SkillAuthorityExpectation,
    effective_enabled: bool,
    effective_manifest: SkillManifest,
    _mutation_guard: super::installer::SkillMutationGuard,
    _skill_directory: Dir,
    _skills_root: BoundDirectory,
}

struct InstalledAuthoritySnapshot {
    expectation: SkillAuthorityExpectation,
    effective_enabled: bool,
    effective_manifest: SkillManifest,
    skill_directory: Dir,
}

/// Sealed projection of one config generation already accepted by the reload
/// controller. Callers cannot manufacture this from a candidate
/// `FreedomConfig`.
#[derive(Clone, Debug)]
struct AcceptedSkillPolicySnapshot {
    skills: crate::config::SkillsConfig,
    config_epoch: u64,
}

impl AcceptedSkillPolicySnapshot {
    fn from_accepted(snapshot: &crate::config::reload::AcceptedConfigSnapshot) -> Result<Self> {
        let config = snapshot.config();
        Ok(Self {
            skills: config.skills.clone(),
            config_epoch: snapshot.epoch(),
        })
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct EffectiveSkillPolicyBindingV1 {
    version: u32,
    skill_id: String,
    disabled_for_eval_sessions: bool,
    eval_session_active: bool,
    pinned_content_hash: Option<String>,
    always_embed_route: bool,
    force_disabled: bool,
    force_enabled: bool,
    visibility_override: Option<SkillVisibility>,
}

/// Exact, non-forgeable receipt returned after the immutable record and
/// current anchor commit attempt. `durability` distinguishes a fully synced
/// commit from a visible commit whose final directory sync was not confirmed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SkillAuthorityReceipt {
    skill_id: String,
    package_generation_sha256: String,
    manifest_sha256: String,
    install_incarnation: u64,
    install_terminal_receipt_sha256: String,
    authority_sequence: u64,
    record_sha256: String,
    current_anchor_sha256: String,
    decision_id: String,
    provenance: SkillProvenance,
    decision_source: SkillAuthorityDecisionSource,
    state: SkillAuthorityState,
    claims: SkillBehaviorClaimsV1,
    durability: SkillAuthorityDurability,
    accepted_policy_current_at_return: bool,
}

/// Authenticated readback of the currently committed authority head. Unlike
/// runtime admission this view is policy-independent: it can prove an
/// `Inactive`/`Revoked` decision even after `freedom.yaml` disables the Skill.
/// Callers still use [`validate_installed_authority`] before executing an
/// `Active` package.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SkillAuthorityCurrentStatus {
    record: SkillAuthorityRecordV1,
    record_sha256: String,
    current_anchor_sha256: String,
    authority_wal_receipt_sha256: String,
}

/// Operator consent binding for an installed-Skill authority mutation. The
/// package generation alone is insufficient because an identical-byte
/// uninstall/reinstall mints a new incarnation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InstalledSkillDecisionExpectation {
    package_generation_sha256: String,
    install_incarnation: u64,
    install_terminal_receipt_sha256: String,
}

impl InstalledSkillDecisionExpectation {
    pub(crate) fn new(
        package_generation_sha256: String,
        install_incarnation: u64,
        install_terminal_receipt_sha256: String,
    ) -> Result<Self> {
        validate_sha256(
            &package_generation_sha256,
            "expected installed-Skill package generation",
        )?;
        anyhow::ensure!(
            install_incarnation > 0,
            "expected installed-Skill incarnation must be non-zero"
        );
        validate_sha256(
            &install_terminal_receipt_sha256,
            "expected installed-Skill terminal receipt",
        )?;
        Ok(Self {
            package_generation_sha256,
            install_incarnation,
            install_terminal_receipt_sha256,
        })
    }
}

impl SkillAuthorityCurrentStatus {
    pub fn record(&self) -> &SkillAuthorityRecordV1 {
        &self.record
    }

    pub fn record_sha256(&self) -> &str {
        &self.record_sha256
    }

    pub fn current_anchor_sha256(&self) -> &str {
        &self.current_anchor_sha256
    }

    pub fn authority_wal_receipt_sha256(&self) -> &str {
        &self.authority_wal_receipt_sha256
    }
}

/// Publication cannot honestly return a plain error after the anchor rename:
/// the decision may already be visible even if the following directory sync
/// fails. This typed state makes that committed-but-not-durable outcome
/// explicit to callers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillAuthorityDurability {
    Confirmed,
    /// The exact bytes were read back from the committed object, but this
    /// platform cannot confirm parent-directory power-loss durability.
    NamespaceDurabilityUnsupported,
    Unconfirmed,
    StateUncertain,
}

impl SkillAuthorityDurability {
    /// The committed object was read back exactly and no sync operation
    /// failed. This is sufficient for live runtime admission, while the enum
    /// still preserves whether namespace power-loss durability was provable.
    pub const fn is_live_verified(self) -> bool {
        matches!(self, Self::Confirmed | Self::NamespaceDurabilityUnsupported)
    }
}

impl SkillAuthorityReceipt {
    pub fn skill_id(&self) -> &str {
        &self.skill_id
    }

    pub fn package_generation_sha256(&self) -> &str {
        &self.package_generation_sha256
    }

    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    pub fn install_incarnation(&self) -> u64 {
        self.install_incarnation
    }

    pub fn install_terminal_receipt_sha256(&self) -> &str {
        &self.install_terminal_receipt_sha256
    }

    pub fn authority_sequence(&self) -> u64 {
        self.authority_sequence
    }

    pub fn record_sha256(&self) -> &str {
        &self.record_sha256
    }

    pub fn current_anchor_sha256(&self) -> &str {
        &self.current_anchor_sha256
    }

    pub fn decision_id(&self) -> &str {
        &self.decision_id
    }

    pub fn provenance(&self) -> SkillProvenance {
        self.provenance
    }

    pub fn decision_source(&self) -> SkillAuthorityDecisionSource {
        self.decision_source
    }

    pub fn state(&self) -> SkillAuthorityState {
        self.state
    }

    pub fn claims(&self) -> &SkillBehaviorClaimsV1 {
        &self.claims
    }

    pub fn durability(&self) -> SkillAuthorityDurability {
        self.durability
    }

    pub fn accepted_policy_current_at_return(&self) -> bool {
        self.accepted_policy_current_at_return
    }
}

/// Successfully authenticated runtime authority. Fields are private so callers
/// cannot manufacture this type from a manifest boolean.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ValidatedSkillAuthority {
    record: SkillAuthorityRecordV1,
    record_sha256: String,
    current_anchor_sha256: String,
}

/// The effective manifest, exact package capability and authority proof are
/// retained together under the shared mutation lock. Runtime consumers must
/// route from this object rather than reopening `<skills>/<id>` after
/// validation.
#[derive(Debug)]
pub struct ValidatedInstalledSkillAuthority {
    authority: ValidatedSkillAuthority,
    effective_manifest: SkillManifest,
    package_generation_sha256: String,
    manifest_sha256: String,
    install_incarnation: u64,
    install_terminal_receipt_sha256: String,
}

impl ValidatedInstalledSkillAuthority {
    pub fn manifest(&self) -> &SkillManifest {
        &self.effective_manifest
    }

    pub fn package_generation_sha256(&self) -> &str {
        &self.package_generation_sha256
    }

    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    pub fn install_incarnation(&self) -> u64 {
        self.install_incarnation
    }

    pub fn install_terminal_receipt_sha256(&self) -> &str {
        &self.install_terminal_receipt_sha256
    }

    pub fn record(&self) -> &SkillAuthorityRecordV1 {
        self.authority.record()
    }

    pub fn record_sha256(&self) -> &str {
        self.authority.record_sha256()
    }

    pub fn current_anchor_sha256(&self) -> &str {
        self.authority.current_anchor_sha256()
    }
}

impl ValidatedSkillAuthority {
    pub fn record(&self) -> &SkillAuthorityRecordV1 {
        &self.record
    }

    pub fn record_sha256(&self) -> &str {
        &self.record_sha256
    }

    pub fn current_anchor_sha256(&self) -> &str {
        &self.current_anchor_sha256
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillAuthorityInactiveReason {
    ExpectationInvalid,
    InstalledPackageMissing,
    InstalledPackageInvalid,
    InstalledPolicyDisabled,
    PinnedContentHashMismatch,
    AcceptedPolicyChanged,
    AuthorityStoreMissing,
    AuthorityStoreInvalid,
    AuthorityNamespaceLimitExceeded,
    AuthorityKeyMissing,
    AuthorityKeyInvalid,
    CurrentAnchorMissing,
    CurrentAnchorInvalid,
    CurrentAnchorMacInvalid,
    CurrentAnchorMismatch,
    AuthorityWalHeadMissing,
    AuthorityWalHeadInvalid,
    AuthorityWalHeadMismatch,
    AuthorityRecordMissing,
    AuthorityRecordInvalid,
    AuthorityRecordMacInvalid,
    AuthorityRecordDigestMismatch,
    PackageGenerationMismatch,
    InstallIncarnationMismatch,
    ManifestDigestMismatch,
    BehaviorClaimsMismatch,
    DecisionInactive,
    DecisionRevoked,
}

impl SkillAuthorityInactiveReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExpectationInvalid => "expectation_invalid",
            Self::InstalledPackageMissing => "installed_package_missing",
            Self::InstalledPackageInvalid => "installed_package_invalid",
            Self::InstalledPolicyDisabled => "installed_policy_disabled",
            Self::PinnedContentHashMismatch => "pinned_content_hash_mismatch",
            Self::AcceptedPolicyChanged => "accepted_policy_changed",
            Self::AuthorityStoreMissing => "authority_store_missing",
            Self::AuthorityStoreInvalid => "authority_store_invalid",
            Self::AuthorityNamespaceLimitExceeded => "authority_namespace_limit_exceeded",
            Self::AuthorityKeyMissing => "authority_key_missing",
            Self::AuthorityKeyInvalid => "authority_key_invalid",
            Self::CurrentAnchorMissing => "current_anchor_missing",
            Self::CurrentAnchorInvalid => "current_anchor_invalid",
            Self::CurrentAnchorMacInvalid => "current_anchor_mac_invalid",
            Self::CurrentAnchorMismatch => "current_anchor_mismatch",
            Self::AuthorityWalHeadMissing => "authority_wal_head_missing",
            Self::AuthorityWalHeadInvalid => "authority_wal_head_invalid",
            Self::AuthorityWalHeadMismatch => "authority_wal_head_mismatch",
            Self::AuthorityRecordMissing => "authority_record_missing",
            Self::AuthorityRecordInvalid => "authority_record_invalid",
            Self::AuthorityRecordMacInvalid => "authority_record_mac_invalid",
            Self::AuthorityRecordDigestMismatch => "authority_record_digest_mismatch",
            Self::PackageGenerationMismatch => "package_generation_mismatch",
            Self::InstallIncarnationMismatch => "install_incarnation_mismatch",
            Self::ManifestDigestMismatch => "manifest_digest_mismatch",
            Self::BehaviorClaimsMismatch => "behavior_claims_mismatch",
            Self::DecisionInactive => "decision_inactive",
            Self::DecisionRevoked => "decision_revoked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SkillAuthorityValidation {
    Active(Box<ValidatedSkillAuthority>),
    Inactive(SkillAuthorityInactiveReason),
}

impl SkillAuthorityValidation {
    #[cfg(test)]
    pub fn inactive_reason(&self) -> Option<SkillAuthorityInactiveReason> {
        match self {
            Self::Active(_) => None,
            Self::Inactive(reason) => Some(*reason),
        }
    }
}

#[derive(Debug)]
pub enum InstalledSkillAuthorityValidation {
    Active(Box<ValidatedInstalledSkillAuthority>),
    Inactive(SkillAuthorityInactiveReason),
}

impl InstalledSkillAuthorityValidation {
    pub fn inactive_reason(&self) -> Option<SkillAuthorityInactiveReason> {
        match self {
            Self::Active(_) => None,
            Self::Inactive(reason) => Some(*reason),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedAuthorityRecordV1 {
    envelope_version: u32,
    record_sha256: String,
    record: SkillAuthorityRecordV1,
    hmac_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SkillCurrentAnchorV1 {
    version: u32,
    skill_id: String,
    package_generation_sha256: String,
    install_incarnation: u64,
    install_terminal_receipt_sha256: String,
    authority_sequence: u64,
    record_sha256: String,
    decision_id: String,
    state: SkillAuthorityState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedCurrentAnchorV1 {
    envelope_version: u32,
    anchor: SkillCurrentAnchorV1,
    hmac_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SkillAuthorityWalEventV1 {
    schema_version: u32,
    audit_event_id: String,
    operation_id: String,
    skill_id: String,
    package_generation_sha256: String,
    install_incarnation: u64,
    install_terminal_receipt_sha256: String,
    authority_sequence: u64,
    previous_authority_receipt_sha256: Option<String>,
    previous_record_sha256: Option<String>,
    record_sha256: String,
    decision_id: String,
    state: SkillAuthorityState,
    auth_hmac_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct SkillAuthorityWalReceiptV1 {
    payload_sha256: String,
    segment_name: String,
    segment_generation: u32,
    segment_seq: u64,
    segment_start_ts_ns: u64,
    segment_node_id_hex: String,
    logical_offset: u64,
    event_id: u64,
    event_hlc_physical_ns: u64,
    event_hlc_logical: u32,
    event_node_id_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthenticatedSkillAuthorityWalHead {
    event: SkillAuthorityWalEventV1,
    receipt_sha256: String,
}

struct AuthorityStore {
    root: BoundDirectory,
    records: Dir,
    current: Dir,
    records_path: PathBuf,
    current_path: PathBuf,
}

struct AuthorityStoreGuard {
    _file: std::fs::File,
}

/// Cross-process publication barrier for a fully built installed-Skill
/// runtime snapshot. Holding this capability blocks both package mutation and
/// authority publication until the caller completes its final ArcSwap store.
///
/// Lock order is always package-mutation then authority, matching installed
/// authority validation/publication and avoiding cross-process inversion.
#[must_use = "the publication barrier must remain alive through the ArcSwap store"]
pub(crate) struct InstalledSkillPublicationGuard {
    skills_root: BoundDirectory,
    authority_store: AuthorityStore,
    authority_key: Zeroizing<Vec<u8>>,
    install_incarnations: super::mutation_lifecycle::SkillInstallIncarnationIndex,
    authority_wal_heads: BTreeMap<String, AuthenticatedSkillAuthorityWalHead>,
    traversal_budget: super::installer::RuntimeAuthorityTraversalBudget,
    _authority_guard: AuthorityStoreGuard,
    _mutation_guard: super::installer::SkillMutationGuard,
}

/// One reload-generation validation session. It freezes installed package
/// mutation and indexes each authenticated WAL domain exactly once, so a
/// directory full of candidate Skills cannot turn validation into
/// `candidate_count * WAL_size` work.
pub(crate) struct InstalledAuthorityValidationBatch {
    home: PathBuf,
    accepted_policy: AcceptedSkillPolicySnapshot,
    skills_root: BoundDirectory,
    install_incarnations: super::mutation_lifecycle::SkillInstallIncarnationIndex,
    authority_wal_heads: BTreeMap<String, AuthenticatedSkillAuthorityWalHead>,
    traversal_budget: super::installer::RuntimeAuthorityTraversalBudget,
    _mutation_guard: super::installer::SkillMutationGuard,
}

impl InstalledSkillPublicationGuard {
    /// Revalidate one already-built runtime proof under the final publication
    /// barrier. No caller-controlled state is trusted: package generation,
    /// install incarnation, immutable authority record, current anchor and WAL
    /// head must all still name the exact same active decision.
    pub(crate) fn validate_installed_binding(
        &mut self,
        skill_id: &str,
        package_generation_sha256: &str,
        install_incarnation: u64,
        install_terminal_receipt_sha256: &str,
        authority_record_sha256: &str,
    ) -> Result<()> {
        super::creator::validate_skill_id(skill_id)
            .context("validate runtime publication Skill id")?;
        validate_sha256(
            package_generation_sha256,
            "runtime publication package generation",
        )?;
        if install_incarnation == 0 {
            anyhow::bail!("runtime publication install incarnation must be non-zero");
        }
        validate_sha256(
            install_terminal_receipt_sha256,
            "runtime publication install receipt",
        )?;
        validate_sha256(
            authority_record_sha256,
            "runtime publication authority record",
        )?;

        let observed_generation = super::installer::target_generation_locked_with_budget(
            &self.skills_root,
            skill_id,
            &mut self.traversal_budget,
        )?
        .with_context(|| {
            format!("installed Skill `{skill_id}` disappeared before runtime publication")
        })?;
        if observed_generation != package_generation_sha256 {
            anyhow::bail!(
                "installed Skill `{skill_id}` generation changed before runtime publication"
            );
        }
        let install_proof = self
            .install_incarnations
            .authenticate_current(skill_id, package_generation_sha256)
            .context("revalidate install incarnation before runtime publication")?;
        if install_proof.install_incarnation() != install_incarnation
            || install_proof.terminal_receipt_sha256() != install_terminal_receipt_sha256
        {
            anyhow::bail!(
                "installed Skill `{skill_id}` incarnation changed before runtime publication"
            );
        }

        let (anchor, _) = read_authenticated_current_anchor_for_publish(
            &self.authority_store,
            skill_id,
            &self.authority_key,
        )?
        .with_context(|| {
            format!("installed Skill `{skill_id}` authority anchor disappeared before publication")
        })?;
        let record_directory = open_existing_record_namespace(&self.authority_store, skill_id)
            .map_err(|reason| {
                anyhow::anyhow!(
                    "installed Skill `{skill_id}` authority namespace is invalid: {reason:?}"
                )
            })?;
        let record_directory_path = self.authority_store.records_path.join(skill_id);
        let chain = load_authenticated_record_chain_with_budget(
            &record_directory,
            &record_directory_path,
            skill_id,
            &self.authority_key,
            &mut self.traversal_budget,
        )
        .map_err(|failure| match failure {
            RecordChainFailure::AggregateTraversal(error) => error,
            failure => anyhow::Error::new(failure),
        })
        .context("revalidate authority record chain before runtime publication")?;
        let latest = chain.last().with_context(|| {
            format!("installed Skill `{skill_id}` authority record disappeared before publication")
        })?;
        if !anchor_matches_record(&anchor.anchor, latest)
            || latest.record_sha256 != authority_record_sha256
            || latest.record.state != SkillAuthorityState::Active
            || latest.record.package_generation_sha256 != package_generation_sha256
            || latest.record.install_incarnation != install_incarnation
            || latest.record.install_terminal_receipt_sha256 != install_terminal_receipt_sha256
        {
            anyhow::bail!(
                "installed Skill `{skill_id}` authority changed before runtime publication"
            );
        }
        let head = self
            .authority_wal_heads
            .get(skill_id)
            .context("installed Skill authority WAL head disappeared before publication")?;
        if !authority_wal_head_matches_record(head, &latest.record, &latest.record_sha256) {
            anyhow::bail!(
                "installed Skill `{skill_id}` authority WAL head changed before publication"
            );
        }
        Ok(())
    }
}

struct AuthenticatedRecordEntry {
    record: SkillAuthorityRecordV1,
    record_sha256: String,
}

#[derive(Debug, thiserror::Error)]
enum RecordChainFailure {
    #[error("Skill authority record namespace entry limit exceeded")]
    NamespaceLimit,
    #[error("Skill authority record chain is invalid")]
    Invalid,
    #[error("Skill authority record digest or immutable filename is invalid")]
    DigestMismatch,
    #[error("Skill authority record HMAC is invalid")]
    MacInvalid,
    #[error("runtime Skill authority record traversal exceeded its aggregate budget: {0:#}")]
    AggregateTraversal(anyhow::Error),
}

#[derive(Debug, thiserror::Error)]
#[error("Skill authority namespace entry limit exceeded")]
struct AuthorityNamespaceLimitExceeded;

pub fn authority_root(home: &Path) -> PathBuf {
    home.join(AUTHORITY_ROOT_NAME)
}

pub(crate) fn lock_installed_skill_publication(
    home: &Path,
) -> Result<InstalledSkillPublicationGuard> {
    let skills_path = home.join("skills");
    let skills_root = open_bound_directory(&skills_path, false, "runtime Skill publication root")?
        .context("installed Skill root is missing at runtime publication")?;
    let mutation_guard = super::installer::lock_skill_mutations(&skills_root)
        .context("lock installed Skill packages through runtime publication")?;
    super::installer::recover_pending_transactions_locked(&skills_root)
        .context("recover installed Skill mutation before runtime publication")?;
    let authority_store = open_existing_authority_store(home).map_err(|reason| {
        anyhow::anyhow!("Skill authority store is unavailable at publication: {reason:?}")
    })?;
    let authority_guard = lock_authority_store(&authority_store, false)
        .context("lock Skill authority decisions through runtime publication")?;
    let authority_key = load_existing_authority_key_checked(home)?;
    let install_incarnations =
        super::mutation_lifecycle::scan_skill_install_incarnation_index(home)
            .context("index installed Skill incarnations for runtime publication")?;
    let authority_wal_heads = scan_authority_wal_heads(home)
        .context("index Skill authority WAL heads for publication")?;
    Ok(InstalledSkillPublicationGuard {
        skills_root,
        authority_store,
        authority_key,
        install_incarnations,
        authority_wal_heads,
        traversal_budget: super::installer::RuntimeAuthorityTraversalBudget::new(),
        _authority_guard: authority_guard,
        _mutation_guard: mutation_guard,
    })
}

pub fn current_anchor_path(home: &Path, skill_id: &str) -> Result<PathBuf> {
    super::creator::validate_skill_id(skill_id)?;
    Ok(authority_root(home)
        .join(AUTHORITY_CURRENT_NAME)
        .join(current_anchor_file_name(skill_id)))
}

/// Read the exact authenticated record/anchor/WAL head currently committed for
/// one installed Skill. Missing authority is `Ok(None)`; malformed, stale or
/// divergent evidence is an error and must never be rendered as an inactive
/// but otherwise healthy decision.
pub fn inspect_current_authority(
    home: &Path,
    skill_id: &str,
) -> Result<Option<SkillAuthorityCurrentStatus>> {
    super::creator::validate_skill_id(skill_id).context("validate Skill authority status id")?;
    let store = match open_existing_authority_store(home) {
        Ok(store) => store,
        Err(SkillAuthorityInactiveReason::AuthorityStoreMissing) => return Ok(None),
        Err(reason) => anyhow::bail!(
            "Skill authority store is unavailable while reading `{skill_id}`: {}",
            reason.as_str()
        ),
    };
    let _authority_guard = lock_authority_store(&store, false)
        .context("lock Skill authority store for authenticated readback")?;
    let key = load_existing_authority_key_checked(home)
        .context("load Skill authority key for authenticated readback")?;
    let Some((anchor, anchor_bytes)) =
        read_authenticated_current_anchor_for_publish(&store, skill_id, &key)?
    else {
        let record_namespace_exists = match store.records.symlink_metadata(skill_id) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect Skill authority record namespace for `{skill_id}`")
                });
            }
            Ok(metadata) if !metadata.is_dir() || cap_metadata_is_link_like(&metadata) => {
                anyhow::bail!(
                    "Skill authority current anchor for `{skill_id}` is missing while an invalid record namespace remains"
                );
            }
            Ok(_) => {
                let namespace_path = store.records_path.join(skill_id);
                let namespace =
                    open_real_child_dir(&store.records, OsStr::new(skill_id), &namespace_path)
                        .context("open orphaned Skill authority record namespace")?;
                ensure_private_directory(&namespace, &namespace_path)
                    .context("validate orphaned Skill authority record namespace")?;
                true
            }
        };
        let wal_head_exists = scan_authority_wal_head(home, skill_id)
            .context("scan orphaned Skill authority WAL evidence")?
            .is_some();
        anyhow::ensure!(
            !record_namespace_exists && !wal_head_exists,
            "Skill authority current anchor for `{skill_id}` is missing while authenticated record or WAL evidence remains"
        );
        return Ok(None);
    };
    let record_directory = open_existing_record_namespace(&store, skill_id).map_err(|reason| {
        anyhow::anyhow!(
            "Skill authority record namespace for `{skill_id}` is unavailable: {}",
            reason.as_str()
        )
    })?;
    let record_directory_path = store.records_path.join(skill_id);
    let chain =
        load_authenticated_record_chain(&record_directory, &record_directory_path, skill_id, &key)
            .map_err(anyhow::Error::new)
            .context("load authenticated Skill authority record chain")?;
    let latest = chain
        .last()
        .with_context(|| format!("Skill authority anchor for `{skill_id}` has no record"))?;
    anyhow::ensure!(
        anchor_matches_record(&anchor.anchor, latest),
        "Skill authority anchor for `{skill_id}` does not match its current record"
    );
    let wal_head = scan_authority_wal_head(home, skill_id)
        .context("read authenticated Skill authority WAL head")?
        .with_context(|| format!("Skill authority WAL head for `{skill_id}` is missing"))?;
    anyhow::ensure!(
        authority_wal_head_matches_record(&wal_head, &latest.record, &latest.record_sha256),
        "Skill authority WAL head for `{skill_id}` does not match its current record"
    );
    Ok(Some(SkillAuthorityCurrentStatus {
        record: latest.record.clone(),
        record_sha256: latest.record_sha256.clone(),
        current_anchor_sha256: sha256_hex(&anchor_bytes),
        authority_wal_receipt_sha256: wal_head.receipt_sha256,
    }))
}

pub fn manifest_sha256(raw_manifest: &[u8]) -> String {
    sha256_hex(raw_manifest)
}

fn provenance_from_install_origin(
    origin: super::installer::SkillMutationOrigin,
) -> Result<SkillProvenance> {
    match origin {
        super::installer::SkillMutationOrigin::CliInstall
        | super::installer::SkillMutationOrigin::CliCreate => Ok(SkillProvenance::LocalInstall),
        super::installer::SkillMutationOrigin::ProactiveAccept => {
            Ok(SkillProvenance::ProactiveAccept)
        }
        super::installer::SkillMutationOrigin::ProactiveCurator => {
            Ok(SkillProvenance::ProactiveCurator)
        }
        super::installer::SkillMutationOrigin::Teacher => Ok(SkillProvenance::Teacher),
        super::installer::SkillMutationOrigin::SelfImproveAccept
        | super::installer::SkillMutationOrigin::SelfImproveRollback => {
            Ok(SkillProvenance::SelfImprove)
        }
        super::installer::SkillMutationOrigin::CliUninstall => {
            anyhow::bail!("a removal receipt cannot provide installed-Skill provenance")
        }
    }
}

pub(crate) fn begin_installed_authority_validation_batch(
    home: &Path,
    reload: &crate::config::reload::ReloadController,
) -> Result<InstalledAuthorityValidationBatch> {
    let accepted_policy = AcceptedSkillPolicySnapshot::from_accepted(&reload.accepted_snapshot())?;
    let skills_root = open_bound_directory(&home.join("skills"), false, "installed Skills root")?
        .context("installed Skill root is missing during authority validation")?;
    let mutation_guard = super::installer::lock_skill_mutations(&skills_root)
        .context("lock installed Skill packages through authority batch validation")?;
    super::installer::recover_pending_transactions_locked(&skills_root)
        .context("recover installed Skill mutations before authority batch validation")?;
    let install_incarnations =
        super::mutation_lifecycle::scan_skill_install_incarnation_index(home)
            .context("index installed Skill incarnations for authority batch validation")?;

    // Freeze authority publication only for the one WAL traversal. Individual
    // record/anchor checks may run after this short lock, but the final
    // publication barrier revalidates every exact proof before ArcSwap.
    let authority_store = open_existing_authority_store(home).map_err(|reason| {
        anyhow::anyhow!("Skill authority store is unavailable during batch validation: {reason:?}")
    })?;
    let authority_guard = lock_authority_store(&authority_store, false)
        .context("lock Skill authority WAL through batch indexing")?;
    let authority_wal_heads = scan_authority_wal_heads(home)
        .context("index Skill authority WAL heads for batch validation")?;
    drop(authority_guard);

    Ok(InstalledAuthorityValidationBatch {
        home: home.to_path_buf(),
        accepted_policy,
        skills_root,
        install_incarnations,
        authority_wal_heads,
        traversal_budget: super::installer::RuntimeAuthorityTraversalBudget::new(),
        _mutation_guard: mutation_guard,
    })
}

impl InstalledAuthorityValidationBatch {
    #[cfg(test)]
    pub(crate) fn set_traversal_limits_for_test(&mut self, max_entries: usize, max_bytes: u64) {
        self.traversal_budget =
            super::installer::RuntimeAuthorityTraversalBudget::with_limits(max_entries, max_bytes);
    }

    pub(crate) fn validate(
        &mut self,
        skill_id: &str,
        reload: &crate::config::reload::ReloadController,
    ) -> Result<InstalledSkillAuthorityValidation> {
        let snapshot = match inspect_installed_authority_snapshot_locked(
            &self.skills_root,
            skill_id,
            &self.accepted_policy,
            &self.install_incarnations,
            &mut self.traversal_budget,
        ) {
            Ok(snapshot) => snapshot,
            Err(InstalledSnapshotFailure::AggregateTraversal(error)) => return Err(error),
            Err(failure) => {
                return Ok(InstalledSkillAuthorityValidation::Inactive(
                    installed_snapshot_failure_reason(failure),
                ));
            }
        };
        if !snapshot.effective_enabled {
            return Ok(InstalledSkillAuthorityValidation::Inactive(
                SkillAuthorityInactiveReason::InstalledPolicyDisabled,
            ));
        }
        let validation = match validate_current_authority_inner_with_heads(
            &self.home,
            &snapshot.expectation,
            Some(&self.authority_wal_heads),
            Some(&mut self.traversal_budget),
        ) {
            Ok(authority) => SkillAuthorityValidation::Active(Box::new(authority)),
            Err(reason) => SkillAuthorityValidation::Inactive(reason),
        };
        self.traversal_budget.ensure_within_limits()?;
        if reload.accepted_snapshot().epoch() != self.accepted_policy.config_epoch {
            return Ok(InstalledSkillAuthorityValidation::Inactive(
                SkillAuthorityInactiveReason::AcceptedPolicyChanged,
            ));
        }
        Ok(materialize_installed_authority_validation(
            &snapshot.expectation,
            &snapshot.effective_manifest,
            validation,
        ))
    }
}

fn installed_snapshot_failure_reason(
    failure: InstalledSnapshotFailure,
) -> SkillAuthorityInactiveReason {
    match failure {
        InstalledSnapshotFailure::Missing => SkillAuthorityInactiveReason::InstalledPackageMissing,
        InstalledSnapshotFailure::PinnedHashMismatch => {
            SkillAuthorityInactiveReason::PinnedContentHashMismatch
        }
        InstalledSnapshotFailure::IncarnationInvalid => {
            SkillAuthorityInactiveReason::InstallIncarnationMismatch
        }
        InstalledSnapshotFailure::AggregateTraversal(_) => {
            SkillAuthorityInactiveReason::InstalledPackageInvalid
        }
        InstalledSnapshotFailure::Invalid(_) => {
            SkillAuthorityInactiveReason::InstalledPackageInvalid
        }
    }
}

fn materialize_installed_authority_validation(
    expectation: &SkillAuthorityExpectation,
    effective_manifest: &SkillManifest,
    validation: SkillAuthorityValidation,
) -> InstalledSkillAuthorityValidation {
    match validation {
        SkillAuthorityValidation::Active(authority) => {
            InstalledSkillAuthorityValidation::Active(Box::new(ValidatedInstalledSkillAuthority {
                authority: *authority,
                effective_manifest: effective_manifest.clone(),
                package_generation_sha256: expectation.package_generation_sha256.clone(),
                manifest_sha256: expectation.manifest_sha256.clone(),
                install_incarnation: expectation.install_incarnation,
                install_terminal_receipt_sha256: expectation
                    .install_terminal_receipt_sha256
                    .clone(),
            }))
        }
        SkillAuthorityValidation::Inactive(reason) => {
            InstalledSkillAuthorityValidation::Inactive(reason)
        }
    }
}

/// Validate authority against the exact currently installed package and the
/// already accepted operator Skill policy. Package and manifest hashes are
/// always computed inside this boundary; callers cannot substitute hashes
/// copied from an authority record.
pub fn validate_installed_authority(
    home: &Path,
    skill_id: &str,
    reload: &crate::config::reload::ReloadController,
) -> InstalledSkillAuthorityValidation {
    let accepted = reload.accepted_snapshot();
    let accepted_policy = match AcceptedSkillPolicySnapshot::from_accepted(&accepted) {
        Ok(policy) => policy,
        Err(_) => {
            return InstalledSkillAuthorityValidation::Inactive(
                SkillAuthorityInactiveReason::InstalledPackageInvalid,
            );
        }
    };
    let skills_dir = home.join("skills");
    let snapshot = match bind_installed_authority_snapshot(&skills_dir, skill_id, &accepted_policy)
    {
        Ok(snapshot) => snapshot,
        Err(failure) => {
            return InstalledSkillAuthorityValidation::Inactive(installed_snapshot_failure_reason(
                failure,
            ));
        }
    };
    if !snapshot.effective_enabled {
        return InstalledSkillAuthorityValidation::Inactive(
            SkillAuthorityInactiveReason::InstalledPolicyDisabled,
        );
    }
    let validation = validate_current_authority(home, &snapshot.expectation);
    if reload.accepted_snapshot().epoch() != accepted_policy.config_epoch {
        return InstalledSkillAuthorityValidation::Inactive(
            SkillAuthorityInactiveReason::AcceptedPolicyChanged,
        );
    }
    materialize_installed_authority_validation(
        &snapshot.expectation,
        &snapshot.effective_manifest,
        validation,
    )
}

/// Publish a decision for the exact live installed package. The shared Skill
/// mutation lock remains held through the authority commit, so a cooperating
/// installer cannot replace the package after its generation was authorized.
#[cfg(test)]
pub(crate) fn publish_installed_authority_decision(
    home: &Path,
    skill_id: &str,
    reload: &crate::config::reload::ReloadController,
    decision: SkillAuthorityDecision,
) -> Result<SkillAuthorityReceipt> {
    publish_installed_authority_decision_with_expectation(home, skill_id, reload, decision, None)
}

#[cfg(test)]
pub(crate) fn publish_installed_authority_decision_with_expectation(
    home: &Path,
    skill_id: &str,
    reload: &crate::config::reload::ReloadController,
    decision: SkillAuthorityDecision,
    expectation: Option<&InstalledSkillDecisionExpectation>,
) -> Result<SkillAuthorityReceipt> {
    let accepted = reload.accepted_snapshot();
    let accepted_policy = AcceptedSkillPolicySnapshot::from_accepted(&accepted)?;
    let skills_dir = home.join("skills");
    let snapshot = bind_installed_authority_snapshot(&skills_dir, skill_id, &accepted_policy)
        .map_err(|failure| match failure {
            InstalledSnapshotFailure::Missing => {
                anyhow::anyhow!("installed Skill package `{skill_id}` is missing")
            }
            InstalledSnapshotFailure::PinnedHashMismatch => {
                anyhow::anyhow!("installed Skill package `{skill_id}` violates its accepted pin")
            }
            InstalledSnapshotFailure::IncarnationInvalid => anyhow::anyhow!(
                "installed Skill package `{skill_id}` lacks its exact authenticated install receipt"
            ),
            InstalledSnapshotFailure::AggregateTraversal(error) => error,
            InstalledSnapshotFailure::Invalid(error) => error,
        })?;
    if let Some(expectation) = expectation {
        anyhow::ensure!(
            snapshot.expectation.package_generation_sha256 == expectation.package_generation_sha256
                && snapshot.expectation.install_incarnation == expectation.install_incarnation
                && snapshot.expectation.install_terminal_receipt_sha256
                    == expectation.install_terminal_receipt_sha256,
            "installed Skill changed after operator consent; refuse authority mutation"
        );
    }
    if decision.state == SkillAuthorityState::Active && !snapshot.effective_enabled {
        anyhow::bail!("operator Skill policy disables `{skill_id}`; refuse active authority");
    }
    let force_new_revision = decision.force_new_revision;
    let expected = &snapshot.expectation;
    let record = SkillAuthorityRecordV1::new(
        expected.skill_id.clone(),
        expected.package_generation_sha256.clone(),
        expected.manifest_sha256.clone(),
        expected.install_incarnation,
        expected.install_terminal_receipt_sha256.clone(),
        expected.provenance,
        decision.decision_source,
        decision.state,
        decision.decision_reason,
        expected.claims.clone(),
    )?;
    if reload.accepted_snapshot().epoch() != accepted_policy.config_epoch {
        anyhow::bail!("accepted Skill policy changed before authority publication");
    }
    let mut receipt = publish_authority_decision_with_revision(home, &record, force_new_revision)?;
    receipt.accepted_policy_current_at_return =
        reload.accepted_snapshot().epoch() == accepted_policy.config_epoch;
    Ok(receipt)
}

/// Activate one installed package without ever exposing a same-id bundled
/// fallback between policy and authority commits.
///
/// The caller supplies a reload controller for the already prepared
/// prospective `enabled` policy plus its exact CAS commit. An exact already
/// active decision is history-idempotent. Every other activation reserves two
/// record slots and keeps the package mutation lock across:
///
/// 1. an authenticated prospective-policy `Inactive` guard,
/// 2. the config CAS, and
/// 3. the final `Active` decision.
///
/// If either later step fails, the rollback closure runs before the package
/// lock is released. The durable inactive guard remains authoritative even
/// when the config writer reports an ambiguous post-rename failure.
pub(crate) fn publish_installed_activation_transaction<C, R>(
    home: &Path,
    skill_id: &str,
    prospective_reload: &crate::config::reload::ReloadController,
    decision_source: SkillAuthorityDecisionSource,
    expectation: Option<&InstalledSkillDecisionExpectation>,
    commit_enabled_policy: C,
    rollback_disabled_policy: R,
) -> Result<SkillAuthorityReceipt>
where
    C: FnOnce() -> Result<()>,
    R: FnOnce() -> Result<()>,
{
    let accepted = prospective_reload.accepted_snapshot();
    let accepted_policy = AcceptedSkillPolicySnapshot::from_accepted(&accepted)?;
    let skills_dir = home.join("skills");
    let snapshot = bind_installed_authority_snapshot(&skills_dir, skill_id, &accepted_policy)
        .map_err(|failure| match failure {
            InstalledSnapshotFailure::Missing => {
                anyhow::anyhow!("installed Skill package `{skill_id}` is missing")
            }
            InstalledSnapshotFailure::PinnedHashMismatch => {
                anyhow::anyhow!("installed Skill package `{skill_id}` violates its accepted pin")
            }
            InstalledSnapshotFailure::IncarnationInvalid => anyhow::anyhow!(
                "installed Skill package `{skill_id}` lacks its exact authenticated install receipt"
            ),
            InstalledSnapshotFailure::AggregateTraversal(error) => error,
            InstalledSnapshotFailure::Invalid(error) => error,
        })?;
    if let Some(expectation) = expectation {
        anyhow::ensure!(
            snapshot.expectation.package_generation_sha256 == expectation.package_generation_sha256
                && snapshot.expectation.install_incarnation == expectation.install_incarnation
                && snapshot.expectation.install_terminal_receipt_sha256
                    == expectation.install_terminal_receipt_sha256,
            "installed Skill changed after operator consent; refuse authority mutation"
        );
    }
    anyhow::ensure!(
        snapshot.effective_enabled,
        "prospective operator Skill policy does not enable `{skill_id}`"
    );
    super::installer::validate_prospective_route_activation_locked(&snapshot._skills_root)?;

    let active = SkillAuthorityDecision::new(decision_source, SkillAuthorityState::Active, None)?;
    let active_record = authority_record_for_snapshot(&snapshot, active)?;
    if inspect_current_authority(home, skill_id)?
        .is_some_and(|current| authority_decision_semantics_match(current.record(), &active_record))
    {
        // Re-enabling an already-authorized exact generation is history
        // idempotent. Reconfirm the existing durable head, then commit the
        // prepared config CAS. If the CAS fails, policy rollback remains the
        // fail-closed boundary; no new authority record was consumed.
        let mut receipt = publish_authority_decision_verified(home, &active_record)
            .context("reconfirm existing installed-Skill activation")?;
        if let Err(error) = commit_enabled_policy() {
            return Err(match rollback_disabled_policy() {
                Ok(()) => error.context("commit prepared Skill enable policy"),
                Err(rollback_error) => error.context(format!(
                    "commit prepared Skill enable policy; Skill activation rollback also failed: {rollback_error:#}"
                )),
            });
        }
        receipt.accepted_policy_current_at_return =
            prospective_reload.accepted_snapshot().epoch() == accepted_policy.config_epoch;
        return Ok(receipt);
    }

    ensure_authority_record_capacity(home, skill_id, 2)
        .context("reserve inactive and active Skill authority revisions")?;

    let staging = SkillAuthorityDecision::new(
        decision_source,
        SkillAuthorityState::Inactive,
        Some("activation transaction pending policy commit".to_string()),
    )?;
    let staging_record = authority_record_for_snapshot(&snapshot, staging)?;
    publish_authority_decision_verified(home, &staging_record)
        .context("publish fail-closed Skill activation guard")?;

    let rollback_on_error = |primary: anyhow::Error, rollback: R| -> anyhow::Error {
        match rollback() {
            Ok(()) => primary,
            Err(rollback_error) => primary.context(format!(
                "Skill activation rollback also failed: {rollback_error:#}; authenticated inactive guard remains committed"
            )),
        }
    };
    if let Err(error) = commit_enabled_policy() {
        return Err(rollback_on_error(
            error.context("commit prepared Skill enable policy"),
            rollback_disabled_policy,
        ));
    }

    let mut receipt = match publish_authority_decision_verified(home, &active_record) {
        Ok(receipt) => receipt,
        Err(error) => {
            return Err(rollback_on_error(
                error.context("publish final installed-Skill activation"),
                rollback_disabled_policy,
            ));
        }
    };
    receipt.accepted_policy_current_at_return =
        prospective_reload.accepted_snapshot().epoch() == accepted_policy.config_epoch;
    Ok(receipt)
}

/// Reduce one installed package's authority without exposing an unchecked
/// same-id bundled fallback between policy and authority commits. The package
/// mutation lock acquired by `bind_installed_authority_snapshot` remains held
/// across route-owner preflight, the exact config CAS, and authority
/// publication.
pub(crate) fn publish_installed_reduction_transaction<C>(
    home: &Path,
    skill_id: &str,
    prospective_reload: &crate::config::reload::ReloadController,
    decision: SkillAuthorityDecision,
    expectation: Option<&InstalledSkillDecisionExpectation>,
    commit_disabled_policy: C,
) -> Result<SkillAuthorityReceipt>
where
    C: FnOnce() -> Result<()>,
{
    anyhow::ensure!(
        decision.state != SkillAuthorityState::Active,
        "Skill authority reduction cannot publish an active decision"
    );
    let accepted = prospective_reload.accepted_snapshot();
    let accepted_policy = AcceptedSkillPolicySnapshot::from_accepted(&accepted)?;
    let skills_dir = home.join("skills");
    let snapshot = bind_installed_authority_snapshot(&skills_dir, skill_id, &accepted_policy)
        .map_err(|failure| match failure {
            InstalledSnapshotFailure::Missing => {
                anyhow::anyhow!("installed Skill package `{skill_id}` is missing")
            }
            InstalledSnapshotFailure::PinnedHashMismatch => {
                anyhow::anyhow!("installed Skill package `{skill_id}` violates its accepted pin")
            }
            InstalledSnapshotFailure::IncarnationInvalid => anyhow::anyhow!(
                "installed Skill package `{skill_id}` lacks its exact authenticated install receipt"
            ),
            InstalledSnapshotFailure::AggregateTraversal(error) => error,
            InstalledSnapshotFailure::Invalid(error) => error,
        })?;
    if let Some(expectation) = expectation {
        anyhow::ensure!(
            snapshot.expectation.package_generation_sha256 == expectation.package_generation_sha256
                && snapshot.expectation.install_incarnation == expectation.install_incarnation
                && snapshot.expectation.install_terminal_receipt_sha256
                    == expectation.install_terminal_receipt_sha256,
            "installed Skill changed after operator consent; refuse authority mutation"
        );
    }
    anyhow::ensure!(
        !snapshot.effective_enabled,
        "prospective operator Skill policy does not disable `{skill_id}`"
    );
    super::installer::validate_prospective_route_reduction_locked(
        &snapshot._skills_root,
        skill_id,
    )?;

    let record = authority_record_for_snapshot(&snapshot, decision)?;
    let already_current = inspect_current_authority(home, skill_id)?
        .is_some_and(|current| authority_decision_semantics_match(current.record(), &record));
    if !already_current {
        ensure_authority_record_capacity(home, skill_id, 1)
            .context("reserve reduced Skill authority revision")?;
    }
    commit_disabled_policy().context("commit prepared Skill disable policy")?;
    let mut receipt = publish_authority_decision_verified(home, &record)
        .context("publish reduced installed-Skill authority")?;
    receipt.accepted_policy_current_at_return =
        prospective_reload.accepted_snapshot().epoch() == accepted_policy.config_epoch;
    Ok(receipt)
}

fn ensure_authority_record_capacity(home: &Path, skill_id: &str, required: usize) -> Result<()> {
    // The caller still owns BoundInstalledAuthoritySnapshot's global package
    // mutation guard. Every production authority writer acquires that guard
    // before its authority lock, so the authenticated chain length cannot
    // change between this preflight and the two following publications.
    anyhow::ensure!(
        required <= MAX_AUTHORITY_RECORDS_PER_SKILL,
        "requested Skill authority reservation exceeds the complete history quota"
    );
    if inspect_current_authority(home, skill_id)?.is_none() {
        return Ok(());
    }
    let store = open_existing_authority_store(home).map_err(|reason| {
        anyhow::anyhow!(
            "Skill authority store is unavailable while reserving history: {}",
            reason.as_str()
        )
    })?;
    let _authority_guard =
        lock_authority_store(&store, false).context("lock Skill authority history reservation")?;
    let key = load_existing_authority_key_checked(home)
        .context("load Skill authority key for history reservation")?;
    let record_directory = open_existing_record_namespace(&store, skill_id).map_err(|reason| {
        anyhow::anyhow!(
            "Skill authority record namespace for `{skill_id}` is unavailable: {}",
            reason.as_str()
        )
    })?;
    let record_directory_path = store.records_path.join(skill_id);
    let chain =
        load_authenticated_record_chain(&record_directory, &record_directory_path, skill_id, &key)
            .map_err(anyhow::Error::new)
            .context("validate Skill authority history before reservation")?;
    ensure_authority_record_capacity_for_len(chain.len(), required)
}

fn ensure_authority_record_capacity_for_len(current: usize, required: usize) -> Result<()> {
    let remaining = MAX_AUTHORITY_RECORDS_PER_SKILL
        .checked_sub(current)
        .context("Skill authority history already exceeds its quota")?;
    anyhow::ensure!(
        remaining >= required,
        "Skill authority history has {remaining} free record slot(s), but this transition requires {required}; compact or archive this Skill's decision history first"
    );
    Ok(())
}

fn authority_record_for_snapshot(
    snapshot: &BoundInstalledAuthoritySnapshot,
    decision: SkillAuthorityDecision,
) -> Result<SkillAuthorityRecordV1> {
    let expected = &snapshot.expectation;
    SkillAuthorityRecordV1::new(
        expected.skill_id.clone(),
        expected.package_generation_sha256.clone(),
        expected.manifest_sha256.clone(),
        expected.install_incarnation,
        expected.install_terminal_receipt_sha256.clone(),
        expected.provenance,
        decision.decision_source,
        decision.state,
        decision.decision_reason,
        expected.claims.clone(),
    )
}

fn publish_authority_decision_verified(
    home: &Path,
    record: &SkillAuthorityRecordV1,
) -> Result<SkillAuthorityReceipt> {
    let first = publish_authority_decision(home, record)?;
    if first.durability().is_live_verified() {
        return Ok(first);
    }
    let verified = publish_authority_decision(home, record)
        .context("reconfirm visible Skill authority decision")?;
    anyhow::ensure!(
        verified.durability().is_live_verified(),
        "Skill authority decision remains visible without a verified publication state"
    );
    Ok(verified)
}

/// Complete a record-first crash without inventing a new decision. Recovery
/// accepts only the single authenticated tail immediately following the
/// current anchor (or the first record when no anchor exists), and only while
/// the exact installed package generation remains live.
pub fn recover_pending_installed_authority(
    home: &Path,
    skill_id: &str,
    reload: &crate::config::reload::ReloadController,
) -> Result<Option<SkillAuthorityReceipt>> {
    let accepted = reload.accepted_snapshot();
    let accepted_policy = AcceptedSkillPolicySnapshot::from_accepted(&accepted)?;
    let skills_dir = home.join("skills");
    let snapshot = bind_installed_authority_snapshot(&skills_dir, skill_id, &accepted_policy)
        .map_err(|failure| match failure {
            InstalledSnapshotFailure::Missing => {
                anyhow::anyhow!("installed Skill package `{skill_id}` is missing")
            }
            InstalledSnapshotFailure::PinnedHashMismatch => {
                anyhow::anyhow!("installed Skill package `{skill_id}` violates its accepted pin")
            }
            InstalledSnapshotFailure::IncarnationInvalid => anyhow::anyhow!(
                "installed Skill package `{skill_id}` lacks its exact authenticated install receipt"
            ),
            InstalledSnapshotFailure::AggregateTraversal(error) => error,
            InstalledSnapshotFailure::Invalid(error) => error,
        })?;
    let store = open_existing_authority_store(home).map_err(|reason| {
        anyhow::anyhow!("Skill authority store is not recoverable: {reason:?}")
    })?;
    let _authority_guard = lock_authority_store(&store, false)?;
    let key = load_existing_authority_key_checked(home)?;
    let record_directory = open_existing_record_namespace(&store, skill_id)
        .map_err(|reason| anyhow::anyhow!("Skill authority record store is invalid: {reason:?}"))?;
    let record_directory_path = store.records_path.join(skill_id);
    let chain =
        load_authenticated_record_chain(&record_directory, &record_directory_path, skill_id, &key)
            .map_err(anyhow::Error::new)?;
    let Some(latest) = chain.last() else {
        return Ok(None);
    };
    if latest.record.package_generation_sha256 != snapshot.expectation.package_generation_sha256
        || latest.record.manifest_sha256 != snapshot.expectation.manifest_sha256
        || latest.record.install_incarnation != snapshot.expectation.install_incarnation
        || latest.record.install_terminal_receipt_sha256
            != snapshot.expectation.install_terminal_receipt_sha256
        || latest.record.provenance != snapshot.expectation.provenance
    {
        anyhow::bail!("orphan Skill authority record targets a different installed package");
    }
    if latest.record.claims != snapshot.expectation.claims {
        anyhow::bail!("orphan Skill authority record targets a different accepted policy");
    }
    if latest.record.state == SkillAuthorityState::Active && !snapshot.effective_enabled {
        anyhow::bail!("current operator policy disables this orphan Skill authority decision");
    }
    if reload.accepted_snapshot().epoch() != accepted_policy.config_epoch {
        anyhow::bail!("accepted Skill policy changed during authority recovery");
    }
    let current = read_authenticated_current_anchor_for_publish(&store, skill_id, &key)?;
    if current
        .as_ref()
        .is_some_and(|(anchor, _)| anchor_matches_record(&anchor.anchor, latest))
    {
        require_authority_wal_head(home, latest)?;
        return Ok(None);
    }
    let recoverable = match current.as_ref() {
        None => chain.len() == 1,
        Some((anchor, _)) => chain
            .get(chain.len().saturating_sub(2))
            .is_some_and(|prior| anchor_matches_record(&anchor.anchor, prior)),
    };
    if !recoverable {
        anyhow::bail!("Skill authority chain has no single recoverable orphan tail");
    }
    sync_parent_directory(&record_directory, &record_directory_path)
        .context("reconfirm orphan Skill authority record durability")?;
    if reload.accepted_snapshot().epoch() != accepted_policy.config_epoch {
        anyhow::bail!("accepted Skill policy changed before authority recovery commit");
    }
    commit_authority_wal_head(home, &key, &latest.record, &latest.record_sha256)
        .context("commit recoverable Skill authority record to its independent WAL head")?;
    let mut receipt = publish_current_anchor(&store, &key, &latest.record, &latest.record_sha256)?;
    receipt.accepted_policy_current_at_return =
        reload.accepted_snapshot().epoch() == accepted_policy.config_epoch;
    Ok(Some(receipt))
}

/// Create the private authority directories without minting an authority
/// identity. The first explicit authority publication creates the dedicated
/// key while holding the authority lock.
pub fn initialize_authority_store(home: &Path) -> Result<()> {
    let store = open_authority_store_for_publish(home)?;
    let _guard = lock_authority_store(&store, true)?;
    sync_parent_directory(&store.root.dir, &store.root.display_path)?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn initialize_authority_key_for_test(home: &Path) -> Result<()> {
    let store = open_authority_store_for_publish(home)?;
    let _guard = lock_authority_store(&store, true)?;
    let _key = load_or_init_authority_key_checked(home)?;
    Ok(())
}

/// Publish one exact decision. The immutable record is synced first, the
/// monotonic authority WAL head advances second, and the independently
/// authenticated current anchor is published and synced last.
fn publish_authority_decision(
    home: &Path,
    record: &SkillAuthorityRecordV1,
) -> Result<SkillAuthorityReceipt> {
    publish_authority_decision_with_revision(home, record, false)
}

fn publish_authority_decision_with_revision(
    home: &Path,
    record: &SkillAuthorityRecordV1,
    force_new_revision: bool,
) -> Result<SkillAuthorityReceipt> {
    record.validate()?;
    let store = open_authority_store_for_publish(home)?;
    let _authority_guard = lock_authority_store(&store, true)?;
    harden_existing_authority_key_directory_for_publish(home)?;
    let key = load_or_init_authority_key_checked(home)?;
    let record_directory = open_record_namespace_for_publish(&store, &record.skill_id)?;
    let record_directory_path = store.records_path.join(&record.skill_id);
    let chain = load_authenticated_record_chain(
        &record_directory,
        &record_directory_path,
        &record.skill_id,
        &key,
    )
    .map_err(anyhow::Error::new)
    .context("validate Skill authority decision chain before publication")?;
    let current_anchor =
        read_authenticated_current_anchor_for_publish(&store, &record.skill_id, &key)?;
    match (chain.last(), current_anchor.as_ref()) {
        (None, None) => {
            if scan_authority_wal_head(home, &record.skill_id)
                .context("scan empty Skill authority WAL head")?
                .is_some()
            {
                anyhow::bail!("Skill authority files were rolled back behind their WAL head");
            }
        }
        (Some(latest), Some((anchor, anchor_bytes))) => {
            if !anchor_matches_record(&anchor.anchor, latest) {
                let prior = chain.get(chain.len().saturating_sub(2));
                if prior.is_some_and(|prior| anchor_matches_record(&anchor.anchor, prior))
                    && authority_decision_semantics_match(&latest.record, record)
                {
                    sync_parent_directory(&record_directory, &record_directory_path)
                        .context("reconfirm orphan Skill authority record durability")?;
                    commit_authority_wal_head(home, &key, &latest.record, &latest.record_sha256)
                        .context(
                            "commit orphan Skill authority record to its independent WAL head",
                        )?;
                    return publish_current_anchor(
                        &store,
                        &key,
                        &latest.record,
                        &latest.record_sha256,
                    )
                    .context("recover previously durable orphan Skill authority record");
                }
                anyhow::bail!(
                    "Skill authority current anchor is not the latest authenticated record"
                );
            }
            require_authority_wal_head(home, latest)?;
            if latest.record.state == SkillAuthorityState::Revoked
                && record.state != SkillAuthorityState::Revoked
                && authority_install_incarnation_matches(&latest.record, record)
            {
                anyhow::bail!(
                    "Skill authority is terminally revoked for this exact install incarnation; reinstall the package before reactivation"
                );
            }
            if !force_new_revision && authority_decision_semantics_match(&latest.record, record) {
                let record_sync = sync_parent_directory(&record_directory, &record_directory_path)
                    .context("reconfirm current Skill authority record durability")?;
                let anchor_sync = sync_parent_directory(&store.current, &store.current_path)
                    .context("reconfirm current Skill authority anchor durability")?;
                let durability = if matches!(
                    (record_sync, anchor_sync),
                    (
                        crate::skills::store::DirectorySyncOutcome::Confirmed,
                        crate::skills::store::DirectorySyncOutcome::Confirmed
                    )
                ) {
                    SkillAuthorityDurability::Confirmed
                } else {
                    SkillAuthorityDurability::NamespaceDurabilityUnsupported
                };
                return Ok(receipt_for_record(
                    &latest.record,
                    &latest.record_sha256,
                    &sha256_hex(anchor_bytes),
                    durability,
                ));
            }
        }
        (Some(latest), None)
            if chain.len() == 1 && authority_decision_semantics_match(&latest.record, record) =>
        {
            sync_parent_directory(&record_directory, &record_directory_path)
                .context("reconfirm first orphan Skill authority record durability")?;
            commit_authority_wal_head(home, &key, &latest.record, &latest.record_sha256).context(
                "commit first orphan Skill authority record to its independent WAL head",
            )?;
            return publish_current_anchor(&store, &key, &latest.record, &latest.record_sha256)
                .context("recover first durable orphan Skill authority record");
        }
        _ => anyhow::bail!(
            "Skill authority chain/current mismatch requires explicit recovery before publication"
        ),
    }
    if chain.len() >= MAX_AUTHORITY_RECORDS_PER_SKILL {
        anyhow::bail!(
            "Skill authority record quota reached; compact or archive this Skill's decision history"
        );
    }

    let mut persisted_record = record.clone();
    persisted_record.authority_sequence = u64::try_from(chain.len())
        .context("Skill authority chain length conversion")?
        .checked_add(1)
        .context("Skill authority sequence overflow")?;
    persisted_record.previous_record_sha256 = chain.last().map(|entry| entry.record_sha256.clone());
    persisted_record.validate()?;

    let record_bytes =
        canonical_json(&persisted_record).context("serialize Skill authority record")?;
    if record_bytes.len() > MAX_AUTHORITY_RECORD_BYTES {
        anyhow::bail!(
            "Skill authority record is {} bytes, exceeding the {}-byte limit",
            record_bytes.len(),
            MAX_AUTHORITY_RECORD_BYTES
        );
    }
    let record_sha256 = sha256_hex(&record_bytes);
    let authenticated_record = AuthenticatedAuthorityRecordV1 {
        envelope_version: SKILL_AUTHORITY_RECORD_VERSION,
        record_sha256: record_sha256.clone(),
        record: persisted_record.clone(),
        hmac_sha256: record_hmac(&key, &record_sha256, &record_bytes),
    };
    let authenticated_record_bytes =
        canonical_json(&authenticated_record).context("serialize authenticated Skill authority")?;
    if authenticated_record_bytes.len() > MAX_AUTHORITY_RECORD_BYTES {
        anyhow::bail!(
            "authenticated Skill authority record is {} bytes, exceeding the {}-byte limit",
            authenticated_record_bytes.len(),
            MAX_AUTHORITY_RECORD_BYTES
        );
    }
    let record_name = record_file_name(&record_sha256);
    publish_immutable_private_file(
        &record_directory,
        &record_directory_path,
        &record_name,
        &authenticated_record_bytes,
    )
    .context("durably publish immutable Skill authority record")?;

    commit_authority_wal_head(home, &key, &persisted_record, &record_sha256)
        .context("durably advance independent Skill authority WAL head")?;
    publish_current_anchor(&store, &key, &persisted_record, &record_sha256)
}

fn anchor_matches_record(anchor: &SkillCurrentAnchorV1, entry: &AuthenticatedRecordEntry) -> bool {
    anchor.skill_id == entry.record.skill_id
        && anchor.package_generation_sha256 == entry.record.package_generation_sha256
        && anchor.install_incarnation == entry.record.install_incarnation
        && anchor.install_terminal_receipt_sha256 == entry.record.install_terminal_receipt_sha256
        && anchor.authority_sequence == entry.record.authority_sequence
        && anchor.record_sha256 == entry.record_sha256
        && anchor.decision_id == entry.record.decision_id
        && anchor.state == entry.record.state
}

fn authority_decision_semantics_match(
    persisted: &SkillAuthorityRecordV1,
    requested: &SkillAuthorityRecordV1,
) -> bool {
    persisted.skill_id == requested.skill_id
        && persisted.package_generation_sha256 == requested.package_generation_sha256
        && persisted.manifest_sha256 == requested.manifest_sha256
        && persisted.install_incarnation == requested.install_incarnation
        && persisted.install_terminal_receipt_sha256 == requested.install_terminal_receipt_sha256
        && persisted.provenance == requested.provenance
        && persisted.decision_source == requested.decision_source
        && persisted.state == requested.state
        && persisted.decision_reason == requested.decision_reason
        && persisted.claims == requested.claims
}

fn authority_install_incarnation_matches(
    persisted: &SkillAuthorityRecordV1,
    requested: &SkillAuthorityRecordV1,
) -> bool {
    persisted.skill_id == requested.skill_id
        && persisted.package_generation_sha256 == requested.package_generation_sha256
        && persisted.install_incarnation == requested.install_incarnation
        && persisted.install_terminal_receipt_sha256 == requested.install_terminal_receipt_sha256
}

fn publish_current_anchor(
    store: &AuthorityStore,
    key: &[u8],
    record: &SkillAuthorityRecordV1,
    record_sha256: &str,
) -> Result<SkillAuthorityReceipt> {
    let anchor = SkillCurrentAnchorV1 {
        version: SKILL_CURRENT_ANCHOR_VERSION,
        skill_id: record.skill_id.clone(),
        package_generation_sha256: record.package_generation_sha256.clone(),
        install_incarnation: record.install_incarnation,
        install_terminal_receipt_sha256: record.install_terminal_receipt_sha256.clone(),
        authority_sequence: record.authority_sequence,
        record_sha256: record_sha256.to_string(),
        decision_id: record.decision_id.clone(),
        state: record.state,
    };
    validate_anchor_shape(&anchor)?;
    let anchor_bytes = canonical_json(&anchor).context("serialize Skill current anchor")?;
    let authenticated_anchor = AuthenticatedCurrentAnchorV1 {
        envelope_version: SKILL_CURRENT_ANCHOR_VERSION,
        hmac_sha256: domain_hmac(key, ANCHOR_HMAC_DOMAIN, &[&anchor_bytes]),
        anchor,
    };
    let authenticated_anchor_bytes =
        canonical_json(&authenticated_anchor).context("serialize authenticated current anchor")?;
    if authenticated_anchor_bytes.len() > MAX_CURRENT_ANCHOR_BYTES {
        anyhow::bail!(
            "Skill current anchor is {} bytes, exceeding the {}-byte limit",
            authenticated_anchor_bytes.len(),
            MAX_CURRENT_ANCHOR_BYTES
        );
    }
    let durability = publish_atomic_private_file(
        &store.current,
        &store.current_path,
        &current_anchor_file_name(&record.skill_id),
        &authenticated_anchor_bytes,
        true,
    )
    .context("publish Skill current anchor last")?;
    Ok(receipt_for_record(
        record,
        record_sha256,
        &sha256_hex(&authenticated_anchor_bytes),
        durability,
    ))
}

fn receipt_for_record(
    record: &SkillAuthorityRecordV1,
    record_sha256: &str,
    current_anchor_sha256: &str,
    durability: SkillAuthorityDurability,
) -> SkillAuthorityReceipt {
    SkillAuthorityReceipt {
        skill_id: record.skill_id.clone(),
        package_generation_sha256: record.package_generation_sha256.clone(),
        manifest_sha256: record.manifest_sha256.clone(),
        install_incarnation: record.install_incarnation,
        install_terminal_receipt_sha256: record.install_terminal_receipt_sha256.clone(),
        authority_sequence: record.authority_sequence,
        record_sha256: record_sha256.to_string(),
        current_anchor_sha256: current_anchor_sha256.to_string(),
        decision_id: record.decision_id.clone(),
        provenance: record.provenance,
        decision_source: record.decision_source,
        state: record.state,
        claims: record.claims.clone(),
        durability,
        accepted_policy_current_at_return: true,
    }
}

fn read_authenticated_current_anchor_for_publish(
    store: &AuthorityStore,
    skill_id: &str,
    key: &[u8],
) -> Result<Option<(AuthenticatedCurrentAnchorV1, Vec<u8>)>> {
    let anchor_name = current_anchor_file_name(skill_id);
    let anchor_path = store.current_path.join(&anchor_name);
    match store.current.symlink_metadata(&anchor_name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect Skill current anchor"),
        Ok(metadata) if !metadata.is_file() || cap_metadata_is_link_like(&metadata) => {
            anyhow::bail!("Skill current anchor is not a real regular file");
        }
        Ok(_) => {}
    }
    let bytes = read_private_regular_file(
        &store.current,
        &anchor_name,
        &anchor_path,
        MAX_CURRENT_ANCHOR_BYTES,
    )?;
    let envelope: AuthenticatedCurrentAnchorV1 =
        serde_json::from_slice(&bytes).context("parse Skill current anchor")?;
    if canonical_json(&envelope)? != bytes
        || envelope.envelope_version != SKILL_CURRENT_ANCHOR_VERSION
        || validate_anchor_shape(&envelope.anchor).is_err()
        || envelope.anchor.skill_id != skill_id
    {
        anyhow::bail!("Skill current anchor is invalid");
    }
    let canonical_anchor = canonical_json(&envelope.anchor)?;
    verify_domain_hmac(
        key,
        ANCHOR_HMAC_DOMAIN,
        &[&canonical_anchor],
        &envelope.hmac_sha256,
    )?;
    Ok(Some((envelope, bytes)))
}

/// Validate the exact current package at a runtime admission boundary. Every
/// failure becomes a typed inactive state; this function never initializes a
/// missing store or key.
fn validate_current_authority(
    home: &Path,
    expected: &SkillAuthorityExpectation,
) -> SkillAuthorityValidation {
    if expected.validate().is_err() {
        return SkillAuthorityValidation::Inactive(
            SkillAuthorityInactiveReason::ExpectationInvalid,
        );
    }
    match validate_current_authority_inner(home, expected) {
        Ok(authority) => SkillAuthorityValidation::Active(Box::new(authority)),
        Err(reason) => SkillAuthorityValidation::Inactive(reason),
    }
}

enum InstalledSnapshotFailure {
    Missing,
    PinnedHashMismatch,
    IncarnationInvalid,
    AggregateTraversal(anyhow::Error),
    Invalid(anyhow::Error),
}

fn bind_installed_authority_snapshot(
    skills_dir: &Path,
    skill_id: &str,
    accepted_policy: &AcceptedSkillPolicySnapshot,
) -> std::result::Result<BoundInstalledAuthoritySnapshot, InstalledSnapshotFailure> {
    super::creator::validate_skill_id(skill_id)
        .context("invalid installed Skill authority id")
        .map_err(InstalledSnapshotFailure::Invalid)?;
    let root = open_bound_directory(skills_dir, false, "installed Skills root")
        .map_err(InstalledSnapshotFailure::Invalid)?
        .ok_or(InstalledSnapshotFailure::Missing)?;
    let mutation_guard = super::installer::lock_skill_mutations(&root)
        .context("lock installed Skill package for authority snapshot")
        .map_err(InstalledSnapshotFailure::Invalid)?;
    super::installer::recover_pending_transactions_locked(&root)
        .context("recover installed Skill mutations before authority snapshot")
        .map_err(InstalledSnapshotFailure::Invalid)?;
    let install_incarnations = super::mutation_lifecycle::scan_skill_install_incarnation_index(
        skills_dir
            .parent()
            .ok_or_else(|| anyhow::anyhow!("installed Skills root has no instance-home parent"))
            .map_err(InstalledSnapshotFailure::Invalid)?,
    )
    .context("index installed Skill incarnations for authority snapshot")
    .map_err(InstalledSnapshotFailure::Invalid)?;
    let mut traversal_budget = super::installer::RuntimeAuthorityTraversalBudget::new();
    let snapshot = inspect_installed_authority_snapshot_locked(
        &root,
        skill_id,
        accepted_policy,
        &install_incarnations,
        &mut traversal_budget,
    )?;
    Ok(BoundInstalledAuthoritySnapshot {
        expectation: snapshot.expectation,
        effective_enabled: snapshot.effective_enabled,
        effective_manifest: snapshot.effective_manifest,
        _mutation_guard: mutation_guard,
        _skill_directory: snapshot.skill_directory,
        _skills_root: root,
    })
}

fn inspect_installed_authority_snapshot_locked(
    root: &BoundDirectory,
    skill_id: &str,
    accepted_policy: &AcceptedSkillPolicySnapshot,
    install_incarnations: &super::mutation_lifecycle::SkillInstallIncarnationIndex,
    traversal_budget: &mut super::installer::RuntimeAuthorityTraversalBudget,
) -> std::result::Result<InstalledAuthoritySnapshot, InstalledSnapshotFailure> {
    super::creator::validate_skill_id(skill_id)
        .context("invalid installed Skill authority id")
        .map_err(InstalledSnapshotFailure::Invalid)?;
    let skill_name = OsStr::new(skill_id);
    let skill_path = root.display_path.join(skill_name);
    match root.dir.symlink_metadata(skill_name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(InstalledSnapshotFailure::Missing);
        }
        Err(error) => {
            return Err(InstalledSnapshotFailure::Invalid(
                anyhow::Error::new(error).context("inspect installed Skill authority package"),
            ));
        }
        Ok(metadata) if !metadata.is_dir() || cap_metadata_is_link_like(&metadata) => {
            return Err(InstalledSnapshotFailure::Invalid(anyhow::anyhow!(
                "installed Skill authority package is not a real directory"
            )));
        }
        Ok(_) => {}
    }
    let skill_directory = open_real_child_dir(&root.dir, skill_name, &skill_path)
        .context("open installed Skill authority package")
        .map_err(InstalledSnapshotFailure::Invalid)?;
    let tree_snapshot = super::installer::capture_installed_skill_authority_tree_snapshot(
        &skill_directory,
        &skill_path,
        traversal_budget,
    )
    .context("capture installed Skill authority package")
    .map_err(|error| {
        if super::installer::is_runtime_authority_traversal_limit(&error) {
            InstalledSnapshotFailure::AggregateTraversal(error)
        } else {
            InstalledSnapshotFailure::Invalid(error)
        }
    })?;
    let manifest_bytes = tree_snapshot.manifest_bytes;
    if manifest_bytes.len() > MAX_INSTALLED_MANIFEST_BYTES {
        return Err(InstalledSnapshotFailure::Invalid(anyhow::anyhow!(
            "installed Skill authority manifest exceeds the {MAX_INSTALLED_MANIFEST_BYTES}-byte limit"
        )));
    }
    let manifest_text = std::str::from_utf8(&manifest_bytes)
        .context("installed Skill authority manifest is not UTF-8")
        .map_err(InstalledSnapshotFailure::Invalid)?;
    let mut manifest: SkillManifest = serde_yaml::from_str(manifest_text)
        .context("parse installed Skill authority manifest")
        .map_err(InstalledSnapshotFailure::Invalid)?;
    if manifest.id.is_empty() || manifest.id != skill_id {
        return Err(InstalledSnapshotFailure::Invalid(anyhow::anyhow!(
            "installed Skill manifest id does not match its canonical directory"
        )));
    }
    if manifest.description.trim().is_empty() {
        return Err(InstalledSnapshotFailure::Invalid(anyhow::anyhow!(
            "installed Skill description must not be empty"
        )));
    }
    super::creator::validate_skill_id(&manifest.id)
        .context("validate installed Skill manifest id")
        .map_err(InstalledSnapshotFailure::Invalid)?;
    manifest.trigger_keywords = manifest
        .trigger_keywords
        .into_iter()
        .map(|keyword| keyword.trim().to_lowercase())
        .filter(|keyword| !keyword.is_empty())
        .collect();
    let content_hash =
        crate::skills::versioning::skill_content_hash_hex(manifest_text, &manifest.system_prompt);
    if accepted_policy
        .skills
        .pinned_hashes
        .get(skill_id)
        .is_some_and(|expected| expected != &content_hash)
    {
        return Err(InstalledSnapshotFailure::PinnedHashMismatch);
    }
    let package_generation_sha256 = tree_snapshot.generation_sha256;
    let install_proof = install_incarnations
        .authenticate_current(skill_id, &package_generation_sha256)
        .map_err(|_| InstalledSnapshotFailure::IncarnationInvalid)?;
    if install_proof.skill_id() != skill_id
        || install_proof.package_generation_sha256() != package_generation_sha256
    {
        return Err(InstalledSnapshotFailure::IncarnationInvalid);
    }
    let provenance = provenance_from_install_origin(install_proof.origin())
        .map_err(InstalledSnapshotFailure::Invalid)?;
    let manifest_sha256 = manifest_sha256(&manifest_bytes);
    super::loader::SkillPolicy::from_config(&accepted_policy.skills)
        .apply_to_manifest(&mut manifest);
    let effective_enabled = manifest.enabled;
    let policy_sha256 = effective_skill_policy_sha256(&accepted_policy.skills, skill_id)
        .context("hash accepted per-Skill policy binding")
        .map_err(InstalledSnapshotFailure::Invalid)?;
    let claims = SkillBehaviorClaimsV1::from_effective_manifest(&manifest, policy_sha256)
        .context("validate installed Skill effective behavior claims")
        .map_err(InstalledSnapshotFailure::Invalid)?;
    let expectation = SkillAuthorityExpectation {
        skill_id: skill_id.to_string(),
        package_generation_sha256,
        manifest_sha256,
        install_incarnation: install_proof.install_incarnation(),
        install_terminal_receipt_sha256: install_proof.terminal_receipt_sha256().to_string(),
        provenance,
        claims,
    };
    expectation
        .validate()
        .context("validate installed Skill authority expectation")
        .map_err(InstalledSnapshotFailure::Invalid)?;
    Ok(InstalledAuthoritySnapshot {
        expectation,
        effective_enabled,
        effective_manifest: manifest,
        skill_directory,
    })
}

fn validate_current_authority_inner(
    home: &Path,
    expected: &SkillAuthorityExpectation,
) -> std::result::Result<ValidatedSkillAuthority, SkillAuthorityInactiveReason> {
    validate_current_authority_inner_with_heads(home, expected, None, None)
}

fn validate_current_authority_inner_with_heads(
    home: &Path,
    expected: &SkillAuthorityExpectation,
    authority_wal_heads: Option<&BTreeMap<String, AuthenticatedSkillAuthorityWalHead>>,
    traversal_budget: Option<&mut super::installer::RuntimeAuthorityTraversalBudget>,
) -> std::result::Result<ValidatedSkillAuthority, SkillAuthorityInactiveReason> {
    let store = open_existing_authority_store(home)?;
    let _authority_guard = lock_authority_store(&store, false)
        .map_err(|_| SkillAuthorityInactiveReason::AuthorityStoreInvalid)?;
    let key = load_existing_authority_key(home)?;

    let anchor_name = current_anchor_file_name(&expected.skill_id);
    let anchor_bytes = read_required_private_file(
        &store.current,
        &anchor_name,
        &store.current_path.join(&anchor_name),
        MAX_CURRENT_ANCHOR_BYTES,
        SkillAuthorityInactiveReason::CurrentAnchorMissing,
        SkillAuthorityInactiveReason::CurrentAnchorInvalid,
    )?;
    let authenticated_anchor: AuthenticatedCurrentAnchorV1 = serde_json::from_slice(&anchor_bytes)
        .map_err(|_| SkillAuthorityInactiveReason::CurrentAnchorInvalid)?;
    if canonical_json(&authenticated_anchor)
        .map_err(|_| SkillAuthorityInactiveReason::CurrentAnchorInvalid)?
        != anchor_bytes
        || authenticated_anchor.envelope_version != SKILL_CURRENT_ANCHOR_VERSION
        || validate_anchor_shape(&authenticated_anchor.anchor).is_err()
    {
        return Err(SkillAuthorityInactiveReason::CurrentAnchorInvalid);
    }
    let canonical_anchor = canonical_json(&authenticated_anchor.anchor)
        .map_err(|_| SkillAuthorityInactiveReason::CurrentAnchorInvalid)?;
    verify_domain_hmac(
        &key,
        ANCHOR_HMAC_DOMAIN,
        &[&canonical_anchor],
        &authenticated_anchor.hmac_sha256,
    )
    .map_err(|_| SkillAuthorityInactiveReason::CurrentAnchorMacInvalid)?;
    let anchor = &authenticated_anchor.anchor;
    if anchor.skill_id != expected.skill_id {
        return Err(SkillAuthorityInactiveReason::CurrentAnchorMismatch);
    }
    if anchor.package_generation_sha256 != expected.package_generation_sha256 {
        return Err(SkillAuthorityInactiveReason::PackageGenerationMismatch);
    }
    if anchor.install_incarnation != expected.install_incarnation
        || anchor.install_terminal_receipt_sha256 != expected.install_terminal_receipt_sha256
    {
        return Err(SkillAuthorityInactiveReason::InstallIncarnationMismatch);
    }

    let record_directory = open_existing_record_namespace(&store, &expected.skill_id)?;
    let record_directory_path = store.records_path.join(&expected.skill_id);
    let chain = match traversal_budget {
        Some(budget) => load_authenticated_record_chain_with_budget(
            &record_directory,
            &record_directory_path,
            &expected.skill_id,
            &key,
            budget,
        ),
        None => load_authenticated_record_chain(
            &record_directory,
            &record_directory_path,
            &expected.skill_id,
            &key,
        ),
    }
    .map_err(|failure| match failure {
        RecordChainFailure::NamespaceLimit => {
            SkillAuthorityInactiveReason::AuthorityNamespaceLimitExceeded
        }
        RecordChainFailure::Invalid => SkillAuthorityInactiveReason::AuthorityRecordInvalid,
        RecordChainFailure::DigestMismatch => {
            SkillAuthorityInactiveReason::AuthorityRecordDigestMismatch
        }
        RecordChainFailure::MacInvalid => SkillAuthorityInactiveReason::AuthorityRecordMacInvalid,
        RecordChainFailure::AggregateTraversal(_) => {
            SkillAuthorityInactiveReason::AuthorityRecordInvalid
        }
    })?;
    let latest = chain
        .last()
        .ok_or(SkillAuthorityInactiveReason::AuthorityRecordMissing)?;
    let authority_wal_head = match authority_wal_heads {
        Some(heads) => heads
            .get(&expected.skill_id)
            .cloned()
            .ok_or(SkillAuthorityInactiveReason::AuthorityWalHeadMissing)?,
        None => scan_authority_wal_head(home, &expected.skill_id)
            .map_err(|_| SkillAuthorityInactiveReason::AuthorityWalHeadInvalid)?
            .ok_or(SkillAuthorityInactiveReason::AuthorityWalHeadMissing)?,
    };
    if !authority_wal_head_matches_record(
        &authority_wal_head,
        &latest.record,
        &latest.record_sha256,
    ) {
        return Err(SkillAuthorityInactiveReason::AuthorityWalHeadMismatch);
    }
    if latest.record_sha256 != anchor.record_sha256
        || latest.record.authority_sequence != anchor.authority_sequence
    {
        return Err(SkillAuthorityInactiveReason::CurrentAnchorMismatch);
    }

    let actual_record_sha256 = latest.record_sha256.clone();
    let record = latest.record.clone();
    if record.skill_id != anchor.skill_id
        || record.decision_id != anchor.decision_id
        || record.state != anchor.state
        || record.authority_sequence != anchor.authority_sequence
    {
        return Err(SkillAuthorityInactiveReason::CurrentAnchorMismatch);
    }
    if record.package_generation_sha256 != expected.package_generation_sha256 {
        return Err(SkillAuthorityInactiveReason::PackageGenerationMismatch);
    }
    if record.install_incarnation != expected.install_incarnation
        || record.install_terminal_receipt_sha256 != expected.install_terminal_receipt_sha256
        || record.provenance != expected.provenance
    {
        return Err(SkillAuthorityInactiveReason::InstallIncarnationMismatch);
    }
    if record.manifest_sha256 != expected.manifest_sha256 {
        return Err(SkillAuthorityInactiveReason::ManifestDigestMismatch);
    }
    // A valid exact-package deny is authoritative even when the accepted
    // behavior policy moved after it was written. Inactive/Revoked must shadow
    // any same-id bundled fallback; only Active decisions need their behavior
    // claims to match before code can execute.
    match record.state {
        SkillAuthorityState::Inactive => {
            return Err(SkillAuthorityInactiveReason::DecisionInactive);
        }
        SkillAuthorityState::Revoked => {
            return Err(SkillAuthorityInactiveReason::DecisionRevoked);
        }
        SkillAuthorityState::Active => {}
    }
    if record.claims != expected.claims {
        return Err(SkillAuthorityInactiveReason::BehaviorClaimsMismatch);
    }
    Ok(ValidatedSkillAuthority {
        record,
        record_sha256: actual_record_sha256,
        current_anchor_sha256: sha256_hex(&anchor_bytes),
    })
}

fn open_existing_authority_store(
    home: &Path,
) -> std::result::Result<AuthorityStore, SkillAuthorityInactiveReason> {
    let root_path = authority_root(home);
    let root = open_bound_directory(&root_path, false, "Skill authority root")
        .map_err(|_| SkillAuthorityInactiveReason::AuthorityStoreInvalid)?
        .ok_or(SkillAuthorityInactiveReason::AuthorityStoreMissing)?;
    ensure_private_directory(&root.dir, &root.display_path)
        .map_err(|_| SkillAuthorityInactiveReason::AuthorityStoreInvalid)?;
    validate_authority_root_entries(&root).map_err(map_namespace_validation_reason)?;

    let records_path = root.display_path.join(AUTHORITY_RECORDS_NAME);
    let current_path = root.display_path.join(AUTHORITY_CURRENT_NAME);
    let records = open_real_child_dir(&root.dir, OsStr::new(AUTHORITY_RECORDS_NAME), &records_path)
        .map_err(|_| SkillAuthorityInactiveReason::AuthorityStoreInvalid)?;
    let current = open_real_child_dir(&root.dir, OsStr::new(AUTHORITY_CURRENT_NAME), &current_path)
        .map_err(|_| SkillAuthorityInactiveReason::AuthorityStoreInvalid)?;
    ensure_private_directory(&records, &records_path)
        .map_err(|_| SkillAuthorityInactiveReason::AuthorityStoreInvalid)?;
    ensure_private_directory(&current, &current_path)
        .map_err(|_| SkillAuthorityInactiveReason::AuthorityStoreInvalid)?;
    Ok(AuthorityStore {
        root,
        records,
        current,
        records_path,
        current_path,
    })
}

fn open_authority_store_for_publish(home: &Path) -> Result<AuthorityStore> {
    let root_path = authority_root(home);
    let trusted_anchor = home.parent().unwrap_or(home);
    let root = match open_bound_directory_from_trusted_anchor(
        trusted_anchor,
        &root_path,
        false,
        "Skill authority root",
    )? {
        Some(root) => {
            ensure_private_directory(&root.dir, &root.display_path)?;
            root
        }
        None => {
            let root = open_bound_directory_from_trusted_anchor(
                trusted_anchor,
                &root_path,
                true,
                "Skill authority root",
            )?
            .context("new Skill authority root disappeared")?;
            secure_new_private_directory(&root.dir, &root.display_path)?;
            root
        }
    };
    validate_authority_root_entries_for_publish(&root)?;
    let records_path = root.display_path.join(AUTHORITY_RECORDS_NAME);
    let current_path = root.display_path.join(AUTHORITY_CURRENT_NAME);
    let records =
        open_or_create_private_child(&root.dir, OsStr::new(AUTHORITY_RECORDS_NAME), &records_path)?;
    let current =
        open_or_create_private_child(&root.dir, OsStr::new(AUTHORITY_CURRENT_NAME), &current_path)?;
    validate_authority_root_entries_for_publish(&root)?;
    Ok(AuthorityStore {
        root,
        records,
        current,
        records_path,
        current_path,
    })
}

fn open_record_namespace_for_publish(store: &AuthorityStore, skill_id: &str) -> Result<Dir> {
    super::creator::validate_skill_id(skill_id)?;
    let path = store.records_path.join(skill_id);
    open_or_create_private_child(&store.records, OsStr::new(skill_id), &path)
}

fn open_existing_record_namespace(
    store: &AuthorityStore,
    skill_id: &str,
) -> std::result::Result<Dir, SkillAuthorityInactiveReason> {
    let path = store.records_path.join(skill_id);
    match store.records.symlink_metadata(skill_id) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(SkillAuthorityInactiveReason::AuthorityRecordMissing)
        }
        Err(_) => Err(SkillAuthorityInactiveReason::AuthorityRecordInvalid),
        Ok(metadata) if !metadata.is_dir() || cap_metadata_is_link_like(&metadata) => {
            Err(SkillAuthorityInactiveReason::AuthorityRecordInvalid)
        }
        Ok(_) => {
            let directory = open_real_child_dir(&store.records, OsStr::new(skill_id), &path)
                .map_err(|_| SkillAuthorityInactiveReason::AuthorityRecordInvalid)?;
            ensure_private_directory(&directory, &path)
                .map_err(|_| SkillAuthorityInactiveReason::AuthorityRecordInvalid)?;
            Ok(directory)
        }
    }
}

fn open_or_create_private_child(parent: &Dir, name: &OsStr, path: &Path) -> Result<Dir> {
    match parent.open_dir_nofollow(name) {
        Ok(dir) => {
            ensure_private_directory(&dir, path)?;
            Ok(dir)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Err(create_error) = create_private_directory(parent, name, path) {
                // Another cooperating process may have created the same
                // fixed child after our no-follow lookup. Accept it only
                // after the normal real-directory and privacy proofs.
                let raced = parent.open_dir_nofollow(name).with_context(|| {
                    format!(
                        "create private Skill authority directory {} failed: {create_error}",
                        path.display()
                    )
                })?;
                ensure_private_directory(&raced, path)?;
                return Ok(raced);
            }
            let dir = open_real_child_dir(parent, name, path)?;
            secure_new_private_directory(&dir, path)?;
            Ok(dir)
        }
        Err(error) => Err(error)
            .with_context(|| format!("open private Skill authority directory {}", path.display())),
    }
}

fn create_private_directory(parent: &Dir, name: &OsStr, path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use cap_std::fs::DirBuilderExt as _;
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        parent.create_dir_with(name, &builder).with_context(|| {
            format!(
                "create private Skill authority directory {}",
                path.display()
            )
        })
    }
    #[cfg(windows)]
    {
        let _ = (parent, name);
        crate::wal::win_native::create_private_directory_new(path).with_context(|| {
            format!(
                "atomically create private Skill authority directory {}",
                path.display()
            )
        })
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        parent.create_dir(name).with_context(|| {
            format!(
                "create private Skill authority directory {}",
                path.display()
            )
        })
    }
}

fn secure_new_private_directory(directory: &Dir, path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt as _;
        directory
            .set_permissions(".", cap_std::fs::Permissions::from_mode(0o700))
            .with_context(|| {
                format!(
                    "set private permissions on Skill authority directory {}",
                    path.display()
                )
            })?;
    }
    #[cfg(windows)]
    {
        crate::wal::win_native::set_private_current_user_directory_dacl_bound(path, directory)
            .with_context(|| {
                format!(
                    "set private DACL on bound Skill authority directory {}",
                    path.display()
                )
            })?;
    }
    ensure_private_directory(directory, path)
}

fn ensure_private_directory(directory: &Dir, path: &Path) -> Result<()> {
    let metadata = directory
        .dir_metadata()
        .with_context(|| format!("inspect Skill authority directory {}", path.display()))?;
    if !metadata.is_dir() || cap_metadata_is_link_like(&metadata) {
        anyhow::bail!(
            "Skill authority directory must be a real directory: {}",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt as _;
        if metadata.mode() & 0o7777 != 0o700 {
            anyhow::bail!(
                "Skill authority directory must have mode 0700: {}",
                path.display()
            );
        }
        if metadata.uid() != effective_uid() {
            anyhow::bail!(
                "Skill authority directory is not owned by the effective user: {}",
                path.display()
            );
        }
    }
    #[cfg(windows)]
    {
        crate::wal::win_native::verify_private_directory_handle_dacl(directory).with_context(
            || {
                format!(
                    "verify private DACL on bound Skill authority directory {}",
                    path.display()
                )
            },
        )?;
    }
    Ok(())
}

fn load_existing_authority_key_checked(home: &Path) -> Result<Zeroizing<Vec<u8>>> {
    match load_existing_authority_key(home) {
        Ok(key) => Ok(key),
        Err(SkillAuthorityInactiveReason::AuthorityKeyMissing) => {
            anyhow::bail!("Skill authority requires its existing dedicated authority key")
        }
        Err(_) => anyhow::bail!("existing dedicated authority key is not valid Skill authority"),
    }
}

fn load_or_init_authority_key_checked(home: &Path) -> Result<Zeroizing<Vec<u8>>> {
    match load_existing_authority_key(home) {
        Ok(key) => Ok(key),
        Err(SkillAuthorityInactiveReason::AuthorityKeyMissing) => {
            let key_path = authority_root(home).join(AUTHORITY_KEY_NAME);
            let generated = Zeroizing::new(
                crate::wal::compaction::load_or_init_key(&key_path)
                    .context("create dedicated Skill authority key")?,
            );
            drop(generated);
            load_existing_authority_key_checked(home)
        }
        Err(_) => anyhow::bail!("existing dedicated authority key is not valid Skill authority"),
    }
}

fn harden_existing_authority_key_directory_for_publish(home: &Path) -> Result<()> {
    let wal_path = home.join(WAL_DIRECTORY_NAME);
    let wal = open_bound_directory(&wal_path, false, "WAL key directory")?
        .context("Skill authority requires an existing WAL key directory")?;
    let metadata = wal
        .dir
        .dir_metadata()
        .with_context(|| format!("inspect WAL key directory {}", wal.display_path.display()))?;
    if !metadata.is_dir() || cap_metadata_is_link_like(&metadata) {
        anyhow::bail!("WAL key directory must be a real directory");
    }
    #[cfg(unix)]
    {
        use cap_std::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != effective_uid() {
            anyhow::bail!("refuse to harden a WAL key directory owned by another user");
        }
        wal.dir
            .set_permissions(".", cap_std::fs::Permissions::from_mode(0o700))
            .with_context(|| {
                format!(
                    "set private mode on WAL key directory {}",
                    wal.display_path.display()
                )
            })?;
    }
    #[cfg(windows)]
    crate::wal::win_native::set_private_current_user_directory_dacl_bound(
        &wal.display_path,
        &wal.dir,
    )
    .with_context(|| {
        format!(
            "set private DACL on bound WAL key directory {}",
            wal.display_path.display()
        )
    })?;
    ensure_private_directory(&wal.dir, &wal.display_path)
}

fn load_existing_authority_key(
    home: &Path,
) -> std::result::Result<Zeroizing<Vec<u8>>, SkillAuthorityInactiveReason> {
    let root_path = authority_root(home);
    let root = open_bound_directory(&root_path, false, "Skill authority root")
        .map_err(|_| SkillAuthorityInactiveReason::AuthorityKeyInvalid)?
        .ok_or(SkillAuthorityInactiveReason::AuthorityKeyMissing)?;
    ensure_private_directory(&root.dir, &root.display_path)
        .map_err(|_| SkillAuthorityInactiveReason::AuthorityKeyInvalid)?;
    let key_name = OsStr::new(AUTHORITY_KEY_NAME);
    let key_path = root.display_path.join(key_name);
    let bytes = read_required_private_file(
        &root.dir,
        key_name,
        &key_path,
        MAX_AUTHORITY_KEY_BYTES,
        SkillAuthorityInactiveReason::AuthorityKeyMissing,
        SkillAuthorityInactiveReason::AuthorityKeyInvalid,
    )?;
    crate::wal::compaction::decode_existing_key(&bytes, &key_path)
        .map(Zeroizing::new)
        .map_err(|_| SkillAuthorityInactiveReason::AuthorityKeyInvalid)
}

fn map_namespace_validation_reason(error: anyhow::Error) -> SkillAuthorityInactiveReason {
    if error.chain().any(|cause| {
        cause
            .downcast_ref::<AuthorityNamespaceLimitExceeded>()
            .is_some()
    }) {
        SkillAuthorityInactiveReason::AuthorityNamespaceLimitExceeded
    } else {
        SkillAuthorityInactiveReason::AuthorityStoreInvalid
    }
}

fn validate_authority_root_entries_for_publish(root: &BoundDirectory) -> Result<()> {
    validate_authority_root_entries(root)
}

fn validate_authority_root_entries(root: &BoundDirectory) -> Result<()> {
    let entries = root.dir.entries().with_context(|| {
        format!(
            "enumerate Skill authority root {}",
            root.display_path.display()
        )
    })?;
    let mut count = 0usize;
    for entry in entries {
        count = count
            .checked_add(1)
            .context("Skill authority root entry counter overflow")?;
        if count > MAX_AUTHORITY_ROOT_ENTRIES {
            return Err(AuthorityNamespaceLimitExceeded.into());
        }
        let entry = entry.context("read Skill authority root entry")?;
        let name = entry.file_name();
        if name == OsStr::new(AUTHORITY_LOCK_NAME) {
            verify_private_regular_entry(
                &root.dir,
                &name,
                &root.display_path.join(AUTHORITY_LOCK_NAME),
            )?;
            continue;
        }
        if name == OsStr::new(AUTHORITY_KEY_NAME) {
            verify_private_regular_entry(
                &root.dir,
                &name,
                &root.display_path.join(AUTHORITY_KEY_NAME),
            )?;
            continue;
        }
        if name != OsStr::new(AUTHORITY_RECORDS_NAME) && name != OsStr::new(AUTHORITY_CURRENT_NAME)
        {
            anyhow::bail!("unexpected entry in private Skill authority root");
        }
        let metadata = root
            .dir
            .symlink_metadata(&name)
            .context("inspect Skill authority root entry")?;
        if !metadata.is_dir() || cap_metadata_is_link_like(&metadata) {
            anyhow::bail!("Skill authority root entry is linked or not a directory");
        }
    }
    Ok(())
}

fn lock_authority_store(store: &AuthorityStore, create: bool) -> Result<AuthorityStoreGuard> {
    let started = std::time::Instant::now();
    let path = store.root.display_path.join(AUTHORITY_LOCK_NAME);
    loop {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(create)
            .follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        #[cfg(windows)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            const FILE_SHARE_READ: u32 = 0x0000_0001;
            options.share_mode(FILE_SHARE_READ);
        }
        let file = match store.root.dir.open_with(AUTHORITY_LOCK_NAME, &options) {
            Ok(file) => file,
            #[cfg(windows)]
            Err(error) if error.raw_os_error() == Some(32) => {
                if started.elapsed() >= std::time::Duration::from_secs(5) {
                    anyhow::bail!("Skill authority lock held for more than five seconds");
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("open Skill authority lock {}", path.display()));
            }
        };
        #[cfg(windows)]
        if create {
            crate::wal::win_native::set_private_current_user_dacl(&path)
                .with_context(|| format!("set private DACL on {}", path.display()))?;
        }
        verify_private_regular_file(&file, &path)?;
        let file = file.into_std();
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd as _;
            // SAFETY: flock receives a live owned regular-file descriptor.
            let status = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if status != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::WouldBlock
                    && started.elapsed() < std::time::Duration::from_secs(5)
                {
                    drop(file);
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    continue;
                }
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    anyhow::bail!("Skill authority lock held for more than five seconds");
                }
                return Err(error).context("lock Skill authority store");
            }
        }
        return Ok(AuthorityStoreGuard { _file: file });
    }
}

#[cfg(test)]
fn scan_namespace_with_limit(directory: &Dir, display_path: &Path, limit: usize) -> Result<()> {
    let entries = directory.entries().with_context(|| {
        format!(
            "enumerate Skill authority namespace {}",
            display_path.display()
        )
    })?;
    let mut count = 0usize;
    for entry in entries {
        count = count
            .checked_add(1)
            .context("Skill authority namespace entry counter overflow")?;
        if count > limit {
            return Err(AuthorityNamespaceLimitExceeded.into());
        }
        let entry = entry.context("read Skill authority namespace entry")?;
        let name = entry.file_name();
        let name_text = name
            .to_str()
            .context("Skill authority namespace name is not UTF-8")?;
        let valid_name = valid_stage_name(name_text) || valid_record_file_name(name_text);
        if !valid_name {
            anyhow::bail!("unexpected file in private Skill authority namespace");
        }
        verify_private_regular_entry(directory, &name, &display_path.join(&name))?;
    }
    Ok(())
}

fn load_authenticated_record_chain(
    directory: &Dir,
    display_path: &Path,
    skill_id: &str,
    key: &[u8],
) -> std::result::Result<Vec<AuthenticatedRecordEntry>, RecordChainFailure> {
    let mut budget = super::installer::RuntimeAuthorityTraversalBudget::unbounded_for_internal();
    load_authenticated_record_chain_with_budget(directory, display_path, skill_id, key, &mut budget)
}

fn load_authenticated_record_chain_with_budget(
    directory: &Dir,
    display_path: &Path,
    skill_id: &str,
    key: &[u8],
    budget: &mut super::installer::RuntimeAuthorityTraversalBudget,
) -> std::result::Result<Vec<AuthenticatedRecordEntry>, RecordChainFailure> {
    let entries = directory
        .entries()
        .map_err(|_| RecordChainFailure::Invalid)?;
    let mut chain = Vec::new();
    let mut entry_count = 0usize;
    for entry in entries {
        budget
            .observe_entry()
            .map_err(RecordChainFailure::AggregateTraversal)?;
        let entry = entry.map_err(|_| RecordChainFailure::Invalid)?;
        entry_count = entry_count
            .checked_add(1)
            .ok_or(RecordChainFailure::Invalid)?;
        if entry_count > MAX_AUTHORITY_RECORDS_PER_SKILL {
            return Err(RecordChainFailure::NamespaceLimit);
        }
        let name = entry.file_name();
        let name_text = name.to_str().ok_or(RecordChainFailure::Invalid)?;
        if !valid_stage_name(name_text) && !valid_record_file_name(name_text) {
            return Err(RecordChainFailure::Invalid);
        }
        if valid_stage_name(name_text) {
            verify_private_regular_entry(directory, &name, &display_path.join(&name))
                .map_err(|_| RecordChainFailure::Invalid)?;
            continue;
        }
        let bytes = read_private_regular_file_observed(
            directory,
            &name,
            &display_path.join(&name),
            MAX_AUTHORITY_RECORD_BYTES,
            |bytes| budget.observe_bytes(bytes),
        )
        .map_err(|error| {
            if super::installer::is_runtime_authority_traversal_limit(&error) {
                RecordChainFailure::AggregateTraversal(error)
            } else {
                RecordChainFailure::Invalid
            }
        })?;
        let envelope: AuthenticatedAuthorityRecordV1 =
            serde_json::from_slice(&bytes).map_err(|_| RecordChainFailure::Invalid)?;
        if canonical_json(&envelope).map_err(|_| RecordChainFailure::Invalid)? != bytes
            || envelope.envelope_version != SKILL_AUTHORITY_RECORD_VERSION
            || envelope.record.validate().is_err()
            || envelope.record.skill_id != skill_id
        {
            return Err(RecordChainFailure::Invalid);
        }
        let canonical_record =
            canonical_json(&envelope.record).map_err(|_| RecordChainFailure::Invalid)?;
        let actual_digest = sha256_hex(&canonical_record);
        if envelope.record_sha256 != actual_digest || name != record_file_name(&actual_digest) {
            return Err(RecordChainFailure::DigestMismatch);
        }
        verify_record_hmac(
            key,
            &envelope.record_sha256,
            &canonical_record,
            &envelope.hmac_sha256,
        )
        .map_err(|_| RecordChainFailure::MacInvalid)?;
        chain.push(AuthenticatedRecordEntry {
            record: envelope.record,
            record_sha256: actual_digest,
        });
    }
    chain.sort_by_key(|entry| entry.record.authority_sequence);
    let mut expected_sequence = 1_u64;
    let mut predecessor: Option<&str> = None;
    for entry in &chain {
        if entry.record.authority_sequence != expected_sequence
            || entry.record.previous_record_sha256.as_deref() != predecessor
        {
            return Err(RecordChainFailure::Invalid);
        }
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(RecordChainFailure::Invalid)?;
        predecessor = Some(&entry.record_sha256);
    }
    Ok(chain)
}

fn verify_private_regular_entry(parent: &Dir, name: &OsStr, path: &Path) -> Result<()> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = parent
        .open_with(name, &options)
        .with_context(|| format!("open private Skill authority file {}", path.display()))?;
    verify_private_regular_file(&file, path)
}

fn verify_private_regular_file(file: &cap_std::fs::File, path: &Path) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect private Skill authority file {}", path.display()))?;
    if !metadata.is_file() || cap_metadata_is_link_like(&metadata) {
        anyhow::bail!(
            "Skill authority entry must be a real regular file: {}",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt as _;
        if metadata.mode() & 0o7777 != 0o600 {
            anyhow::bail!(
                "Skill authority file must have mode 0600: {}",
                path.display()
            );
        }
        if metadata.uid() != effective_uid() {
            anyhow::bail!(
                "Skill authority file is not owned by the effective user: {}",
                path.display()
            );
        }
    }
    #[cfg(windows)]
    {
        let clone = file
            .try_clone()
            .with_context(|| format!("clone private authority handle {}", path.display()))?
            .into_std();
        crate::wal::win_native::verify_private_file_handle(&clone)
            .with_context(|| format!("verify private DACL on {}", path.display()))?;
    }
    Ok(())
}

fn read_required_private_file(
    parent: &Dir,
    name: &OsStr,
    path: &Path,
    max_bytes: usize,
    missing: SkillAuthorityInactiveReason,
    invalid: SkillAuthorityInactiveReason,
) -> std::result::Result<Vec<u8>, SkillAuthorityInactiveReason> {
    match parent.symlink_metadata(name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err(missing),
        Err(_) => return Err(invalid),
        Ok(metadata) if !metadata.is_file() || cap_metadata_is_link_like(&metadata) => {
            return Err(invalid);
        }
        Ok(_) => {}
    }
    read_private_regular_file(parent, name, path, max_bytes).map_err(|_| invalid)
}

fn read_private_regular_file(
    parent: &Dir,
    name: &OsStr,
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    read_private_regular_file_observed(parent, name, path, max_bytes, |_| Ok(()))
}

fn read_private_regular_file_observed(
    parent: &Dir,
    name: &OsStr,
    path: &Path,
    max_bytes: usize,
    observe: impl FnOnce(u64) -> Result<()>,
) -> Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let mut file = parent
        .open_with(name, &options)
        .with_context(|| format!("open private Skill authority file {}", path.display()))?;
    verify_private_regular_file(&file, path)?;
    let mut bytes = Vec::new();
    let limit = u64::try_from(max_bytes)
        .context("Skill authority read limit conversion")?
        .saturating_add(1);
    let read = std::io::Read::by_ref(&mut file)
        .take(limit)
        .read_to_end(&mut bytes);
    observe(bytes.len() as u64)?;
    read.with_context(|| format!("read private Skill authority file {}", path.display()))?;
    if bytes.len() > max_bytes {
        anyhow::bail!(
            "Skill authority file exceeds the {max_bytes}-byte limit: {}",
            path.display()
        );
    }
    Ok(bytes)
}

fn publish_immutable_private_file(
    parent: &Dir,
    parent_path: &Path,
    name: &OsStr,
    bytes: &[u8],
) -> Result<()> {
    match parent.symlink_metadata(name) {
        Ok(metadata) => {
            if !metadata.is_file() || cap_metadata_is_link_like(&metadata) {
                anyhow::bail!("immutable Skill authority record name is not a regular file");
            }
            let existing =
                read_private_regular_file(parent, name, &parent_path.join(name), bytes.len())?;
            if existing != bytes {
                anyhow::bail!("immutable Skill authority record digest collision or corruption");
            }
            sync_parent_directory(parent, parent_path)
                .context("reconfirm immutable Skill authority record durability")?;
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect immutable Skill authority record"),
    }

    match publish_atomic_private_file(parent, parent_path, name, bytes, false) {
        Ok(
            SkillAuthorityDurability::Confirmed
            | SkillAuthorityDurability::NamespaceDurabilityUnsupported,
        ) => Ok(()),
        Ok(SkillAuthorityDurability::Unconfirmed | SkillAuthorityDurability::StateUncertain) => {
            anyhow::bail!(
                "immutable Skill authority record is visible but durability is unconfirmed; retry required"
            )
        }
        Err(commit_error) => {
            let raced =
                read_private_regular_file(parent, name, &parent_path.join(name), bytes.len());
            if matches!(raced, Ok(ref existing) if existing.as_slice() == bytes) {
                Ok(())
            } else {
                Err(commit_error)
            }
        }
    }
}

fn publish_atomic_private_file(
    parent: &Dir,
    parent_path: &Path,
    target_name: &OsStr,
    bytes: &[u8],
    replace_existing: bool,
) -> Result<SkillAuthorityDurability> {
    let (stage_name, mut stage) = create_private_stage(parent, parent_path)?;
    let stage_path = parent_path.join(&stage_name);
    stage.write_all(bytes).with_context(|| {
        format!(
            "write private Skill authority stage {}",
            stage_path.display()
        )
    })?;
    stage.flush().with_context(|| {
        format!(
            "flush private Skill authority stage {}",
            stage_path.display()
        )
    })?;
    stage.sync_all().with_context(|| {
        format!(
            "sync private Skill authority stage {}",
            stage_path.display()
        )
    })?;
    verify_private_regular_file(&stage, &stage_path)?;
    drop(stage);

    #[cfg(test)]
    if replace_existing
        && TEST_FAIL_ANCHOR_BEFORE_RENAME.with(|fail| {
            let active = fail.get();
            fail.set(false);
            active
        })
    {
        remove_stage_if_present(parent, parent_path, &stage_name);
        anyhow::bail!("injected failure before Skill current-anchor rename");
    }

    if let Err(error) = rename_child(
        parent,
        &stage_name,
        parent,
        target_name,
        replace_existing,
        &stage_path,
        &parent_path.join(target_name),
    ) {
        remove_stage_if_present(parent, parent_path, &stage_name);
        return Err(error);
    }
    #[cfg(test)]
    let force_sync_failure = if replace_existing {
        TEST_FAIL_ANCHOR_SYNC_AFTER_RENAME.with(|fail| {
            let active = fail.get();
            fail.set(false);
            active
        })
    } else {
        TEST_FAIL_RECORD_SYNC_AFTER_RENAME.with(|fail| {
            let active = fail.get();
            fail.set(false);
            active
        })
    };
    #[cfg(not(test))]
    let force_sync_failure = false;
    let durability = if force_sync_failure {
        SkillAuthorityDurability::Unconfirmed
    } else {
        match sync_parent_directory(parent, parent_path) {
            Ok(crate::skills::store::DirectorySyncOutcome::Confirmed) => {
                SkillAuthorityDurability::Confirmed
            }
            Ok(crate::skills::store::DirectorySyncOutcome::Unsupported) => {
                SkillAuthorityDurability::NamespaceDurabilityUnsupported
            }
            Err(_) => SkillAuthorityDurability::Unconfirmed,
        }
    };

    #[cfg(test)]
    if replace_existing
        && TEST_FAIL_ANCHOR_READBACK_AFTER_RENAME.with(|fail| {
            let active = fail.get();
            fail.set(false);
            active
        })
    {
        return Ok(SkillAuthorityDurability::StateUncertain);
    }

    let committed = match read_private_regular_file(
        parent,
        target_name,
        &parent_path.join(target_name),
        bytes.len(),
    ) {
        Ok(committed) => committed,
        Err(_) => return Ok(SkillAuthorityDurability::StateUncertain),
    };
    if committed != bytes {
        return Ok(SkillAuthorityDurability::StateUncertain);
    }
    Ok(durability)
}

fn create_private_stage(parent: &Dir, parent_path: &Path) -> Result<(OsString, cap_std::fs::File)> {
    for _ in 0..8 {
        let mut nonce = [0_u8; DECISION_ID_HEX_BYTES];
        getrandom::getrandom(&mut nonce).context("generate Skill authority stage name")?;
        let name = OsString::from(format!("{AUTHORITY_STAGE_PREFIX}{}", hex::encode(nonce)));
        let path = parent_path.join(&name);
        let mut options = OpenOptions::new();
        options
            .write(true)
            .read(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match parent.open_with(&name, &options) {
            Ok(file) => {
                #[cfg(windows)]
                {
                    crate::wal::win_native::set_private_current_user_dacl(&path)
                        .with_context(|| format!("set private DACL on {}", path.display()))?;
                }
                verify_private_regular_file(&file, &path)?;
                return Ok((name, file));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("create private Skill authority stage {}", path.display())
                });
            }
        }
    }
    anyhow::bail!("could not allocate a unique Skill authority stage name")
}

fn remove_stage_if_present(parent: &Dir, parent_path: &Path, stage_name: &OsStr) {
    let path = parent_path.join(stage_name);
    if parent
        .symlink_metadata(stage_name)
        .is_ok_and(|metadata| metadata.is_file() && !cap_metadata_is_link_like(&metadata))
    {
        let _ = remove_child_file(parent, stage_name, &path);
        let _ = sync_parent_directory(parent, parent_path);
    }
}

fn validate_anchor_shape(anchor: &SkillCurrentAnchorV1) -> Result<()> {
    if anchor.version != SKILL_CURRENT_ANCHOR_VERSION {
        anyhow::bail!("unsupported Skill current-anchor version");
    }
    super::creator::validate_skill_id(&anchor.skill_id)
        .context("invalid Skill current-anchor id")?;
    validate_sha256(
        &anchor.package_generation_sha256,
        "current-anchor package generation",
    )?;
    if anchor.install_incarnation == 0 {
        anyhow::bail!("Skill current-anchor install incarnation must be non-zero");
    }
    validate_sha256(
        &anchor.install_terminal_receipt_sha256,
        "current-anchor install terminal receipt",
    )?;
    if anchor.authority_sequence == 0 {
        anyhow::bail!("Skill current-anchor sequence must be non-zero");
    }
    validate_sha256(&anchor.record_sha256, "current-anchor record digest")?;
    validate_lower_hex(
        &anchor.decision_id,
        DECISION_ID_HEX_BYTES * 2,
        "current-anchor decision id",
    )
}

fn validate_behavior_string(value: &str, max_bytes: usize, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        anyhow::bail!("{label} is empty, oversized, non-canonical, or contains controls");
    }
    Ok(())
}

fn validate_optional_behavior_string(value: &Option<String>, label: &str) -> Result<()> {
    if let Some(value) = value {
        validate_behavior_string(value, MAX_BEHAVIOR_STRING_BYTES, label)?;
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    validate_lower_hex(value, 64, label)
}

fn validate_lower_hex(value: &str, width: usize, label: &str) -> Result<()> {
    if value.len() != width
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        anyhow::bail!("{label} must be exactly {width} lowercase hexadecimal characters");
    }
    Ok(())
}

fn valid_stage_name(name: &str) -> bool {
    name.strip_prefix(AUTHORITY_STAGE_PREFIX)
        .is_some_and(|nonce| {
            nonce.len() == DECISION_ID_HEX_BYTES * 2
                && nonce
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn valid_record_file_name(name: &str) -> bool {
    name.strip_prefix(AUTHORITY_RECORD_PREFIX)
        .and_then(|body| body.strip_suffix(AUTHORITY_JSON_SUFFIX))
        .is_some_and(|digest| validate_sha256(digest, "record filename").is_ok())
}

fn record_file_name(record_sha256: &str) -> OsString {
    debug_assert!(validate_sha256(record_sha256, "record digest").is_ok());
    OsString::from(format!(
        "{AUTHORITY_RECORD_PREFIX}{record_sha256}{AUTHORITY_JSON_SUFFIX}"
    ))
}

fn current_anchor_file_name(skill_id: &str) -> OsString {
    debug_assert!(super::creator::validate_skill_id(skill_id).is_ok());
    OsString::from(format!("{skill_id}{AUTHORITY_JSON_SUFFIX}"))
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).context("serialize canonical JSON")
}

fn canonical_value_sha256<T: Serialize>(value: &T) -> Result<String> {
    Ok(sha256_hex(&canonical_json(value)?))
}

fn authority_wal_unsigned_value(
    record: &SkillAuthorityRecordV1,
    record_sha256: &str,
    previous_authority_receipt_sha256: Option<&str>,
) -> Result<serde_json::Value> {
    let mut value = serde_json::json!({
        "schema_version": 1,
        "operation_id": record.decision_id,
        "skill_id": record.skill_id,
        "package_generation_sha256": record.package_generation_sha256,
        "install_incarnation": record.install_incarnation,
        "install_terminal_receipt_sha256": record.install_terminal_receipt_sha256,
        "authority_sequence": record.authority_sequence,
        "previous_authority_receipt_sha256": previous_authority_receipt_sha256,
        "previous_record_sha256": record.previous_record_sha256,
        "record_sha256": record_sha256,
        "decision_id": record.decision_id,
        "state": record.state,
    });
    let audit_event_id = {
        let bytes =
            serde_json::to_vec(&value).context("serialize Skill authority WAL event binding")?;
        let mut hasher = Sha256::new();
        hasher.update(AUTHORITY_WAL_HMAC_DOMAIN);
        hasher.update(&bytes);
        hex::encode(hasher.finalize())
    };
    value
        .as_object_mut()
        .context("Skill authority WAL binding must be a JSON object")?
        .insert(
            "audit_event_id".to_string(),
            serde_json::Value::String(audit_event_id),
        );
    Ok(value)
}

fn authority_wal_payload(
    record: &SkillAuthorityRecordV1,
    record_sha256: &str,
    previous_authority_receipt_sha256: Option<&str>,
    key: &[u8],
) -> Result<Vec<u8>> {
    let mut value =
        authority_wal_unsigned_value(record, record_sha256, previous_authority_receipt_sha256)?;
    let unsigned =
        serde_json::to_vec(&value).context("serialize unsigned Skill authority WAL event")?;
    let mut mac = AuthorityMac::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(AUTHORITY_WAL_HMAC_DOMAIN);
    mac.update(&[crate::wal::events::ExtendedSubtype::SkillAuthorityDecision as u8]);
    mac.update(&unsigned);
    value
        .as_object_mut()
        .context("Skill authority WAL payload must be a JSON object")?
        .insert(
            "auth_hmac_sha256".to_string(),
            serde_json::Value::String(hex::encode(mac.finalize().into_bytes())),
        );
    serde_json::to_vec(&value).context("serialize authenticated Skill authority WAL event")
}

fn validate_authority_wal_event(event: &SkillAuthorityWalEventV1) -> Result<()> {
    if event.schema_version != 1 {
        anyhow::bail!("unsupported Skill authority WAL schema");
    }
    validate_sha256(&event.audit_event_id, "Skill authority WAL audit id")?;
    validate_lower_hex(
        &event.operation_id,
        DECISION_ID_HEX_BYTES * 2,
        "Skill authority WAL operation id",
    )?;
    if event.operation_id != event.decision_id {
        anyhow::bail!("Skill authority WAL operation id does not bind its decision");
    }
    super::creator::validate_skill_id(&event.skill_id).context("invalid Skill authority WAL id")?;
    validate_sha256(
        &event.package_generation_sha256,
        "Skill authority WAL package generation",
    )?;
    if event.install_incarnation == 0 {
        anyhow::bail!("Skill authority WAL install incarnation must be non-zero");
    }
    validate_sha256(
        &event.install_terminal_receipt_sha256,
        "Skill authority WAL install receipt",
    )?;
    if event.authority_sequence == 0 {
        anyhow::bail!("Skill authority WAL sequence must be non-zero");
    }
    match (
        event.authority_sequence,
        event.previous_authority_receipt_sha256.as_deref(),
        event.previous_record_sha256.as_deref(),
    ) {
        (1, None, None) => {}
        (1, _, _) => anyhow::bail!("first Skill authority WAL event names a predecessor"),
        (_, Some(receipt), Some(record)) => {
            validate_sha256(receipt, "Skill authority WAL predecessor receipt")?;
            validate_sha256(record, "Skill authority WAL predecessor record")?;
        }
        _ => anyhow::bail!("non-first Skill authority WAL event lacks its predecessor"),
    }
    validate_sha256(&event.record_sha256, "Skill authority WAL record digest")?;
    validate_lower_hex(
        &event.decision_id,
        DECISION_ID_HEX_BYTES * 2,
        "Skill authority WAL decision id",
    )?;
    validate_sha256(
        &event.auth_hmac_sha256,
        "Skill authority WAL authentication tag",
    )
}

fn authenticate_authority_wal_payload(
    payload: &[u8],
    key: &[u8],
) -> Result<SkillAuthorityWalEventV1> {
    let mut value: serde_json::Value =
        serde_json::from_slice(payload).context("parse Skill authority WAL payload")?;
    let tag_hex = value
        .as_object_mut()
        .context("Skill authority WAL payload is not a JSON object")?
        .remove("auth_hmac_sha256")
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .context("Skill authority WAL payload lacks its authentication tag")?;
    validate_sha256(&tag_hex, "Skill authority WAL authentication tag")?;
    let tag = hex::decode(&tag_hex).context("decode Skill authority WAL authentication tag")?;
    let unsigned =
        serde_json::to_vec(&value).context("serialize unsigned Skill authority WAL payload")?;
    let mut mac = AuthorityMac::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(AUTHORITY_WAL_HMAC_DOMAIN);
    mac.update(&[crate::wal::events::ExtendedSubtype::SkillAuthorityDecision as u8]);
    mac.update(&unsigned);
    mac.verify_slice(&tag)
        .context("Skill authority WAL payload authentication failed")?;
    let actual_audit_event_id = value
        .as_object_mut()
        .context("Skill authority WAL payload is not a JSON object")?
        .remove("audit_event_id")
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .context("Skill authority WAL payload lacks its audit id")?;
    let expected_audit_event_id = {
        let binding =
            serde_json::to_vec(&value).context("serialize Skill authority WAL audit-id binding")?;
        let mut hasher = Sha256::new();
        hasher.update(AUTHORITY_WAL_HMAC_DOMAIN);
        hasher.update(&binding);
        hex::encode(hasher.finalize())
    };
    if actual_audit_event_id != expected_audit_event_id {
        anyhow::bail!("Skill authority WAL audit id does not match its binding");
    }
    value
        .as_object_mut()
        .context("Skill authority WAL payload is not a JSON object")?
        .insert(
            "audit_event_id".to_string(),
            serde_json::Value::String(actual_audit_event_id.clone()),
        );
    value
        .as_object_mut()
        .context("Skill authority WAL payload is not a JSON object")?
        .insert(
            "auth_hmac_sha256".to_string(),
            serde_json::Value::String(tag_hex),
        );
    let event: SkillAuthorityWalEventV1 =
        serde_json::from_value(value).context("decode Skill authority WAL event")?;
    if event.audit_event_id != expected_audit_event_id {
        anyhow::bail!("Skill authority WAL audit id changed during decoding");
    }
    validate_authority_wal_event(&event)?;
    Ok(event)
}

/// Authenticate and fully decode one authority frame before audit-RPC admits
/// it to the instance WAL. The WAL scanner intentionally authenticates every
/// authority frame before inspecting its Skill id; admitting a merely
/// well-shaped but unauthenticated payload would therefore let one bad local
/// request poison authority validation for every installed Skill.
pub(crate) fn authenticate_authority_wal_ingress(
    home: &Path,
    payload: &[u8],
) -> Result<(String, String)> {
    let key = load_existing_authority_key_checked(home)
        .context("load dedicated Skill authority key for ingress")?;
    let event = authenticate_authority_wal_payload(payload, &key)
        .context("authenticate Skill authority audit-RPC payload")?;
    Ok((event.audit_event_id, event.operation_id))
}

fn scan_authority_wal_head(
    home: &Path,
    skill_id: &str,
) -> Result<Option<AuthenticatedSkillAuthorityWalHead>> {
    super::creator::validate_skill_id(skill_id).context("validate Skill authority WAL id")?;
    Ok(scan_authority_wal_heads(home)?.remove(skill_id))
}

fn scan_authority_wal_heads(
    home: &Path,
) -> Result<BTreeMap<String, AuthenticatedSkillAuthorityWalHead>> {
    #[cfg(test)]
    record_authority_wal_scan_for_test(home);
    let key = load_existing_authority_key_checked(home)
        .context("load dedicated Skill authority key for WAL scan")?;
    let mut events_by_skill =
        BTreeMap::<String, BTreeMap<u64, AuthenticatedSkillAuthorityWalHead>>::new();
    crate::wal::scan::for_each_frame_at_home(
        home,
        crate::wal::scan::supported_home_scan_limits(),
        |location, frame| {
            if frame.header.event_type != crate::wal::events::EVENT_TYPE_EXTENDED
                || frame.header.event_subtype
                    != crate::wal::events::ExtendedSubtype::SkillAuthorityDecision as u8
            {
                return Ok(());
            }
            // Authenticate before using the skill id. A CRC-repaired rewrite
            // must not be able to hide or move the monotonic authority tail.
            let event = authenticate_authority_wal_payload(frame.payload, &key)?;
            let receipt = SkillAuthorityWalReceiptV1 {
                payload_sha256: sha256_hex(frame.payload),
                segment_name: location
                    .segment_name
                    .to_str()
                    .context("Skill authority WAL segment name is not UTF-8")?
                    .to_string(),
                segment_generation: location.segment_generation,
                segment_seq: location.segment_seq,
                segment_start_ts_ns: location.segment_start_ts_ns,
                segment_node_id_hex: hex::encode(location.segment_node_id),
                logical_offset: location.logical_offset,
                event_id: frame.header.event_id.raw(),
                event_hlc_physical_ns: frame.header.hlc.physical_ns(),
                event_hlc_logical: frame.header.hlc.logical(),
                event_node_id_hex: hex::encode(frame.header.node_id.0),
            };
            let sequence = event.authority_sequence;
            let head = AuthenticatedSkillAuthorityWalHead {
                event,
                receipt_sha256: canonical_value_sha256(&receipt)?,
            };
            let skill_id = head.event.skill_id.clone();
            if events_by_skill
                .entry(skill_id.clone())
                .or_default()
                .insert(sequence, head)
                .is_some()
            {
                anyhow::bail!(
                    "Skill `{skill_id}` has duplicate authenticated authority sequence {sequence}"
                );
            }
            Ok(())
        },
    )?;
    let mut heads = BTreeMap::new();
    for (skill_id, mut events) in events_by_skill {
        let mut previous: Option<&AuthenticatedSkillAuthorityWalHead> = None;
        for head in events.values() {
            let expected_sequence = match previous {
                None => 1,
                Some(prior) => prior
                    .event
                    .authority_sequence
                    .checked_add(1)
                    .context("Skill authority WAL sequence overflow")?,
            };
            if head.event.authority_sequence != expected_sequence {
                anyhow::bail!("Skill `{skill_id}` authority WAL chain is non-contiguous");
            }
            if head.event.previous_authority_receipt_sha256.as_deref()
                != previous.map(|prior| prior.receipt_sha256.as_str())
                || head.event.previous_record_sha256.as_deref()
                    != previous.map(|prior| prior.event.record_sha256.as_str())
            {
                anyhow::bail!(
                    "Skill `{skill_id}` authority WAL event does not extend the authenticated head"
                );
            }
            previous = Some(head);
        }
        if let Some((_, head)) = events.pop_last() {
            heads.insert(skill_id, head);
        }
    }
    Ok(heads)
}

#[cfg(test)]
fn authority_wal_scan_counts() -> &'static std::sync::Mutex<BTreeMap<PathBuf, usize>> {
    static COUNTS: std::sync::OnceLock<std::sync::Mutex<BTreeMap<PathBuf, usize>>> =
        std::sync::OnceLock::new();
    COUNTS.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

#[cfg(test)]
fn record_authority_wal_scan_for_test(home: &Path) {
    let mut counts = authority_wal_scan_counts()
        .lock()
        .expect("authority WAL scan counter lock poisoned");
    *counts.entry(home.to_path_buf()).or_default() += 1;
}

#[cfg(test)]
fn authority_wal_scan_count_for_test(home: &Path) -> usize {
    authority_wal_scan_counts()
        .lock()
        .expect("authority WAL scan counter lock poisoned")
        .get(home)
        .copied()
        .unwrap_or_default()
}

#[cfg(test)]
pub(crate) fn scan_authority_wal_head_exists_for_test(home: &Path, skill_id: &str) -> Result<bool> {
    Ok(scan_authority_wal_head(home, skill_id)?.is_some())
}

fn authority_wal_head_matches_record(
    head: &AuthenticatedSkillAuthorityWalHead,
    record: &SkillAuthorityRecordV1,
    record_sha256: &str,
) -> bool {
    head.event.skill_id == record.skill_id
        && head.event.package_generation_sha256 == record.package_generation_sha256
        && head.event.install_incarnation == record.install_incarnation
        && head.event.install_terminal_receipt_sha256 == record.install_terminal_receipt_sha256
        && head.event.authority_sequence == record.authority_sequence
        && head.event.previous_record_sha256 == record.previous_record_sha256
        && head.event.record_sha256 == record_sha256
        && head.event.decision_id == record.decision_id
        && head.event.state == record.state
}

fn require_authority_wal_head(home: &Path, entry: &AuthenticatedRecordEntry) -> Result<()> {
    let head = scan_authority_wal_head(home, &entry.record.skill_id)
        .context("validate independent Skill authority WAL head")?
        .context("Skill authority WAL head is missing")?;
    if !authority_wal_head_matches_record(&head, &entry.record, &entry.record_sha256) {
        anyhow::bail!("Skill authority files do not match their independent WAL head");
    }
    Ok(())
}

fn append_authority_wal_payload_blocking(home: &Path, payload: Vec<u8>) -> Result<()> {
    let home = home.to_path_buf();
    std::thread::Builder::new()
        .name("neoth-skill-authority-wal".to_string())
        .spawn(move || {
            let daemon_live =
                crate::daemon::pidfile::live_daemon_pid(&home.join("neothd.pid"))?.is_some();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("build Skill authority WAL runtime")?;
            runtime.block_on(async move {
                let subtype = crate::wal::events::ExtendedSubtype::SkillAuthorityDecision as u8;
                if daemon_live {
                    crate::daemon::audit_rpc::try_post_skill_mutation_frame(
                        &home,
                        crate::wal::events::EVENT_TYPE_EXTENDED,
                        subtype,
                        &payload,
                    )
                    .await
                    .map_err(anyhow::Error::new)
                    .context("daemon did not durably ACK Skill authority WAL head")?;
                    return Ok(());
                }
                let wal_dir = home.join("wal");
                std::fs::create_dir_all(&wal_dir)
                    .context("create Skill authority WAL directory")?;
                let segment =
                    crate::wal::writer::unique_standalone_segment_path(&wal_dir, "skill-authority");
                let (writer, join) =
                    crate::wal::writer::spawn_for_home(segment, home.to_path_buf())
                        .context("spawn home-bound Skill authority WAL writer")?;
                let header = crate::wal::HeaderBuilder::new(
                    crate::wal::events::EVENT_TYPE_EXTENDED,
                    &payload,
                )
                .event_subtype(subtype)
                .build();
                writer
                    .append(header, payload)
                    .await
                    .context("append authenticated Skill authority WAL head")?;
                super::registry::notify_runtime_authority_transition(
                    &home,
                    super::registry::RuntimeAuthorityTransitionKind::AuthorityDecision,
                );
                drop(writer);
                let _ = join.await;
                Ok(())
            })
        })
        .context("spawn Skill authority WAL transaction thread")?
        .join()
        .map_err(|_| anyhow::anyhow!("Skill authority WAL transaction thread panicked"))?
}

fn commit_authority_wal_head(
    home: &Path,
    key: &[u8],
    record: &SkillAuthorityRecordV1,
    record_sha256: &str,
) -> Result<AuthenticatedSkillAuthorityWalHead> {
    let current = scan_authority_wal_head(home, &record.skill_id)
        .context("scan authenticated Skill authority WAL head")?;
    if let Some(current) = current.as_ref()
        && authority_wal_head_matches_record(current, record, record_sha256)
    {
        super::registry::notify_runtime_authority_transition(
            home,
            super::registry::RuntimeAuthorityTransitionKind::AuthorityDecision,
        );
        return Ok(current.clone());
    }
    match current.as_ref() {
        None if record.authority_sequence == 1 && record.previous_record_sha256.is_none() => {}
        Some(previous)
            if record.authority_sequence == previous.event.authority_sequence.saturating_add(1)
                && record.previous_record_sha256.as_deref()
                    == Some(previous.event.record_sha256.as_str()) => {}
        _ => anyhow::bail!(
            "Skill authority record does not extend the independent authenticated WAL head"
        ),
    }
    let payload = authority_wal_payload(
        record,
        record_sha256,
        current.as_ref().map(|head| head.receipt_sha256.as_str()),
        key,
    )?;
    let delivery = append_authority_wal_payload_blocking(home, payload);
    let delivery_was_acknowledged = delivery.is_ok();
    let observed = scan_authority_wal_head(home, &record.skill_id)
        .context("re-scan Skill authority WAL head after append")?;
    if let Some(observed) = observed
        && authority_wal_head_matches_record(&observed, record, record_sha256)
    {
        if !delivery_was_acknowledged {
            super::registry::notify_runtime_authority_transition(
                home,
                super::registry::RuntimeAuthorityTransitionKind::AuthorityDecision,
            );
        }
        return Ok(observed);
    }
    delivery?;
    anyhow::bail!("Skill authority WAL append was ACKed but its exact head is not visible")
}

fn effective_skill_policy_sha256(
    config: &crate::config::SkillsConfig,
    skill_id: &str,
) -> Result<String> {
    let normalized_id = skill_id.to_lowercase();
    let force_disabled = config
        .disabled
        .iter()
        .any(|id| id.trim().to_lowercase() == normalized_id);
    let force_enabled = config
        .enabled
        .iter()
        .any(|id| id.trim().to_lowercase() == normalized_id);
    let mut visibility_override = None;
    for (id, visibility) in &config.visibility_overrides {
        if id.trim().to_lowercase() != normalized_id {
            continue;
        }
        if visibility_override.is_some_and(|known| known != *visibility) {
            anyhow::bail!(
                "accepted Skill policy contains conflicting case-insensitive visibility overrides"
            );
        }
        visibility_override = Some(*visibility);
    }
    canonical_value_sha256(&EffectiveSkillPolicyBindingV1 {
        version: 1,
        skill_id: normalized_id.clone(),
        disabled_for_eval_sessions: config.disabled_for_eval_sessions,
        eval_session_active: config.eval_session_active,
        pinned_content_hash: config.pinned_hashes.get(&normalized_id).cloned(),
        always_embed_route: config.always_embed_route,
        force_disabled,
        force_enabled,
        visibility_override,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn record_hmac(key: &[u8], record_sha256: &str, canonical_record: &[u8]) -> String {
    domain_hmac(
        key,
        RECORD_HMAC_DOMAIN,
        &[record_sha256.as_bytes(), canonical_record],
    )
}

fn verify_record_hmac(
    key: &[u8],
    record_sha256: &str,
    canonical_record: &[u8],
    expected: &str,
) -> Result<()> {
    verify_domain_hmac(
        key,
        RECORD_HMAC_DOMAIN,
        &[record_sha256.as_bytes(), canonical_record],
        expected,
    )
}

fn domain_hmac(key: &[u8], domain: &[u8], fields: &[&[u8]]) -> String {
    let mut mac = AuthorityMac::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    update_framed(&mut mac, domain);
    for field in fields {
        update_framed(&mut mac, field);
    }
    hex::encode(mac.finalize().into_bytes())
}

fn verify_domain_hmac(key: &[u8], domain: &[u8], fields: &[&[u8]], expected: &str) -> Result<()> {
    validate_sha256(expected, "Skill authority HMAC")?;
    let expected = hex::decode(expected).context("decode Skill authority HMAC")?;
    let mut mac = AuthorityMac::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    update_framed(&mut mac, domain);
    for field in fields {
        update_framed(&mut mac, field);
    }
    mac.verify_slice(&expected)
        .context("Skill authority HMAC verification failed")
}

fn update_framed(mac: &mut AuthorityMac, value: &[u8]) {
    mac.update(&(value.len() as u64).to_le_bytes());
    mac.update(value);
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected_platform_durability() -> SkillAuthorityDurability {
        #[cfg(unix)]
        {
            SkillAuthorityDurability::Confirmed
        }
        #[cfg(not(unix))]
        {
            SkillAuthorityDurability::NamespaceDurabilityUnsupported
        }
    }

    fn digest(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn claims() -> SkillBehaviorClaimsV1 {
        SkillBehaviorClaimsV1 {
            effective_tools: vec![
                "mcp::fs::read".to_string(),
                "mcp::recall::query".to_string(),
            ],
            effective_enabled: true,
            skills_policy_sha256: digest(0x03),
            system_prompt_sha256: digest(0x04),
            trigger_keywords_sha256: digest(0x05),
            paths_sha256: digest(0x06),
            modes_sha256: digest(0x07),
            delegate_to: Some("planner".to_string()),
            model: Some("provider/model-v1".to_string()),
            effort: Some(EffortBudget::High),
            loop_trigger: true,
            visibility: SkillVisibility::NameOnly,
            source: Some("git+https://example.invalid/owner/skill".to_string()),
        }
    }

    fn record(skill_id: &str, state: SkillAuthorityState) -> SkillAuthorityRecordV1 {
        SkillAuthorityRecordV1 {
            version: SKILL_AUTHORITY_RECORD_VERSION,
            skill_id: skill_id.to_string(),
            package_generation_sha256: digest(0x11),
            manifest_sha256: digest(0x22),
            install_incarnation: 1,
            install_terminal_receipt_sha256: digest(0x23),
            authority_sequence: 1,
            previous_record_sha256: None,
            provenance: SkillProvenance::CommunityImport,
            decision_source: SkillAuthorityDecisionSource::OperatorCli,
            state,
            decision_reason: match state {
                SkillAuthorityState::Active => None,
                SkillAuthorityState::Inactive => Some("awaiting operator activation".to_string()),
                SkillAuthorityState::Revoked => {
                    Some("operator revoked this generation".to_string())
                }
            },
            claims: claims(),
            decision_id: digest(0x33)[..DECISION_ID_HEX_BYTES * 2].to_string(),
            decided_at_unix_ms: 1_750_000_000_000,
        }
    }

    fn install_test_key(home: &Path) {
        let wal_dir = home.join(WAL_DIRECTORY_NAME);
        std::fs::create_dir_all(&wal_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&wal_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        #[cfg(windows)]
        crate::wal::win_native::set_private_current_user_directory_dacl(&wal_dir).unwrap();
        crate::wal::compaction::load_or_init_key(&wal_dir.join(WAL_HMAC_KEY_NAME)).unwrap();
    }

    fn fixture() -> (tempfile::TempDir, SkillAuthorityRecordV1) {
        let home = tempfile::tempdir().unwrap();
        install_test_key(home.path());
        (home, record("alpha", SkillAuthorityState::Active))
    }

    fn assert_inactive(
        home: &Path,
        expected: &SkillAuthorityExpectation,
        reason: SkillAuthorityInactiveReason,
    ) {
        assert_eq!(
            validate_current_authority(home, expected).inactive_reason(),
            Some(reason)
        );
    }

    fn record_path(home: &Path, record_sha256: &str) -> PathBuf {
        authority_root(home)
            .join(AUTHORITY_RECORDS_NAME)
            .join("alpha")
            .join(record_file_name(record_sha256))
    }

    fn anchor_path(home: &Path, skill_id: &str) -> PathBuf {
        current_anchor_path(home, skill_id).unwrap()
    }

    fn read_record_file(
        home: &Path,
        receipt: &SkillAuthorityReceipt,
    ) -> AuthenticatedAuthorityRecordV1 {
        serde_json::from_slice(&std::fs::read(record_path(home, &receipt.record_sha256)).unwrap())
            .unwrap()
    }

    fn read_anchor_file(home: &Path, skill_id: &str) -> AuthenticatedCurrentAnchorV1 {
        serde_json::from_slice(&std::fs::read(anchor_path(home, skill_id)).unwrap()).unwrap()
    }

    fn private_replace(path: &Path, bytes: &[u8]) {
        crate::util::atomic_write::atomic_write_private(path, bytes).unwrap();
    }

    fn append_authority_test_payload_at(home: &Path, segment: PathBuf, payload: Vec<u8>) {
        let home = home.to_path_buf();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let (writer, join) = crate::wal::writer::spawn_for_home(segment, home).unwrap();
                let header = crate::wal::HeaderBuilder::new(
                    crate::wal::events::EVENT_TYPE_EXTENDED,
                    &payload,
                )
                .event_subtype(crate::wal::events::ExtendedSubtype::SkillAuthorityDecision as u8)
                .build();
                writer.append(header, payload).await.unwrap();
                drop(writer);
                join.await.unwrap();
            });
        })
        .join()
        .unwrap();
    }

    fn write_installed_skill(home: &Path, prompt: &str) {
        write_installed_skill_named(home, "alpha", prompt);
    }

    fn write_installed_skill_named(home: &Path, skill_id: &str, prompt: &str) {
        let directory = home.join("skills").join(skill_id);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join("skill.yaml"),
            format!(
                "id: {skill_id}\n\
                 description: Authority fixture\n\
                 trigger_keywords: [\" {skill_id} \", \"\", TeSt]\n\
                 system_prompt: {prompt:?}\n\
                 tool_allowlist: [mcp::fs::read]\n\
                 visibility: name_only\n"
            ),
        )
        .unwrap();
    }

    fn record_installed_skill_incarnation(
        home: &Path,
        origin: super::super::installer::SkillMutationOrigin,
    ) {
        record_installed_skill_incarnation_named(home, "alpha", origin);
    }

    fn record_installed_skill_incarnation_named(
        home: &Path,
        skill_id: &str,
        origin: super::super::installer::SkillMutationOrigin,
    ) {
        let current =
            super::super::installer::inspect_current_install(&home.join("skills"), skill_id)
                .unwrap();
        super::super::mutation_lifecycle::record_committed_install_incarnation_for_test(
            home,
            skill_id,
            &current.generation_sha256,
            origin,
        )
        .unwrap();
    }

    fn reload_controller(
        home: &Path,
        config: crate::config::FreedomConfig,
    ) -> crate::config::reload::ReloadController {
        let path = home.join("freedom.yaml");
        std::fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
        crate::config::reload::ReloadController::new(config, path)
    }

    fn active_decision() -> SkillAuthorityDecision {
        SkillAuthorityDecision::new(
            SkillAuthorityDecisionSource::OperatorCli,
            SkillAuthorityState::Active,
            None,
        )
        .unwrap()
    }

    fn activation_transaction_fixture() -> (
        tempfile::TempDir,
        crate::config::reload::ReloadController,
        InstalledSkillDecisionExpectation,
    ) {
        let home = tempfile::tempdir().unwrap();
        install_test_key(home.path());
        write_installed_skill(home.path(), "activation transaction");
        record_installed_skill_incarnation(
            home.path(),
            super::super::installer::SkillMutationOrigin::CliInstall,
        );
        let mut config = crate::config::FreedomConfig::default();
        config.skills.enabled.push("alpha".to_string());
        let reload = reload_controller(home.path(), config);
        let current =
            super::super::installer::inspect_current_install(&home.path().join("skills"), "alpha")
                .unwrap();
        let proof = super::super::mutation_lifecycle::authenticate_current_install_incarnation(
            home.path(),
            "alpha",
            &current.generation_sha256,
        )
        .unwrap();
        let expectation = InstalledSkillDecisionExpectation::new(
            current.generation_sha256,
            proof.install_incarnation(),
            proof.terminal_receipt_sha256().to_string(),
        )
        .unwrap();
        (home, reload, expectation)
    }

    #[test]
    fn activation_transaction_commit_failure_rolls_back_and_keeps_exact_inactive_guard() {
        let (home, reload, expectation) = activation_transaction_fixture();
        let commit_called = std::cell::Cell::new(false);
        let rollback_called = std::cell::Cell::new(false);

        let error = publish_installed_activation_transaction(
            home.path(),
            "alpha",
            &reload,
            SkillAuthorityDecisionSource::OperatorCli,
            Some(&expectation),
            || {
                commit_called.set(true);
                anyhow::bail!("injected policy commit failure")
            },
            || {
                rollback_called.set(true);
                Ok(())
            },
        )
        .unwrap_err();

        assert!(commit_called.get());
        assert!(rollback_called.get());
        assert!(format!("{error:#}").contains("injected policy commit failure"));
        let current = inspect_current_authority(home.path(), "alpha")
            .unwrap()
            .expect("inactive guard must remain current");
        assert_eq!(current.record().state, SkillAuthorityState::Inactive);
        assert_eq!(
            current.record().package_generation_sha256.as_str(),
            expectation.package_generation_sha256.as_str()
        );
        assert_eq!(
            current.record().install_incarnation,
            expectation.install_incarnation
        );
        assert_eq!(
            current.record().install_terminal_receipt_sha256.as_str(),
            expectation.install_terminal_receipt_sha256.as_str()
        );
        assert_eq!(
            validate_installed_authority(home.path(), "alpha", &reload).inactive_reason(),
            Some(SkillAuthorityInactiveReason::DecisionInactive)
        );
    }

    #[test]
    fn activation_transaction_success_publishes_exact_final_active_authority() {
        let (home, reload, expectation) = activation_transaction_fixture();
        let commit_called = std::cell::Cell::new(false);
        let rollback_called = std::cell::Cell::new(false);

        let receipt = publish_installed_activation_transaction(
            home.path(),
            "alpha",
            &reload,
            SkillAuthorityDecisionSource::OperatorCli,
            Some(&expectation),
            || {
                commit_called.set(true);
                Ok(())
            },
            || {
                rollback_called.set(true);
                Ok(())
            },
        )
        .unwrap();

        assert!(commit_called.get());
        assert!(!rollback_called.get());
        assert_eq!(receipt.state(), SkillAuthorityState::Active);
        assert_eq!(
            receipt.package_generation_sha256(),
            expectation.package_generation_sha256.as_str()
        );
        assert_eq!(
            receipt.install_incarnation(),
            expectation.install_incarnation
        );
        assert_eq!(
            receipt.install_terminal_receipt_sha256(),
            expectation.install_terminal_receipt_sha256.as_str()
        );
        let current = inspect_current_authority(home.path(), "alpha")
            .unwrap()
            .expect("final Active decision must remain current");
        assert_eq!(current.record().state, SkillAuthorityState::Active);
        assert_eq!(current.record_sha256(), receipt.record_sha256());
        let InstalledSkillAuthorityValidation::Active(validated) =
            validate_installed_authority(home.path(), "alpha", &reload)
        else {
            panic!("exact transaction authority must be executable");
        };
        assert_eq!(
            validated.package_generation_sha256(),
            expectation.package_generation_sha256.as_str()
        );
        assert_eq!(
            validated.install_incarnation(),
            expectation.install_incarnation
        );
        assert_eq!(
            validated.install_terminal_receipt_sha256(),
            expectation.install_terminal_receipt_sha256.as_str()
        );
    }

    #[test]
    fn repeated_exact_activation_reuses_authority_history() {
        let (home, reload, expectation) = activation_transaction_fixture();
        let first = publish_installed_activation_transaction(
            home.path(),
            "alpha",
            &reload,
            SkillAuthorityDecisionSource::OperatorCli,
            Some(&expectation),
            || Ok(()),
            || Ok(()),
        )
        .unwrap();
        let second = publish_installed_activation_transaction(
            home.path(),
            "alpha",
            &reload,
            SkillAuthorityDecisionSource::OperatorCli,
            Some(&expectation),
            || Ok(()),
            || Ok(()),
        )
        .unwrap();

        assert_eq!(second.authority_sequence(), first.authority_sequence());
        assert_eq!(second.record_sha256(), first.record_sha256());
        assert_eq!(
            second.current_anchor_sha256(),
            first.current_anchor_sha256()
        );
    }

    #[test]
    fn activation_capacity_reserves_both_fail_closed_revisions() {
        assert!(
            ensure_authority_record_capacity_for_len(MAX_AUTHORITY_RECORDS_PER_SKILL - 2, 2)
                .is_ok()
        );
        let error =
            ensure_authority_record_capacity_for_len(MAX_AUTHORITY_RECORDS_PER_SKILL - 1, 2)
                .unwrap_err();
        assert!(
            format!("{error:#}").contains("requires 2"),
            "capacity error must explain that activation is an atomic two-record transition: {error:#}"
        );
    }

    #[test]
    fn exact_active_authority_round_trip_is_typed_and_anchor_last() {
        let (home, record) = fixture();
        let receipt = publish_authority_decision(home.path(), &record).unwrap();

        assert!(record_path(home.path(), &receipt.record_sha256).is_file());
        assert!(anchor_path(home.path(), &record.skill_id).is_file());
        let expected = SkillAuthorityExpectation::from_record(&record);
        let SkillAuthorityValidation::Active(validated) =
            validate_current_authority(home.path(), &expected)
        else {
            panic!("exact authority did not activate");
        };
        assert_eq!(validated.record(), &record);
        assert_eq!(validated.record_sha256(), receipt.record_sha256);
        assert_eq!(
            validated.current_anchor_sha256(),
            receipt.current_anchor_sha256
        );
    }

    #[test]
    fn authority_wal_chain_uses_authenticated_sequence_not_segment_name_order() {
        let (home, first_record) = fixture();
        initialize_authority_key_for_test(home.path()).unwrap();
        let key = load_existing_authority_key_checked(home.path()).unwrap();
        let first_record_sha256 = sha256_hex(&canonical_json(&first_record).unwrap());
        let first_payload =
            authority_wal_payload(&first_record, &first_record_sha256, None, &key).unwrap();
        let wal_dir = home.path().join("wal");
        let offline_segment =
            crate::wal::writer::unique_standalone_segment_path(&wal_dir, "skill-authority");
        append_authority_test_payload_at(home.path(), offline_segment, first_payload);
        let first_head = scan_authority_wal_head(home.path(), "alpha")
            .unwrap()
            .unwrap();

        let mut second_record = first_record.clone();
        second_record.authority_sequence = 2;
        second_record.previous_record_sha256 = Some(first_record_sha256.clone());
        second_record.state = SkillAuthorityState::Revoked;
        second_record.decision_reason = Some("test segment ordering".to_string());
        second_record.decision_id = digest(0x71)[..DECISION_ID_HEX_BYTES * 2].to_string();
        second_record.decided_at_unix_ms += 1;
        let second_record_sha256 = sha256_hex(&canonical_json(&second_record).unwrap());
        let second_payload = authority_wal_payload(
            &second_record,
            &second_record_sha256,
            Some(&first_head.receipt_sha256),
            &key,
        )
        .unwrap();
        append_authority_test_payload_at(home.path(), wal_dir.join("000001.wal"), second_payload);

        let latest = scan_authority_wal_head(home.path(), "alpha")
            .unwrap()
            .unwrap();
        assert_eq!(latest.event.authority_sequence, 2);
        assert_eq!(latest.event.record_sha256, second_record_sha256);
    }

    #[test]
    fn public_admission_hashes_live_package_and_returns_owned_runtime_manifest() {
        let home = tempfile::tempdir().unwrap();
        install_test_key(home.path());
        write_installed_skill(home.path(), "first generation");
        record_installed_skill_incarnation(
            home.path(),
            super::super::installer::SkillMutationOrigin::CliInstall,
        );
        let reload = reload_controller(home.path(), crate::config::FreedomConfig::default());
        publish_installed_authority_decision(home.path(), "alpha", &reload, active_decision())
            .unwrap();

        let InstalledSkillAuthorityValidation::Active(authorized) =
            validate_installed_authority(home.path(), "alpha", &reload)
        else {
            panic!("exact installed generation was not authorized");
        };
        assert_eq!(authorized.manifest().system_prompt, "first generation");
        assert_eq!(
            authorized.manifest().trigger_keywords,
            vec!["alpha".to_string(), "test".to_string()]
        );

        let skills_root =
            open_bound_directory(&home.path().join("skills"), false, "test Skills root")
                .unwrap()
                .unwrap();
        let _mutation_guard = super::super::installer::lock_skill_mutations(&skills_root).unwrap();
        drop(_mutation_guard);
        drop(skills_root);

        write_installed_skill(home.path(), "second generation");
        assert_eq!(authorized.manifest().system_prompt, "first generation");
        assert_eq!(
            validate_installed_authority(home.path(), "alpha", &reload).inactive_reason(),
            Some(SkillAuthorityInactiveReason::InstallIncarnationMismatch)
        );
    }

    #[test]
    fn validation_batch_indexes_each_wal_domain_once_for_multiple_candidates() {
        let home = tempfile::tempdir().unwrap();
        install_test_key(home.path());
        write_installed_skill_named(home.path(), "alpha", "first");
        write_installed_skill_named(home.path(), "beta", "second");
        record_installed_skill_incarnation_named(
            home.path(),
            "alpha",
            super::super::installer::SkillMutationOrigin::CliInstall,
        );
        record_installed_skill_incarnation_named(
            home.path(),
            "beta",
            super::super::installer::SkillMutationOrigin::CliInstall,
        );
        let reload = reload_controller(home.path(), crate::config::FreedomConfig::default());
        publish_installed_authority_decision(home.path(), "alpha", &reload, active_decision())
            .unwrap();
        publish_installed_authority_decision(home.path(), "beta", &reload, active_decision())
            .unwrap();

        let incarnation_scans_before =
            super::super::mutation_lifecycle::incarnation_index_scan_count_for_test(home.path());
        let authority_scans_before = authority_wal_scan_count_for_test(home.path());
        let mut batch = begin_installed_authority_validation_batch(home.path(), &reload).unwrap();
        assert_eq!(
            super::super::mutation_lifecycle::incarnation_index_scan_count_for_test(home.path()),
            incarnation_scans_before + 1
        );
        assert_eq!(
            authority_wal_scan_count_for_test(home.path()),
            authority_scans_before + 1
        );

        assert!(matches!(
            batch.validate("alpha", &reload).unwrap(),
            InstalledSkillAuthorityValidation::Active(_)
        ));
        assert!(matches!(
            batch.validate("beta", &reload).unwrap(),
            InstalledSkillAuthorityValidation::Active(_)
        ));
        assert_eq!(
            super::super::mutation_lifecycle::incarnation_index_scan_count_for_test(home.path()),
            incarnation_scans_before + 1,
            "per-candidate validation must not rescan the mutation WAL"
        );
        assert_eq!(
            authority_wal_scan_count_for_test(home.path()),
            authority_scans_before + 1,
            "per-candidate validation must not rescan the authority WAL"
        );
    }

    #[test]
    fn validation_batch_budget_is_shared_with_rejected_candidates() {
        let home = tempfile::tempdir().unwrap();
        install_test_key(home.path());
        write_installed_skill_named(home.path(), "alpha", "authorised");
        write_installed_skill_named(home.path(), "beta", "not authorised");
        record_installed_skill_incarnation_named(
            home.path(),
            "alpha",
            super::super::installer::SkillMutationOrigin::CliInstall,
        );
        record_installed_skill_incarnation_named(
            home.path(),
            "beta",
            super::super::installer::SkillMutationOrigin::CliInstall,
        );
        let reload = reload_controller(home.path(), crate::config::FreedomConfig::default());
        publish_installed_authority_decision(home.path(), "alpha", &reload, active_decision())
            .unwrap();

        let mut batch = begin_installed_authority_validation_batch(home.path(), &reload).unwrap();
        // Alpha consumes one package entry and one authority-record entry.
        // Beta has no authority at all, but its attempted package traversal
        // must still consume the shared budget and fail the whole batch.
        batch.set_traversal_limits_for_test(2, u64::MAX);
        assert!(matches!(
            batch.validate("alpha", &reload).unwrap(),
            InstalledSkillAuthorityValidation::Active(_)
        ));
        let error = batch.validate("beta", &reload).unwrap_err();
        assert!(
            super::super::installer::is_runtime_authority_traversal_limit(&error),
            "aggregate overflow must remain a fatal whole-batch error: {error:#}"
        );
    }

    #[test]
    fn rejected_oversized_authority_record_charges_actual_bounded_read_bytes() {
        let home = tempfile::tempdir().unwrap();
        install_test_key(home.path());
        write_installed_skill(home.path(), "oversized record accounting");
        record_installed_skill_incarnation(
            home.path(),
            super::super::installer::SkillMutationOrigin::CliInstall,
        );
        let reload = reload_controller(home.path(), crate::config::FreedomConfig::default());
        let receipt =
            publish_installed_authority_decision(home.path(), "alpha", &reload, active_decision())
                .unwrap();
        private_replace(
            &record_path(home.path(), receipt.record_sha256()),
            &vec![b'x'; MAX_AUTHORITY_RECORD_BYTES + 1],
        );

        let mut batch = begin_installed_authority_validation_batch(home.path(), &reload).unwrap();
        batch.set_traversal_limits_for_test(16, 1024);
        let error = batch.validate("alpha", &reload).unwrap_err();
        assert!(
            super::super::installer::is_runtime_authority_traversal_limit(&error),
            "bytes consumed before the oversized-record rejection must remain charged: {error:#}"
        );
    }

    #[test]
    fn publication_guard_indexes_once_and_shares_its_final_barrier_budget() {
        let home = tempfile::tempdir().unwrap();
        install_test_key(home.path());
        write_installed_skill(home.path(), "final barrier budget");
        record_installed_skill_incarnation(
            home.path(),
            super::super::installer::SkillMutationOrigin::CliInstall,
        );
        let reload = reload_controller(home.path(), crate::config::FreedomConfig::default());
        publish_installed_authority_decision(home.path(), "alpha", &reload, active_decision())
            .unwrap();
        let InstalledSkillAuthorityValidation::Active(validated) =
            validate_installed_authority(home.path(), "alpha", &reload)
        else {
            panic!("fixture authority must be active");
        };
        let generation = validated.package_generation_sha256().to_string();
        let incarnation = validated.install_incarnation();
        let install_receipt = validated.install_terminal_receipt_sha256().to_string();
        let authority_record = validated.record_sha256().to_string();
        drop(validated);

        let incarnation_scans_before =
            super::super::mutation_lifecycle::incarnation_index_scan_count_for_test(home.path());
        let authority_scans_before = authority_wal_scan_count_for_test(home.path());
        let mut guard = lock_installed_skill_publication(home.path()).unwrap();
        assert_eq!(
            super::super::mutation_lifecycle::incarnation_index_scan_count_for_test(home.path()),
            incarnation_scans_before + 1
        );
        assert_eq!(
            authority_wal_scan_count_for_test(home.path()),
            authority_scans_before + 1
        );
        guard.traversal_budget =
            super::super::installer::RuntimeAuthorityTraversalBudget::with_limits(2, u64::MAX);
        guard
            .validate_installed_binding(
                "alpha",
                &generation,
                incarnation,
                &install_receipt,
                &authority_record,
            )
            .unwrap();
        let error = guard
            .validate_installed_binding(
                "alpha",
                &generation,
                incarnation,
                &install_receipt,
                &authority_record,
            )
            .unwrap_err();
        assert!(
            super::super::installer::is_runtime_authority_traversal_limit(&error),
            "the final publication barrier must share one aggregate budget: {error:#}"
        );
        assert_eq!(
            super::super::mutation_lifecycle::incarnation_index_scan_count_for_test(home.path()),
            incarnation_scans_before + 1
        );
        assert_eq!(
            authority_wal_scan_count_for_test(home.path()),
            authority_scans_before + 1
        );
    }

    #[test]
    fn final_publication_guard_blocks_revocation_through_snapshot_store_boundary() {
        let home = tempfile::tempdir().unwrap();
        install_test_key(home.path());
        write_installed_skill(home.path(), "publication barrier");
        record_installed_skill_incarnation(
            home.path(),
            super::super::installer::SkillMutationOrigin::CliInstall,
        );
        let reload = reload_controller(home.path(), crate::config::FreedomConfig::default());
        publish_installed_authority_decision(home.path(), "alpha", &reload, active_decision())
            .unwrap();
        let InstalledSkillAuthorityValidation::Active(validated) =
            validate_installed_authority(home.path(), "alpha", &reload)
        else {
            panic!("fixture authority must be active");
        };
        let generation = validated.package_generation_sha256().to_string();
        let incarnation = validated.install_incarnation();
        let install_receipt = validated.install_terminal_receipt_sha256().to_string();
        let authority_record = validated.record_sha256().to_string();
        drop(validated);

        let mut publication_guard = lock_installed_skill_publication(home.path()).unwrap();
        publication_guard
            .validate_installed_binding(
                "alpha",
                &generation,
                incarnation,
                &install_receipt,
                &authority_record,
            )
            .unwrap();

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let revoke_home = home.path().to_path_buf();
        let revoke_reload = reload.clone();
        let revoke = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let decision = SkillAuthorityDecision::new(
                SkillAuthorityDecisionSource::SecurityRevocation,
                SkillAuthorityState::Revoked,
                Some("barrier regression".to_string()),
            )
            .unwrap();
            result_tx
                .send(publish_installed_authority_decision(
                    &revoke_home,
                    "alpha",
                    &revoke_reload,
                    decision,
                ))
                .unwrap();
        });
        started_rx.recv().unwrap();
        assert!(
            result_rx
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err(),
            "revocation must remain blocked while the final snapshot guard is held"
        );
        publication_guard
            .validate_installed_binding(
                "alpha",
                &generation,
                incarnation,
                &install_receipt,
                &authority_record,
            )
            .unwrap();
        drop(publication_guard);
        result_rx
            .recv_timeout(std::time::Duration::from_secs(6))
            .unwrap()
            .unwrap();
        revoke.join().unwrap();
        assert_eq!(
            validate_installed_authority(home.path(), "alpha", &reload).inactive_reason(),
            Some(SkillAuthorityInactiveReason::DecisionRevoked)
        );
    }

    #[test]
    fn pending_replacement_suspends_previously_active_authority() {
        let home = tempfile::tempdir().unwrap();
        install_test_key(home.path());
        write_installed_skill(home.path(), "generation zero");
        record_installed_skill_incarnation(
            home.path(),
            super::super::installer::SkillMutationOrigin::CliInstall,
        );
        let reload = reload_controller(home.path(), crate::config::FreedomConfig::default());
        publish_installed_authority_decision(home.path(), "alpha", &reload, active_decision())
            .unwrap();
        super::super::mutation_lifecycle::record_pending_install_incarnation_for_test(
            home.path(),
            "alpha",
            &digest(0x72),
            super::super::installer::SkillMutationOrigin::SelfImproveAccept,
        )
        .unwrap();

        assert_eq!(
            validate_installed_authority(home.path(), "alpha", &reload).inactive_reason(),
            Some(SkillAuthorityInactiveReason::InstallIncarnationMismatch)
        );
    }

    #[test]
    fn byte_exact_rollback_does_not_reactivate_an_old_authority_receipt() {
        let home = tempfile::tempdir().unwrap();
        install_test_key(home.path());
        write_installed_skill(home.path(), "generation zero");
        record_installed_skill_incarnation(
            home.path(),
            super::super::installer::SkillMutationOrigin::CliInstall,
        );
        let reload = reload_controller(home.path(), crate::config::FreedomConfig::default());
        publish_installed_authority_decision(home.path(), "alpha", &reload, active_decision())
            .unwrap();

        write_installed_skill(home.path(), "generation one");
        record_installed_skill_incarnation(
            home.path(),
            super::super::installer::SkillMutationOrigin::SelfImproveAccept,
        );
        write_installed_skill(home.path(), "generation zero");
        record_installed_skill_incarnation(
            home.path(),
            super::super::installer::SkillMutationOrigin::SelfImproveRollback,
        );

        assert_eq!(
            validate_installed_authority(home.path(), "alpha", &reload).inactive_reason(),
            Some(SkillAuthorityInactiveReason::InstallIncarnationMismatch)
        );
    }

    #[test]
    fn uninstall_reinstall_of_identical_bytes_requires_fresh_authority() {
        let home = tempfile::tempdir().unwrap();
        install_test_key(home.path());
        write_installed_skill(home.path(), "identical generation");
        record_installed_skill_incarnation(
            home.path(),
            super::super::installer::SkillMutationOrigin::CliInstall,
        );
        let reload = reload_controller(home.path(), crate::config::FreedomConfig::default());
        publish_installed_authority_decision(home.path(), "alpha", &reload, active_decision())
            .unwrap();

        std::fs::remove_dir_all(home.path().join("skills/alpha")).unwrap();
        super::super::mutation_lifecycle::record_committed_removal_incarnation_for_test(
            home.path(),
            "alpha",
            super::super::installer::SkillMutationOrigin::CliUninstall,
        )
        .unwrap();
        write_installed_skill(home.path(), "identical generation");
        record_installed_skill_incarnation(
            home.path(),
            super::super::installer::SkillMutationOrigin::CliInstall,
        );

        assert_eq!(
            validate_installed_authority(home.path(), "alpha", &reload).inactive_reason(),
            Some(SkillAuthorityInactiveReason::InstallIncarnationMismatch)
        );
    }

    #[test]
    fn newly_accepted_disabling_policy_invalidates_prior_active_authority() {
        let home = tempfile::tempdir().unwrap();
        install_test_key(home.path());
        write_installed_skill(home.path(), "stable");
        record_installed_skill_incarnation(
            home.path(),
            super::super::installer::SkillMutationOrigin::CliInstall,
        );
        let initial = crate::config::FreedomConfig::default();
        let reload = reload_controller(home.path(), initial.clone());
        publish_installed_authority_decision(home.path(), "alpha", &reload, active_decision())
            .unwrap();

        let mut disabled = initial;
        disabled.skills.disabled.push("alpha".to_string());
        std::fs::write(
            home.path().join("freedom.yaml"),
            serde_yaml::to_string(&disabled).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            reload.try_reload().unwrap(),
            crate::config::reload::ReloadResult::Reloaded { .. }
        ));
        assert_eq!(
            validate_installed_authority(home.path(), "alpha", &reload).inactive_reason(),
            Some(SkillAuthorityInactiveReason::InstalledPolicyDisabled)
        );
    }

    #[test]
    fn accepted_content_pin_is_enforced_at_central_authority_boundary() {
        let home = tempfile::tempdir().unwrap();
        install_test_key(home.path());
        write_installed_skill(home.path(), "pinned");
        record_installed_skill_incarnation(
            home.path(),
            super::super::installer::SkillMutationOrigin::CliInstall,
        );
        let mut config = crate::config::FreedomConfig::default();
        config
            .skills
            .pinned_hashes
            .insert("alpha".to_string(), digest(0xee));
        let reload = reload_controller(home.path(), config);

        assert!(
            publish_installed_authority_decision(home.path(), "alpha", &reload, active_decision(),)
                .is_err()
        );
        assert_eq!(
            validate_installed_authority(home.path(), "alpha", &reload).inactive_reason(),
            Some(SkillAuthorityInactiveReason::PinnedContentHashMismatch)
        );
    }

    #[test]
    fn empty_effective_tool_list_is_an_exact_deny_all_claim() {
        let (home, mut record) = fixture();
        record.claims.effective_tools.clear();
        publish_authority_decision(home.path(), &record).unwrap();
        let exact = SkillAuthorityExpectation::from_record(&record);
        assert!(matches!(
            validate_current_authority(home.path(), &exact),
            SkillAuthorityValidation::Active(_)
        ));

        let mut broadened = exact;
        broadened
            .claims
            .effective_tools
            .push("mcp::fs::read".to_string());
        assert_inactive(
            home.path(),
            &broadened,
            SkillAuthorityInactiveReason::BehaviorClaimsMismatch,
        );
    }

    #[test]
    fn exact_inactive_or_revoked_decision_shadows_policy_claim_drift() {
        for state in [SkillAuthorityState::Inactive, SkillAuthorityState::Revoked] {
            let home = tempfile::tempdir().unwrap();
            install_test_key(home.path());
            let record = record("alpha", state);
            publish_authority_decision(home.path(), &record).unwrap();
            let mut changed_policy = SkillAuthorityExpectation::from_record(&record);
            changed_policy
                .claims
                .effective_tools
                .push("mcp::web::fetch".to_string());

            assert_inactive(
                home.path(),
                &changed_policy,
                match state {
                    SkillAuthorityState::Inactive => SkillAuthorityInactiveReason::DecisionInactive,
                    SkillAuthorityState::Revoked => SkillAuthorityInactiveReason::DecisionRevoked,
                    SkillAuthorityState::Active => unreachable!(),
                },
            );
        }
    }

    #[test]
    fn package_manifest_and_every_effective_claim_drift_fail_closed() {
        let (home, record) = fixture();
        publish_authority_decision(home.path(), &record).unwrap();
        let expected = SkillAuthorityExpectation::from_record(&record);

        let mut package_drift = expected.clone();
        package_drift.package_generation_sha256 = digest(0x44);
        assert_inactive(
            home.path(),
            &package_drift,
            SkillAuthorityInactiveReason::PackageGenerationMismatch,
        );

        let mut manifest_drift = expected.clone();
        manifest_drift.manifest_sha256 = digest(0x55);
        assert_inactive(
            home.path(),
            &manifest_drift,
            SkillAuthorityInactiveReason::ManifestDigestMismatch,
        );

        let mut variants = Vec::new();
        let mut changed = expected.claims.clone();
        changed.effective_tools.remove(0);
        variants.push(changed);
        let mut changed = expected.claims.clone();
        changed.effective_enabled = false;
        variants.push(changed);
        let mut changed = expected.claims.clone();
        changed.skills_policy_sha256 = digest(0x81);
        variants.push(changed);
        let mut changed = expected.claims.clone();
        changed.system_prompt_sha256 = digest(0x82);
        variants.push(changed);
        let mut changed = expected.claims.clone();
        changed.trigger_keywords_sha256 = digest(0x83);
        variants.push(changed);
        let mut changed = expected.claims.clone();
        changed.paths_sha256 = digest(0x84);
        variants.push(changed);
        let mut changed = expected.claims.clone();
        changed.modes_sha256 = digest(0x85);
        variants.push(changed);
        let mut changed = expected.claims.clone();
        changed.delegate_to = Some("other-agent".to_string());
        variants.push(changed);
        let mut changed = expected.claims.clone();
        changed.model = Some("provider/model-v2".to_string());
        variants.push(changed);
        let mut changed = expected.claims.clone();
        changed.effort = Some(EffortBudget::Low);
        variants.push(changed);
        let mut changed = expected.claims.clone();
        changed.loop_trigger = false;
        variants.push(changed);
        let mut changed = expected.claims.clone();
        changed.visibility = SkillVisibility::On;
        variants.push(changed);
        let mut changed = expected.claims.clone();
        changed.source = None;
        variants.push(changed);

        for claims in variants {
            let mut drift = expected.clone();
            drift.claims = claims;
            assert_inactive(
                home.path(),
                &drift,
                SkillAuthorityInactiveReason::BehaviorClaimsMismatch,
            );
        }
    }

    #[test]
    fn inactive_and_revoked_current_decisions_never_activate() {
        for (state, reason) in [
            (
                SkillAuthorityState::Inactive,
                SkillAuthorityInactiveReason::DecisionInactive,
            ),
            (
                SkillAuthorityState::Revoked,
                SkillAuthorityInactiveReason::DecisionRevoked,
            ),
        ] {
            let (home, _) = fixture();
            let record = record("alpha", state);
            publish_authority_decision(home.path(), &record).unwrap();
            assert_inactive(
                home.path(),
                &SkillAuthorityExpectation::from_record(&record),
                reason,
            );
        }
    }

    #[test]
    fn missing_store_anchor_record_and_key_each_fail_closed() {
        let no_store = tempfile::tempdir().unwrap();
        let record = record("alpha", SkillAuthorityState::Active);
        assert_inactive(
            no_store.path(),
            &SkillAuthorityExpectation::from_record(&record),
            SkillAuthorityInactiveReason::AuthorityStoreMissing,
        );

        let (missing_anchor_home, record) = fixture();
        initialize_authority_store(missing_anchor_home.path()).unwrap();
        initialize_authority_key_for_test(missing_anchor_home.path()).unwrap();
        assert!(
            inspect_current_authority(missing_anchor_home.path(), "alpha")
                .unwrap()
                .is_none(),
            "a completely empty authority namespace is the only missing-anchor None state"
        );
        assert_inactive(
            missing_anchor_home.path(),
            &SkillAuthorityExpectation::from_record(&record),
            SkillAuthorityInactiveReason::CurrentAnchorMissing,
        );

        let (orphan_anchor_home, record) = fixture();
        publish_authority_decision(orphan_anchor_home.path(), &record).unwrap();
        crate::util::atomic_write::durable_remove_file(&anchor_path(
            orphan_anchor_home.path(),
            &record.skill_id,
        ))
        .unwrap();
        let error = inspect_current_authority(orphan_anchor_home.path(), "alpha").unwrap_err();
        assert!(
            format!("{error:#}").contains("record or WAL evidence remains"),
            "orphan authority must not be rendered as missing authority: {error:#}"
        );

        let (missing_record_home, record) = fixture();
        let receipt = publish_authority_decision(missing_record_home.path(), &record).unwrap();
        crate::util::atomic_write::durable_remove_file(&record_path(
            missing_record_home.path(),
            &receipt.record_sha256,
        ))
        .unwrap();
        assert_inactive(
            missing_record_home.path(),
            &SkillAuthorityExpectation::from_record(&record),
            SkillAuthorityInactiveReason::AuthorityRecordMissing,
        );

        let (missing_key_home, record) = fixture();
        publish_authority_decision(missing_key_home.path(), &record).unwrap();
        crate::util::atomic_write::durable_remove_file(
            &authority_root(missing_key_home.path()).join(AUTHORITY_KEY_NAME),
        )
        .unwrap();
        assert_inactive(
            missing_key_home.path(),
            &SkillAuthorityExpectation::from_record(&record),
            SkillAuthorityInactiveReason::AuthorityKeyMissing,
        );
    }

    #[test]
    fn record_and_anchor_hmac_tamper_are_distinct_fail_closed_states() {
        let (record_home, record) = fixture();
        let receipt = publish_authority_decision(record_home.path(), &record).unwrap();
        let mut envelope = read_record_file(record_home.path(), &receipt);
        envelope.hmac_sha256 = digest(0xaa);
        private_replace(
            &record_path(record_home.path(), &receipt.record_sha256),
            &canonical_json(&envelope).unwrap(),
        );
        assert_inactive(
            record_home.path(),
            &SkillAuthorityExpectation::from_record(&record),
            SkillAuthorityInactiveReason::AuthorityRecordMacInvalid,
        );

        let (anchor_home, record) = fixture();
        publish_authority_decision(anchor_home.path(), &record).unwrap();
        let mut anchor = read_anchor_file(anchor_home.path(), &record.skill_id);
        anchor.hmac_sha256 = digest(0xbb);
        private_replace(
            &anchor_path(anchor_home.path(), &record.skill_id),
            &canonical_json(&anchor).unwrap(),
        );
        assert_inactive(
            anchor_home.path(),
            &SkillAuthorityExpectation::from_record(&record),
            SkillAuthorityInactiveReason::CurrentAnchorMacInvalid,
        );
    }

    #[test]
    fn authenticated_current_anchor_cannot_cross_bind_another_skill() {
        let home = tempfile::tempdir().unwrap();
        install_test_key(home.path());
        let alpha = record("alpha", SkillAuthorityState::Active);
        let mut beta = record("beta", SkillAuthorityState::Active);
        beta.package_generation_sha256 = digest(0x77);
        publish_authority_decision(home.path(), &alpha).unwrap();
        publish_authority_decision(home.path(), &beta).unwrap();

        let beta_anchor = std::fs::read(anchor_path(home.path(), "beta")).unwrap();
        private_replace(&anchor_path(home.path(), "alpha"), &beta_anchor);
        assert_inactive(
            home.path(),
            &SkillAuthorityExpectation::from_record(&alpha),
            SkillAuthorityInactiveReason::CurrentAnchorMismatch,
        );
    }

    #[test]
    fn record_filename_and_payload_digest_must_match_exactly() {
        let (home, record) = fixture();
        let receipt = publish_authority_decision(home.path(), &record).unwrap();
        let envelope_bytes =
            std::fs::read(record_path(home.path(), &receipt.record_sha256)).unwrap();
        let fake_digest = digest(0xcc);
        private_replace(&record_path(home.path(), &fake_digest), &envelope_bytes);

        let key = load_existing_authority_key_checked(home.path()).unwrap();
        let mut anchor = read_anchor_file(home.path(), &record.skill_id);
        anchor.anchor.record_sha256 = fake_digest;
        let canonical_anchor = canonical_json(&anchor.anchor).unwrap();
        anchor.hmac_sha256 = domain_hmac(&key, ANCHOR_HMAC_DOMAIN, &[canonical_anchor.as_slice()]);
        private_replace(
            &anchor_path(home.path(), &record.skill_id),
            &canonical_json(&anchor).unwrap(),
        );

        assert_inactive(
            home.path(),
            &SkillAuthorityExpectation::from_record(&record),
            SkillAuthorityInactiveReason::AuthorityRecordDigestMismatch,
        );
    }

    #[test]
    fn legacy_unknown_and_noncanonical_json_never_migrate_to_authority() {
        let (legacy_home, record) = fixture();
        let receipt = publish_authority_decision(legacy_home.path(), &record).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(
            &std::fs::read(record_path(legacy_home.path(), &receipt.record_sha256)).unwrap(),
        )
        .unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("legacy_enabled".to_string(), serde_json::Value::Bool(true));
        private_replace(
            &record_path(legacy_home.path(), &receipt.record_sha256),
            &serde_json::to_vec(&value).unwrap(),
        );
        assert_inactive(
            legacy_home.path(),
            &SkillAuthorityExpectation::from_record(&record),
            SkillAuthorityInactiveReason::AuthorityRecordInvalid,
        );

        let (noncanonical_home, record) = fixture();
        publish_authority_decision(noncanonical_home.path(), &record).unwrap();
        let mut bytes =
            std::fs::read(anchor_path(noncanonical_home.path(), &record.skill_id)).unwrap();
        bytes.push(b'\n');
        private_replace(
            &anchor_path(noncanonical_home.path(), &record.skill_id),
            &bytes,
        );
        assert_inactive(
            noncanonical_home.path(),
            &SkillAuthorityExpectation::from_record(&record),
            SkillAuthorityInactiveReason::CurrentAnchorInvalid,
        );
    }

    #[test]
    fn dedicated_key_replacement_or_corruption_invalidates_existing_authority() {
        let (home, record) = fixture();
        publish_authority_decision(home.path(), &record).unwrap();
        crate::wal::compaction::rewrap_key(
            &authority_root(home.path()).join(AUTHORITY_KEY_NAME),
            &[0x5a; 32],
        )
        .unwrap();
        assert_inactive(
            home.path(),
            &SkillAuthorityExpectation::from_record(&record),
            SkillAuthorityInactiveReason::CurrentAnchorMacInvalid,
        );

        private_replace(
            &authority_root(home.path()).join(AUTHORITY_KEY_NAME),
            b"short",
        );
        assert_inactive(
            home.path(),
            &SkillAuthorityExpectation::from_record(&record),
            SkillAuthorityInactiveReason::AuthorityKeyInvalid,
        );
    }

    #[test]
    fn wal_key_rotation_preserves_authority_but_retired_key_cannot_sign_it() {
        let (home, record) = fixture();
        let first = publish_authority_decision(home.path(), &record).unwrap();
        let wal_dir = home.path().join(WAL_DIRECTORY_NAME);
        let active_path = wal_dir.join(WAL_HMAC_KEY_NAME);
        let old_wal_key = crate::wal::compaction::load_existing_key(&active_path).unwrap();
        crate::wal::compaction::rewrap_key(
            &wal_dir.join("hmac.key.1700000000.archive"),
            &old_wal_key,
        )
        .unwrap();
        crate::wal::compaction::rewrap_key(&active_path, &[0x5a; 32]).unwrap();

        assert!(matches!(
            validate_current_authority(
                home.path(),
                &SkillAuthorityExpectation::from_record(&record)
            ),
            SkillAuthorityValidation::Active(_)
        ));

        let mut renewed = record.clone();
        renewed.decision_id = digest(0x5b)[..DECISION_ID_HEX_BYTES * 2].to_string();
        renewed.decided_at_unix_ms += 1;
        let second = publish_authority_decision_with_revision(home.path(), &renewed, true).unwrap();
        assert_eq!(first.authority_sequence(), 1);
        assert_eq!(second.authority_sequence(), 2);
        assert!(matches!(
            validate_current_authority(
                home.path(),
                &SkillAuthorityExpectation::from_record(&renewed)
            ),
            SkillAuthorityValidation::Active(_)
        ));

        let mut forged = record.clone();
        forged.authority_sequence = 1;
        forged.previous_record_sha256 = None;
        let forged_record_sha256 = sha256_hex(&canonical_json(&forged).unwrap());
        let payload =
            authority_wal_payload(&forged, &forged_record_sha256, None, &old_wal_key).unwrap();
        let error = authenticate_authority_wal_ingress(home.path(), &payload).unwrap_err();
        assert!(
            format!("{error:#}").contains("authentication failed"),
            "a retired WAL key must not remain an authority signer: {error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn first_publish_privately_migrates_canonical_umask_wal_directory() {
        use std::os::unix::fs::PermissionsExt as _;

        let home = tempfile::tempdir().unwrap();
        let wal_dir = home.path().join(WAL_DIRECTORY_NAME);
        std::fs::create_dir_all(&wal_dir).unwrap();
        std::fs::set_permissions(&wal_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        crate::wal::compaction::load_or_init_key(&wal_dir.join(WAL_HMAC_KEY_NAME)).unwrap();

        publish_authority_decision(home.path(), &record("alpha", SkillAuthorityState::Active))
            .unwrap();
        assert_eq!(
            std::fs::metadata(&wal_dir).unwrap().permissions().mode() & 0o7777,
            0o700
        );
    }

    #[cfg(windows)]
    #[test]
    fn authority_directories_are_private_on_the_bound_handles() {
        let (home, record) = fixture();
        publish_authority_decision(home.path(), &record).unwrap();

        let store = open_existing_authority_store(home.path()).unwrap();
        crate::wal::win_native::verify_private_directory_handle_dacl(&store.root.dir).unwrap();
        crate::wal::win_native::verify_private_directory_handle_dacl(&store.records).unwrap();
        crate::wal::win_native::verify_private_directory_handle_dacl(&store.current).unwrap();

        let namespace =
            open_existing_record_namespace(&store, &record.skill_id).expect("record namespace");
        crate::wal::win_native::verify_private_directory_handle_dacl(&namespace).unwrap();
    }

    #[test]
    fn immutable_record_publish_is_idempotent_and_new_decision_gets_new_digest() {
        let (home, record) = fixture();
        let first = publish_authority_decision(home.path(), &record).unwrap();
        let second = publish_authority_decision(home.path(), &record).unwrap();
        assert_eq!(first, second);

        let mut forced = record.clone();
        forced.decision_id = digest(0x65)[..DECISION_ID_HEX_BYTES * 2].to_string();
        forced.decided_at_unix_ms += 1;
        let forced_receipt =
            publish_authority_decision_with_revision(home.path(), &forced, true).unwrap();
        assert_eq!(forced_receipt.authority_sequence(), 2);
        assert_ne!(first.record_sha256(), forced_receipt.record_sha256());

        let mut revoked = record.clone();
        revoked.state = SkillAuthorityState::Revoked;
        revoked.decision_reason = Some("operator revoked this generation".to_string());
        revoked.decision_id = digest(0x66)[..DECISION_ID_HEX_BYTES * 2].to_string();
        revoked.decided_at_unix_ms += 1;
        let revoked_receipt = publish_authority_decision(home.path(), &revoked).unwrap();
        assert_eq!(revoked_receipt.authority_sequence(), 3);
        assert_ne!(first.record_sha256, revoked_receipt.record_sha256);
        assert!(record_path(home.path(), &first.record_sha256).is_file());
        assert!(record_path(home.path(), &revoked_receipt.record_sha256).is_file());
        assert_inactive(
            home.path(),
            &SkillAuthorityExpectation::from_record(&revoked),
            SkillAuthorityInactiveReason::DecisionRevoked,
        );
    }

    #[test]
    fn revoke_is_terminal_for_the_exact_install_incarnation_only() {
        let (home, active) = fixture();
        publish_authority_decision(home.path(), &active).unwrap();

        let mut revoked = active.clone();
        revoked.state = SkillAuthorityState::Revoked;
        revoked.decision_reason = Some("operator permanently revoked this install".to_string());
        revoked.decision_id = digest(0x74)[..DECISION_ID_HEX_BYTES * 2].to_string();
        revoked.decided_at_unix_ms += 1;
        publish_authority_decision(home.path(), &revoked).unwrap();

        let mut replayed_active = active.clone();
        replayed_active.decision_id = digest(0x75)[..DECISION_ID_HEX_BYTES * 2].to_string();
        replayed_active.decided_at_unix_ms += 2;
        let error = publish_authority_decision(home.path(), &replayed_active).unwrap_err();
        assert!(
            format!("{error:#}").contains("terminally revoked"),
            "unexpected exact-incarnation reactivation result: {error:#}"
        );

        let mut reinstalled_active = replayed_active;
        reinstalled_active.install_incarnation += 1;
        reinstalled_active.install_terminal_receipt_sha256 = digest(0x76);
        let receipt = publish_authority_decision(home.path(), &reinstalled_active).unwrap();
        assert_eq!(receipt.authority_sequence(), 3);
        assert_eq!(receipt.state(), SkillAuthorityState::Active);
    }

    #[test]
    fn stale_active_anchor_cannot_replay_over_retained_revocation_tail() {
        let (home, active) = fixture();
        let active_receipt = publish_authority_decision(home.path(), &active).unwrap();
        let stale_anchor = std::fs::read(anchor_path(home.path(), &active.skill_id)).unwrap();

        let mut revoked = active.clone();
        revoked.state = SkillAuthorityState::Revoked;
        revoked.decision_reason = Some("operator revoked this generation".to_string());
        revoked.decision_id = digest(0x67)[..DECISION_ID_HEX_BYTES * 2].to_string();
        revoked.decided_at_unix_ms += 1;
        let revoked_receipt = publish_authority_decision(home.path(), &revoked).unwrap();
        assert_eq!(active_receipt.authority_sequence(), 1);
        assert_eq!(revoked_receipt.authority_sequence(), 2);

        private_replace(&anchor_path(home.path(), &active.skill_id), &stale_anchor);
        assert_inactive(
            home.path(),
            &SkillAuthorityExpectation::from_record(&revoked),
            SkillAuthorityInactiveReason::CurrentAnchorMismatch,
        );
    }

    #[test]
    fn deleting_revocation_record_and_replaying_old_anchor_stays_inactive() {
        let (home, active) = fixture();
        publish_authority_decision(home.path(), &active).unwrap();
        let stale_anchor = std::fs::read(anchor_path(home.path(), &active.skill_id)).unwrap();

        let mut revoked = active.clone();
        revoked.state = SkillAuthorityState::Revoked;
        revoked.decision_reason = Some("security revocation".to_string());
        revoked.decision_id = digest(0x68)[..DECISION_ID_HEX_BYTES * 2].to_string();
        revoked.decided_at_unix_ms += 1;
        let revoked_receipt = publish_authority_decision(home.path(), &revoked).unwrap();

        std::fs::remove_file(record_path(home.path(), &revoked_receipt.record_sha256)).unwrap();
        private_replace(&anchor_path(home.path(), &active.skill_id), &stale_anchor);
        assert_inactive(
            home.path(),
            &SkillAuthorityExpectation::from_record(&active),
            SkillAuthorityInactiveReason::AuthorityWalHeadMismatch,
        );
    }

    #[test]
    fn record_first_crash_notifies_before_anchor_and_is_recoverable_by_identical_retry() {
        let (home, record) = fixture();
        let mut transitions =
            super::super::registry::subscribe_runtime_authority_transitions_for_test();
        TEST_FAIL_ANCHOR_BEFORE_RENAME.with(|fail| fail.set(true));
        assert!(publish_authority_decision(home.path(), &record).is_err());
        assert!(!anchor_path(home.path(), &record.skill_id).exists());
        let expected_home =
            std::fs::canonicalize(home.path()).unwrap_or_else(|_| home.path().to_path_buf());
        let mut saw_authority_transition = false;
        while let Ok((observed_home, kind)) = transitions.try_recv() {
            if observed_home == expected_home
                && kind == super::super::registry::RuntimeAuthorityTransitionKind::AuthorityDecision
            {
                saw_authority_transition = true;
            }
        }
        assert!(
            saw_authority_transition,
            "the durable authority WAL head must wake the runtime before anchor publication"
        );

        let recovered = publish_authority_decision(home.path(), &record).unwrap();
        assert_eq!(recovered.authority_sequence(), 1);
        assert!(matches!(
            validate_current_authority(
                home.path(),
                &SkillAuthorityExpectation::from_record(&record)
            ),
            SkillAuthorityValidation::Active(_)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn authority_wal_parent_sync_failure_never_publishes_the_anchor() {
        let (home, record) = fixture();
        crate::wal::writer::fail_segment_parent_sync_for_test(&home.path().join("wal"));

        let error = publish_authority_decision(home.path(), &record).unwrap_err();
        assert!(
            format!("{error:#}").contains("parent-directory sync failure"),
            "unexpected publication failure: {error:#}"
        );
        assert!(
            !anchor_path(home.path(), &record.skill_id).exists(),
            "an authority anchor must not publish without a durable WAL directory entry"
        );
        assert!(
            !scan_authority_wal_head_exists_for_test(home.path(), &record.skill_id).unwrap(),
            "failed parent fsync must not manufacture an authenticated WAL head"
        );

        let recovered = publish_authority_decision(home.path(), &record).unwrap();
        assert_eq!(recovered.durability(), expected_platform_durability());
        assert_eq!(recovered.authority_sequence(), 1);
    }

    #[test]
    fn recovery_never_anchors_orphan_active_record_under_new_disabling_policy() {
        let home = tempfile::tempdir().unwrap();
        install_test_key(home.path());
        write_installed_skill(home.path(), "recovery policy");
        record_installed_skill_incarnation(
            home.path(),
            super::super::installer::SkillMutationOrigin::CliInstall,
        );
        let initial = crate::config::FreedomConfig::default();
        let reload = reload_controller(home.path(), initial.clone());

        TEST_FAIL_ANCHOR_BEFORE_RENAME.with(|fail| fail.set(true));
        assert!(
            publish_installed_authority_decision(home.path(), "alpha", &reload, active_decision(),)
                .is_err()
        );
        assert!(!anchor_path(home.path(), "alpha").exists());

        let mut disabled = initial;
        disabled.skills.disabled.push("alpha".to_string());
        std::fs::write(
            home.path().join("freedom.yaml"),
            serde_yaml::to_string(&disabled).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            reload.try_reload().unwrap(),
            crate::config::reload::ReloadResult::Reloaded { .. }
        ));
        assert!(recover_pending_installed_authority(home.path(), "alpha", &reload).is_err());
        assert!(!anchor_path(home.path(), "alpha").exists());
    }

    #[test]
    fn record_sync_failure_retries_without_publishing_anchor_early() {
        let (home, record) = fixture();
        TEST_FAIL_RECORD_SYNC_AFTER_RENAME.with(|fail| fail.set(true));
        assert!(publish_authority_decision(home.path(), &record).is_err());
        assert!(!anchor_path(home.path(), &record.skill_id).exists());

        let receipt = publish_authority_decision(home.path(), &record).unwrap();
        assert_eq!(receipt.durability(), expected_platform_durability());
    }

    #[test]
    fn post_anchor_rename_failures_return_typed_committed_states() {
        let (sync_home, record) = fixture();
        TEST_FAIL_ANCHOR_SYNC_AFTER_RENAME.with(|fail| fail.set(true));
        let unconfirmed = publish_authority_decision(sync_home.path(), &record).unwrap();
        assert_eq!(
            unconfirmed.durability(),
            SkillAuthorityDurability::Unconfirmed
        );
        assert!(matches!(
            validate_current_authority(
                sync_home.path(),
                &SkillAuthorityExpectation::from_record(&record)
            ),
            SkillAuthorityValidation::Active(_)
        ));

        let (readback_home, record) = fixture();
        TEST_FAIL_ANCHOR_READBACK_AFTER_RENAME.with(|fail| fail.set(true));
        let uncertain = publish_authority_decision(readback_home.path(), &record).unwrap();
        assert_eq!(
            uncertain.durability(),
            SkillAuthorityDurability::StateUncertain
        );
    }

    #[test]
    fn namespace_scan_counts_before_filtering_and_rejects_unknown_entries() {
        let (home, _) = fixture();
        initialize_authority_store(home.path()).unwrap();
        let store = open_existing_authority_store(home.path()).unwrap();
        let records = open_record_namespace_for_publish(&store, "alpha").unwrap();
        let records_path = store.records_path.join("alpha");
        private_replace(
            &records_path.join(format!(
                "{AUTHORITY_STAGE_PREFIX}{}",
                &digest(0x01)[..DECISION_ID_HEX_BYTES * 2]
            )),
            b"a",
        );
        private_replace(
            &records_path.join(format!(
                "{AUTHORITY_STAGE_PREFIX}{}",
                &digest(0x02)[..DECISION_ID_HEX_BYTES * 2]
            )),
            b"b",
        );
        assert!(
            scan_namespace_with_limit(&records, &records_path, 1)
                .unwrap_err()
                .to_string()
                .contains("entry limit")
        );
    }

    #[test]
    fn unrelated_record_namespace_damage_does_not_globally_disable_active_skill() {
        let (home, record) = fixture();
        publish_authority_decision(home.path(), &record).unwrap();
        let store = open_existing_authority_store(home.path()).unwrap();
        let unrelated = open_record_namespace_for_publish(&store, "beta").unwrap();
        let unrelated_path = store.records_path.join("beta");
        private_replace(&unrelated_path.join("unexpected"), b"x");
        drop(unrelated);
        drop(store);

        assert!(matches!(
            validate_current_authority(
                home.path(),
                &SkillAuthorityExpectation::from_record(&record)
            ),
            SkillAuthorityValidation::Active(_)
        ));
    }

    #[test]
    fn invalid_ids_and_parent_components_never_escape_the_store() {
        assert!(current_anchor_path(Path::new("home"), "../escape").is_err());
        let home = tempfile::tempdir().unwrap();
        let path_with_parent = home.path().join("nested").join("..").join("instance");
        assert!(initialize_authority_store(&path_with_parent).is_err());
        assert!(
            !home
                .path()
                .join("instance")
                .join(AUTHORITY_ROOT_NAME)
                .exists()
        );
    }

    #[test]
    fn per_skill_policy_hash_is_order_stable_and_ignores_unrelated_policy() {
        let mut left = crate::config::SkillsConfig::default();
        left.enabled = vec![" BETA ".to_string(), "ALPHA".to_string()];
        left.disabled = vec!["other".to_string(), "ALPHA".to_string()];
        left.visibility_overrides
            .insert("other".to_string(), SkillVisibility::Off);
        left.visibility_overrides
            .insert("ALPHA".to_string(), SkillVisibility::NameOnly);
        left.pinned_hashes.insert("other".to_string(), digest(0x41));
        left.pinned_hashes.insert("alpha".to_string(), digest(0x42));

        let mut right = crate::config::SkillsConfig::default();
        right.enabled = vec!["alpha".to_string(), "beta".to_string(), "alpha".to_string()];
        right.disabled = vec!["alpha".to_string(), "OTHER".to_string()];
        right
            .visibility_overrides
            .insert("alpha".to_string(), SkillVisibility::NameOnly);
        right
            .visibility_overrides
            .insert("unrelated".to_string(), SkillVisibility::On);
        right
            .pinned_hashes
            .insert("alpha".to_string(), digest(0x42));
        right
            .pinned_hashes
            .insert("unrelated".to_string(), digest(0x99));
        right.session_catalog = true;
        right.auto_distill = false;
        right.meeting_summary.admin = Some("unrelated".to_string());

        assert_eq!(
            effective_skill_policy_sha256(&left, "alpha").unwrap(),
            effective_skill_policy_sha256(&right, "alpha").unwrap()
        );
        right.enable_all_bundled = !left.enable_all_bundled;
        assert_eq!(
            effective_skill_policy_sha256(&left, "alpha").unwrap(),
            effective_skill_policy_sha256(&right, "alpha").unwrap(),
            "bundled-default policy must not stale installed-Skill authority"
        );
        right.always_embed_route = !left.always_embed_route;
        assert_ne!(
            effective_skill_policy_sha256(&left, "alpha").unwrap(),
            effective_skill_policy_sha256(&right, "alpha").unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn weak_directory_or_file_modes_fail_closed() {
        use std::os::unix::fs::PermissionsExt as _;

        let (root_home, record) = fixture();
        publish_authority_decision(root_home.path(), &record).unwrap();
        std::fs::set_permissions(
            authority_root(root_home.path()),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert_inactive(
            root_home.path(),
            &SkillAuthorityExpectation::from_record(&record),
            SkillAuthorityInactiveReason::AuthorityStoreInvalid,
        );

        let (file_home, record) = fixture();
        publish_authority_decision(file_home.path(), &record).unwrap();
        std::fs::set_permissions(
            anchor_path(file_home.path(), &record.skill_id),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert_inactive(
            file_home.path(),
            &SkillAuthorityExpectation::from_record(&record),
            SkillAuthorityInactiveReason::CurrentAnchorInvalid,
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_anchor_and_store_paths_fail_closed_without_following() {
        use std::os::unix::fs::symlink;

        let (anchor_home, active_record) = fixture();
        publish_authority_decision(anchor_home.path(), &active_record).unwrap();
        let anchor = anchor_path(anchor_home.path(), &active_record.skill_id);
        let outside = anchor_home.path().join("outside-anchor");
        std::fs::write(&outside, b"not authority").unwrap();
        std::fs::remove_file(&anchor).unwrap();
        symlink(&outside, &anchor).unwrap();
        assert_inactive(
            anchor_home.path(),
            &SkillAuthorityExpectation::from_record(&active_record),
            SkillAuthorityInactiveReason::CurrentAnchorInvalid,
        );

        let store_home = tempfile::tempdir().unwrap();
        install_test_key(store_home.path());
        let outside_dir = tempfile::tempdir().unwrap();
        symlink(
            outside_dir.path(),
            store_home.path().join(AUTHORITY_ROOT_NAME),
        )
        .unwrap();
        let record = record("alpha", SkillAuthorityState::Active);
        assert_inactive(
            store_home.path(),
            &SkillAuthorityExpectation::from_record(&record),
            SkillAuthorityInactiveReason::AuthorityStoreInvalid,
        );
    }
}
