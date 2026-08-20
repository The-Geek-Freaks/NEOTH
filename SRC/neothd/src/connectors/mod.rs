//! Typed, fail-closed connector control-plane contracts.
//!
//! This module deliberately stops at descriptor, configuration, and policy
//! admission.  It does not perform sync, execute actions, dispatch MCP tools,
//! install software, or read credentials.  Those effectful seams must be
//! added as later, separately-gated slices.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const CONNECTOR_REGISTRY_SCHEMA_VERSION: u32 = 1;
const MAX_ID_LEN: usize = 64;
const MAX_CREDENTIAL_REF_LEN: usize = 128;

/// The closed, canonical connector namespace.  Parsing is intentionally
/// exact: aliases, whitespace trimming, and case-folding would make durable
/// account identity ambiguous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorId {
    LocalImport,
    Obsidian,
    AgentReachResearch,
}

impl ConnectorId {
    pub const ALL: &'static [Self] = &[Self::LocalImport, Self::Obsidian, Self::AgentReachResearch];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalImport => "local_import",
            Self::Obsidian => "obsidian",
            Self::AgentReachResearch => "agent_reach_research",
        }
    }
}

impl fmt::Display for ConnectorId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ConnectorId {
    type Err = UnknownConnectorId;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "local_import" => Ok(Self::LocalImport),
            "obsidian" => Ok(Self::Obsidian),
            "agent_reach_research" => Ok(Self::AgentReachResearch),
            _ => Err(UnknownConnectorId(value.to_owned())),
        }
    }
}

impl<'de> Deserialize<'de> for ConnectorId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown or non-canonical connector id `{0}`")]
pub struct UnknownConnectorId(String);

/// Stable account identifier, namespaced by [`ConnectorId`] in
/// [`ConnectorInstanceId`].  It is never an operator-channel identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ConnectorAccountId(String);

impl ConnectorAccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, StrictIdError> {
        let value = value.into();
        validate_strict_id(&value, "connector account")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ConnectorAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for ConnectorAccountId {
    type Err = StrictIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for ConnectorAccountId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Stable subject identifier.  Subjects deliberately remain independent from
/// connector accounts and channel sender identities.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct SubjectId(String);

impl SubjectId {
    pub fn new(value: impl Into<String>) -> Result<Self, StrictIdError> {
        let value = value.into();
        validate_strict_id(&value, "subject")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SubjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for SubjectId {
    type Err = StrictIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for SubjectId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// A unique control-plane identity.  A missing account denotes the one local
/// instance of an accountless connector, not a wildcard account.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct ConnectorInstanceId {
    pub connector_id: ConnectorId,
    pub account_id: Option<ConnectorAccountId>,
}

impl ConnectorInstanceId {
    pub const fn accountless(connector_id: ConnectorId) -> Self {
        Self {
            connector_id,
            account_id: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "invalid {kind} id `{value}`; use 1..={MAX_ID_LEN} lowercase ASCII letters/digits with internal `_` or `-`"
)]
pub struct StrictIdError {
    kind: &'static str,
    value: String,
}

fn validate_strict_id(value: &str, kind: &'static str) -> Result<(), StrictIdError> {
    let bytes = value.as_bytes();
    let is_alnum = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let valid = !bytes.is_empty()
        && bytes.len() <= MAX_ID_LEN
        && is_alnum(bytes[0])
        && is_alnum(bytes[bytes.len() - 1])
        && bytes
            .iter()
            .copied()
            .all(|byte| is_alnum(byte) || byte == b'_' || byte == b'-');
    if valid {
        Ok(())
    } else {
        Err(StrictIdError {
            kind,
            value: value.to_owned(),
        })
    }
}

/// A SecretStore lookup key, never credential material.  Its inner string is
/// deliberately private; `Debug` and `Display` redact it so diagnostics cannot
/// accidentally turn a persistence reference into a loggable secret value.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CredentialRef(String);

impl CredentialRef {
    pub fn new(value: impl Into<String>) -> Result<Self, CredentialRefError> {
        let value = value.into();
        // A persisted credential reference is deliberately not a generic
        // `secret/<string>` bag: that shape could accept real API tokens after
        // a cosmetic prefix.  References live in one closed SecretStore
        // namespace and end in the same bounded identifier grammar used by
        // connector/account identities.
        let reference_id = value.strip_prefix("secret/connectors/");
        let valid = value.len() <= MAX_CREDENTIAL_REF_LEN
            && reference_id
                .map(|id| {
                    validate_strict_id(id, "credential reference id").is_ok()
                        && !has_secret_material_prefix(id)
                })
                .unwrap_or(false);
        if valid {
            Ok(Self(value))
        } else {
            Err(CredentialRefError)
        }
    }
}

/// Reject well-known credential wire prefixes even inside the otherwise-valid
/// SecretStore reference namespace. This prevents callers from turning secret
/// material into a persistable lookup key by prepending `secret/connectors/`.
fn has_secret_material_prefix(value: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "sk-",
        "sk_",
        "ya29.",
        "ghp_",
        "github_pat_",
        "xoxb-",
        "xapp-",
        "akia",
        "bearer-",
    ];

    PREFIXES.iter().any(|prefix| value.starts_with(prefix))
}

impl fmt::Debug for CredentialRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialRef(<redacted>)")
    }
}

impl fmt::Display for CredentialRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<credential-ref>")
    }
}

impl Serialize for CredentialRef {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CredentialRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "credential reference must be a bounded canonical `secret/connectors/<id>` SecretStore key, never credential material"
)]
pub struct CredentialRefError;

/// Closed connector role vocabulary.  This is a descriptor classification, not
/// a runtime permission token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorRole {
    AgentChannel,
    ContextSource,
    ResearchBackend,
    ActionSink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ConnectorRoles(u8);

impl ConnectorRoles {
    const AGENT_CHANNEL_MASK: u8 = 1 << 0;
    const CONTEXT_SOURCE_MASK: u8 = 1 << 1;
    const RESEARCH_BACKEND_MASK: u8 = 1 << 2;
    const ACTION_SINK_MASK: u8 = 1 << 3;

    pub const NONE: Self = Self(0);
    pub const CHANNEL: Self = Self(Self::AGENT_CHANNEL_MASK);
    pub const CONTEXT_SOURCE: Self = Self(Self::CONTEXT_SOURCE_MASK);
    pub const RESEARCH_BACKEND: Self = Self(Self::RESEARCH_BACKEND_MASK);
    pub const ACTION_SINK: Self = Self(Self::ACTION_SINK_MASK);

    pub const fn contains(self, role: ConnectorRole) -> bool {
        let bit = match role {
            ConnectorRole::AgentChannel => Self::AGENT_CHANNEL_MASK,
            ConnectorRole::ContextSource => Self::CONTEXT_SOURCE_MASK,
            ConnectorRole::ResearchBackend => Self::RESEARCH_BACKEND_MASK,
            ConnectorRole::ActionSink => Self::ACTION_SINK_MASK,
        };
        self.0 & bit != 0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountBinding {
    LocalSystem,
    AccountRequired,
    Forbidden,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextAccess {
    None,
    ReadOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportClass {
    None,
    ExplicitOperatorSelected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressClass {
    None,
    LocalOnly,
    PolicyGatedNetwork,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialClass {
    None,
    SecretStoreReference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectClass {
    None,
    PermitBound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ActionCapabilities {
    pub draft_creation: bool,
    pub mutation: bool,
    pub communication: bool,
}

impl ActionCapabilities {
    pub const NONE: Self = Self {
        draft_creation: false,
        mutation: false,
        communication: false,
    };

    pub const fn any(self) -> bool {
        self.draft_creation || self.mutation || self.communication
    }
}

/// Technical affordances only.  In particular, action capabilities cannot
/// confer agent authority or make an execution route admissible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ConnectorCapabilities {
    pub context_access: ContextAccess,
    pub import_class: ImportClass,
    pub egress: EgressClass,
    pub credential_class: CredentialClass,
    pub side_effects: SideEffectClass,
    pub actions: ActionCapabilities,
    pub direct_execution: bool,
    pub mcp_dispatch: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorAvailability {
    Available,
    DisabledExperimental,
}

/// Resource bounds are a policy snapshot, never a best-effort suggestion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_items_per_run: u32,
    pub max_bytes_per_item: u64,
    pub max_total_bytes_per_run: u64,
    pub max_runtime_seconds: u32,
}

impl ResourceLimits {
    pub const LOCAL_DEFAULT: Self = Self {
        max_items_per_run: 1_000,
        max_bytes_per_item: 16 * 1024 * 1024,
        max_total_bytes_per_run: 128 * 1024 * 1024,
        max_runtime_seconds: 300,
    };

    fn is_valid(self) -> bool {
        self.max_items_per_run > 0
            && self.max_bytes_per_item > 0
            && self.max_total_bytes_per_run >= self.max_bytes_per_item
            && self.max_runtime_seconds > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentState {
    Denied,
    ExplicitlyGranted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionClass {
    MetadataOnly,
    EncryptedEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEgress {
    DenyAll,
    LocalOnly,
    ApprovedNetwork,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentAuthority {
    Denied,
    /// Reserved for a later permit-bound action contract; never sufficient to
    /// execute an action in this descriptor-only slice.
    MayRequestPermit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectPolicy {
    Forbidden,
    PermitRequired,
}

/// Immutable-at-use policy input.  A later supervisor must take a fresh
/// snapshot for each credential, egress, or provider-boundary fallback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorPolicySnapshot {
    pub revision: u64,
    pub consent: ConsentState,
    pub retention: RetentionClass,
    pub egress: PolicyEgress,
    pub agent_authority: AgentAuthority,
    pub side_effects: SideEffectPolicy,
    pub limits: ResourceLimits,
}

impl ConnectorPolicySnapshot {
    pub const fn deny_all() -> Self {
        Self {
            revision: 0,
            consent: ConsentState::Denied,
            retention: RetentionClass::MetadataOnly,
            egress: PolicyEgress::DenyAll,
            agent_authority: AgentAuthority::Denied,
            side_effects: SideEffectPolicy::Forbidden,
            limits: ResourceLimits {
                max_items_per_run: 0,
                max_bytes_per_item: 0,
                max_total_bytes_per_run: 0,
                max_runtime_seconds: 0,
            },
        }
    }

    pub const fn local_read_only(revision: u64) -> Self {
        Self {
            revision,
            consent: ConsentState::ExplicitlyGranted,
            retention: RetentionClass::EncryptedEvidence,
            egress: PolicyEgress::LocalOnly,
            agent_authority: AgentAuthority::Denied,
            side_effects: SideEffectPolicy::Forbidden,
            limits: ResourceLimits::LOCAL_DEFAULT,
        }
    }
}

/// Persistable configuration that holds only a SecretStore reference.  It is
/// intentionally not a runnable connector object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorConfiguration {
    pub connector_id: ConnectorId,
    pub account_id: Option<ConnectorAccountId>,
    pub subject_id: SubjectId,
    pub credential_ref: Option<CredentialRef>,
    pub policy: ConnectorPolicySnapshot,
}

impl ConnectorConfiguration {
    pub fn instance_id(&self) -> ConnectorInstanceId {
        ConnectorInstanceId {
            connector_id: self.connector_id,
            account_id: self.account_id.clone(),
        }
    }
}

/// Health is evidence about an attempted probe, never a mutable authority,
/// readiness grant, credential proof, or fallback decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct HealthObservation {
    pub observed_at_unix_ms: i64,
    pub reachable: bool,
    pub error_code: Option<&'static str>,
}

/// One closed registry row.  Descriptors may advertise technical capability;
/// the configuration validator and later permit systems decide admissibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ConnectorDescriptor {
    pub id: ConnectorId,
    pub display_name: &'static str,
    pub roles: ConnectorRoles,
    pub account_binding: AccountBinding,
    pub capabilities: ConnectorCapabilities,
    pub availability: ConnectorAvailability,
}

const READ_ONLY_LOCAL_CAPABILITIES: ConnectorCapabilities = ConnectorCapabilities {
    context_access: ContextAccess::ReadOnly,
    import_class: ImportClass::ExplicitOperatorSelected,
    egress: EgressClass::LocalOnly,
    credential_class: CredentialClass::None,
    side_effects: SideEffectClass::None,
    actions: ActionCapabilities::NONE,
    direct_execution: false,
    mcp_dispatch: false,
};

const RESEARCH_REFERENCE_CAPABILITIES: ConnectorCapabilities = ConnectorCapabilities {
    context_access: ContextAccess::None,
    import_class: ImportClass::None,
    egress: EgressClass::None,
    credential_class: CredentialClass::None,
    side_effects: SideEffectClass::None,
    actions: ActionCapabilities::NONE,
    direct_execution: false,
    mcp_dispatch: false,
};

/// The only CC-01 connector inventory.  `agent_reach_research` is retained as
/// a visibly disabled architecture/Doctor reference; it is not an adapter.
pub static CONNECTOR_REGISTRY: &[ConnectorDescriptor] = &[
    ConnectorDescriptor {
        id: ConnectorId::LocalImport,
        display_name: "Local Import",
        roles: ConnectorRoles::CONTEXT_SOURCE,
        account_binding: AccountBinding::LocalSystem,
        capabilities: READ_ONLY_LOCAL_CAPABILITIES,
        availability: ConnectorAvailability::Available,
    },
    ConnectorDescriptor {
        id: ConnectorId::Obsidian,
        display_name: "Obsidian",
        roles: ConnectorRoles::CONTEXT_SOURCE,
        account_binding: AccountBinding::LocalSystem,
        capabilities: READ_ONLY_LOCAL_CAPABILITIES,
        availability: ConnectorAvailability::Available,
    },
    ConnectorDescriptor {
        id: ConnectorId::AgentReachResearch,
        display_name: "Agent-Reach Research (reference only)",
        roles: ConnectorRoles::RESEARCH_BACKEND,
        account_binding: AccountBinding::Forbidden,
        capabilities: RESEARCH_REFERENCE_CAPABILITIES,
        availability: ConnectorAvailability::DisabledExperimental,
    },
];

pub fn connector_descriptors() -> &'static [ConnectorDescriptor] {
    CONNECTOR_REGISTRY
}

pub fn descriptor(id: ConnectorId) -> &'static ConnectorDescriptor {
    CONNECTOR_REGISTRY
        .iter()
        .find(|descriptor| descriptor.id == id)
        .expect("every closed ConnectorId variant must have a registry descriptor")
}

/// Descriptor-only role contracts.  These traits intentionally expose no
/// `sync`, `execute`, `MCP`, direct-process, or credential methods.
pub trait AgentChannel: Send + Sync {
    fn descriptor(&self) -> &'static ConnectorDescriptor;
}

pub trait ContextSource: Send + Sync {
    fn descriptor(&self) -> &'static ConnectorDescriptor;
}

pub trait ResearchBackend: Send + Sync {
    fn descriptor(&self) -> &'static ConnectorDescriptor;
}

pub trait ActionSink: Send + Sync {
    fn descriptor(&self) -> &'static ConnectorDescriptor;
}

/// Admission points are distinct on purpose.  No route can be inferred from
/// a context role or a technical action capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorEntryPoint {
    ChannelRouting,
    ContextImport,
    ResearchJob,
    ActionExecution,
    McpDispatch,
    DirectExecution,
}

pub fn validate_registry() -> Result<(), ConnectorRegistryError> {
    let mut ids = BTreeSet::new();
    for descriptor in CONNECTOR_REGISTRY {
        if !ids.insert(descriptor.id) {
            return Err(ConnectorRegistryError::DuplicateCanonicalId(descriptor.id));
        }
        validate_descriptor(descriptor)?;
    }
    for id in ConnectorId::ALL {
        if !ids.contains(id) {
            return Err(ConnectorRegistryError::MissingDescriptor(*id));
        }
    }
    Ok(())
}

/// Validates capability combinations independent from the static registry so
/// tests and future generated registry builders fail before accepting a bad
/// descriptor.
pub fn validate_descriptor(descriptor: &ConnectorDescriptor) -> Result<(), ConnectorRegistryError> {
    if descriptor.roles == ConnectorRoles::NONE {
        return Err(ConnectorRegistryError::MissingRole(descriptor.id));
    }

    let capabilities = descriptor.capabilities;
    if descriptor.roles.contains(ConnectorRole::ContextSource)
        && descriptor.roles.contains(ConnectorRole::AgentChannel)
    {
        return Err(ConnectorRegistryError::ContextSourceCannotBeAgentChannel(
            descriptor.id,
        ));
    }

    if descriptor.roles.contains(ConnectorRole::ResearchBackend)
        && (descriptor.roles != ConnectorRoles::RESEARCH_BACKEND
            || descriptor.account_binding != AccountBinding::Forbidden
            || capabilities.context_access != ContextAccess::None
            || capabilities.import_class != ImportClass::None
            || capabilities.egress != EgressClass::None
            || capabilities.credential_class != CredentialClass::None
            || capabilities.actions.any()
            || capabilities.side_effects != SideEffectClass::None
            || capabilities.direct_execution
            || capabilities.mcp_dispatch)
    {
        return Err(ConnectorRegistryError::UnsafeResearchBackend(descriptor.id));
    }

    if descriptor.roles.contains(ConnectorRole::ContextSource)
        && capabilities.import_class != ImportClass::ExplicitOperatorSelected
    {
        return Err(ConnectorRegistryError::ContextSourceMissingExplicitImport(
            descriptor.id,
        ));
    }

    if descriptor.roles.contains(ConnectorRole::ContextSource)
        && (capabilities.context_access != ContextAccess::ReadOnly
            || capabilities.actions.any()
            || capabilities.side_effects != SideEffectClass::None
            || capabilities.direct_execution
            || capabilities.mcp_dispatch)
    {
        return Err(ConnectorRegistryError::ContextSourceNotReadOnly(
            descriptor.id,
        ));
    }

    if !descriptor.roles.contains(ConnectorRole::ActionSink) && capabilities.actions.any() {
        return Err(ConnectorRegistryError::ActionCapabilityWithoutSink(
            descriptor.id,
        ));
    }

    if descriptor.availability == ConnectorAvailability::DisabledExperimental
        && descriptor.roles != ConnectorRoles::RESEARCH_BACKEND
    {
        return Err(ConnectorRegistryError::FeatureDisabledDescriptorNotResearch(descriptor.id));
    }
    Ok(())
}

/// Validates all persisted configuration before any future sync/action layer
/// can obtain a connector instance.  It is intentionally fail-closed.
pub fn validate_configurations(
    configurations: &[ConnectorConfiguration],
) -> Result<(), ConnectorConfigurationError> {
    validate_registry().map_err(ConnectorConfigurationError::Registry)?;
    let mut instances = BTreeSet::new();
    for configuration in configurations {
        let descriptor = descriptor(configuration.connector_id);
        let instance = configuration.instance_id();
        if !instances.insert(instance) {
            return Err(ConnectorConfigurationError::DuplicateOrAmbiguousInstance(
                configuration.connector_id,
            ));
        }
        validate_configuration(descriptor, configuration)?;
    }
    Ok(())
}

fn validate_configuration(
    descriptor: &ConnectorDescriptor,
    configuration: &ConnectorConfiguration,
) -> Result<(), ConnectorConfigurationError> {
    if descriptor.availability != ConnectorAvailability::Available {
        return Err(ConnectorConfigurationError::FeatureDisabled(descriptor.id));
    }
    match (
        descriptor.account_binding,
        configuration.account_id.is_some(),
    ) {
        (AccountBinding::Forbidden, true) | (AccountBinding::LocalSystem, true) => {
            return Err(ConnectorConfigurationError::AccountNotSupported(
                descriptor.id,
            ));
        }
        (AccountBinding::AccountRequired, false) => {
            return Err(ConnectorConfigurationError::AccountRequired(descriptor.id));
        }
        _ => {}
    }
    match (
        descriptor.capabilities.credential_class,
        configuration.credential_ref.is_some(),
    ) {
        (CredentialClass::None, true) => {
            return Err(ConnectorConfigurationError::CredentialNotSupported(
                descriptor.id,
            ));
        }
        (CredentialClass::SecretStoreReference, false) => {
            return Err(ConnectorConfigurationError::CredentialRequired(
                descriptor.id,
            ));
        }
        _ => {}
    }
    validate_policy(descriptor, &configuration.policy)
}

fn validate_policy(
    descriptor: &ConnectorDescriptor,
    policy: &ConnectorPolicySnapshot,
) -> Result<(), ConnectorConfigurationError> {
    if policy.revision == 0 || !policy.limits.is_valid() {
        return Err(ConnectorConfigurationError::InvalidPolicySnapshot(
            descriptor.id,
        ));
    }
    if policy.consent != ConsentState::ExplicitlyGranted {
        return Err(ConnectorConfigurationError::ConsentNotGranted(
            descriptor.id,
        ));
    }
    if policy.agent_authority != AgentAuthority::Denied {
        return Err(ConnectorConfigurationError::AgentAuthorityNotImplemented(
            descriptor.id,
        ));
    }
    if policy.side_effects != SideEffectPolicy::Forbidden {
        return Err(ConnectorConfigurationError::SideEffectsNotImplemented(
            descriptor.id,
        ));
    }
    let egress_allowed = match descriptor.capabilities.egress {
        EgressClass::None => policy.egress == PolicyEgress::DenyAll,
        EgressClass::LocalOnly => policy.egress == PolicyEgress::LocalOnly,
        EgressClass::PolicyGatedNetwork => policy.egress == PolicyEgress::ApprovedNetwork,
    };
    if !egress_allowed {
        return Err(ConnectorConfigurationError::EgressNotAllowed(descriptor.id));
    }
    Ok(())
}

/// Performs no side effect.  This is an explicit control-plane guard that
/// proves roles cannot silently cross into unrelated effectful routes.
pub fn admit_entry_point(
    configuration: &ConnectorConfiguration,
    entry_point: ConnectorEntryPoint,
) -> Result<(), ConnectorAdmissionError> {
    validate_configurations(std::slice::from_ref(configuration))
        .map_err(ConnectorAdmissionError::Configuration)?;
    let descriptor = descriptor(configuration.connector_id);
    let admitted = match entry_point {
        ConnectorEntryPoint::ContextImport => {
            descriptor.roles.contains(ConnectorRole::ContextSource)
                && descriptor.capabilities.context_access == ContextAccess::ReadOnly
                && descriptor.capabilities.import_class == ImportClass::ExplicitOperatorSelected
        }
        ConnectorEntryPoint::ResearchJob => {
            descriptor.roles.contains(ConnectorRole::ResearchBackend)
        }
        ConnectorEntryPoint::ChannelRouting => {
            descriptor.roles.contains(ConnectorRole::AgentChannel)
        }
        ConnectorEntryPoint::ActionExecution => false,
        ConnectorEntryPoint::McpDispatch => false,
        ConnectorEntryPoint::DirectExecution => false,
    };
    if admitted {
        Ok(())
    } else {
        Err(ConnectorAdmissionError::Forbidden {
            connector: descriptor.id,
            entry_point,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnectorRegistryError {
    #[error("duplicate canonical connector id `{0}`")]
    DuplicateCanonicalId(ConnectorId),
    #[error("closed connector id `{0}` has no descriptor")]
    MissingDescriptor(ConnectorId),
    #[error("connector `{0}` declares no role")]
    MissingRole(ConnectorId),
    #[error("context source `{0}` must not also be an agent channel")]
    ContextSourceCannotBeAgentChannel(ConnectorId),
    #[error(
        "research backend `{0}` crosses an account, source, action, direct-execution, or MCP boundary"
    )]
    UnsafeResearchBackend(ConnectorId),
    #[error("context source `{0}` is not strictly read-only")]
    ContextSourceNotReadOnly(ConnectorId),
    #[error("context source `{0}` must require explicit operator-selected import")]
    ContextSourceMissingExplicitImport(ConnectorId),
    #[error("connector `{0}` advertises actions without the ActionSink role")]
    ActionCapabilityWithoutSink(ConnectorId),
    #[error("disabled experimental connector `{0}` is not a research reference")]
    FeatureDisabledDescriptorNotResearch(ConnectorId),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnectorConfigurationError {
    #[error("connector registry is invalid: {0}")]
    Registry(ConnectorRegistryError),
    #[error("connector `{0}` appears more than once with the same account identity")]
    DuplicateOrAmbiguousInstance(ConnectorId),
    #[error("connector `{0}` is disabled or experimental and cannot be configured")]
    FeatureDisabled(ConnectorId),
    #[error("connector `{0}` does not support a connector account")]
    AccountNotSupported(ConnectorId),
    #[error("connector `{0}` requires a connector account")]
    AccountRequired(ConnectorId),
    #[error("connector `{0}` must not receive a credential reference")]
    CredentialNotSupported(ConnectorId),
    #[error("connector `{0}` requires an opaque SecretStore credential reference")]
    CredentialRequired(ConnectorId),
    #[error("connector `{0}` policy snapshot is absent, stale, or has invalid resource limits")]
    InvalidPolicySnapshot(ConnectorId),
    #[error("connector `{0}` has no explicit consent")]
    ConsentNotGranted(ConnectorId),
    #[error("connector `{0}` agent authority is not implemented in CC-01")]
    AgentAuthorityNotImplemented(ConnectorId),
    #[error("connector `{0}` side effects are not implemented in CC-01")]
    SideEffectsNotImplemented(ConnectorId),
    #[error("connector `{0}` policy egress does not match its descriptor boundary")]
    EgressNotAllowed(ConnectorId),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnectorAdmissionError {
    #[error("connector configuration is not admissible: {0}")]
    Configuration(ConnectorConfigurationError),
    #[error("connector `{connector}` is forbidden from {entry_point:?}")]
    Forbidden {
        connector: ConnectorId,
        entry_point: ConnectorEntryPoint,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_import_config() -> ConnectorConfiguration {
        ConnectorConfiguration {
            connector_id: ConnectorId::LocalImport,
            account_id: None,
            subject_id: SubjectId::new("operator").unwrap(),
            credential_ref: None,
            policy: ConnectorPolicySnapshot::local_read_only(1),
        }
    }

    #[test]
    fn registry_is_closed_complete_and_has_only_safe_reference_descriptors() {
        validate_registry().unwrap();
        assert_eq!(connector_descriptors().len(), ConnectorId::ALL.len());
        assert_eq!(
            descriptor(ConnectorId::LocalImport).capabilities.egress,
            EgressClass::LocalOnly
        );
        let research = descriptor(ConnectorId::AgentReachResearch);
        assert_eq!(
            research.availability,
            ConnectorAvailability::DisabledExperimental
        );
        assert_eq!(research.roles, ConnectorRoles::RESEARCH_BACKEND);
        assert!(!research.capabilities.direct_execution);
        assert!(!research.capabilities.mcp_dispatch);
    }

    #[test]
    fn strict_ids_and_connector_names_never_normalize_ambiguous_input() {
        for valid in ["operator", "local_2", "project-7"] {
            assert_eq!(SubjectId::new(valid).unwrap().as_str(), valid);
        }
        for invalid in [
            "", "Local", " local", "local ", "_local", "local_", "../local", "ümlaut",
        ] {
            assert!(
                SubjectId::new(invalid).is_err(),
                "{invalid} must be rejected"
            );
        }
        assert!(ConnectorAccountId::new("a".repeat(MAX_ID_LEN + 1)).is_err());
        assert!(" Local_Import".parse::<ConnectorId>().is_err());
        assert!("LOCAL_IMPORT".parse::<ConnectorId>().is_err());
    }

    #[test]
    fn credential_ref_is_opaque_and_never_accepts_credential_material() {
        let reference = CredentialRef::new("secret/connectors/gmail-work").unwrap();
        assert_eq!(format!("{reference:?}"), "CredentialRef(<redacted>)");
        assert_eq!(reference.to_string(), "<credential-ref>");
        assert!(CredentialRef::new("ya29.real-token-value").is_err());
        assert!(CredentialRef::new("secret/sk-proj-abcdefghijklmnopqrstuvwxyz").is_err());
        assert!(
            CredentialRef::new("secret/connectors/sk-proj-abcdefghijklmnopqrstuvwxyz").is_err()
        );
        assert!(CredentialRef::new("secret//ambiguous").is_err());
        assert!(CredentialRef::new("secret/connectors/nested/key").is_err());
        let encoded = serde_json::to_string(&reference).unwrap();
        assert_eq!(encoded, "\"secret/connectors/gmail-work\"");
        assert!(
            serde_json::from_str::<CredentialRef>("\"secret/sk-proj-abcdefghijklmnopqrstuvwxyz\"")
                .is_err()
        );
        assert!(
            serde_json::from_str::<CredentialRef>(
                "\"secret/connectors/sk-proj-abcdefghijklmnopqrstuvwxyz\""
            )
            .is_err()
        );
    }

    #[test]
    fn research_backend_cannot_cross_source_action_process_mcp_egress_or_credential_boundaries() {
        let base = *descriptor(ConnectorId::AgentReachResearch);
        let forbidden = ConnectorDescriptor {
            account_binding: AccountBinding::AccountRequired,
            ..base
        };
        assert!(matches!(
            validate_descriptor(&forbidden),
            Err(ConnectorRegistryError::UnsafeResearchBackend(_))
        ));
        let forbidden = ConnectorDescriptor {
            capabilities: ConnectorCapabilities {
                mcp_dispatch: true,
                ..base.capabilities
            },
            ..base
        };
        assert!(matches!(
            validate_descriptor(&forbidden),
            Err(ConnectorRegistryError::UnsafeResearchBackend(_))
        ));
        let forbidden = ConnectorDescriptor {
            capabilities: ConnectorCapabilities {
                egress: EgressClass::PolicyGatedNetwork,
                ..base.capabilities
            },
            ..base
        };
        assert!(matches!(
            validate_descriptor(&forbidden),
            Err(ConnectorRegistryError::UnsafeResearchBackend(_))
        ));
        let forbidden = ConnectorDescriptor {
            capabilities: ConnectorCapabilities {
                credential_class: CredentialClass::SecretStoreReference,
                ..base.capabilities
            },
            ..base
        };
        assert!(matches!(
            validate_descriptor(&forbidden),
            Err(ConnectorRegistryError::UnsafeResearchBackend(_))
        ));
        let forbidden = ConnectorDescriptor {
            capabilities: ConnectorCapabilities {
                side_effects: SideEffectClass::PermitBound,
                ..base.capabilities
            },
            ..base
        };
        assert!(matches!(
            validate_descriptor(&forbidden),
            Err(ConnectorRegistryError::UnsafeResearchBackend(_))
        ));
    }

    #[test]
    fn context_source_cannot_be_channel_writable_or_implicit_import() {
        let base = *descriptor(ConnectorId::LocalImport);
        let unsafe_source = ConnectorDescriptor {
            roles: ConnectorRoles::CONTEXT_SOURCE.union(ConnectorRoles::CHANNEL),
            ..base
        };
        assert!(matches!(
            validate_descriptor(&unsafe_source),
            Err(ConnectorRegistryError::ContextSourceCannotBeAgentChannel(_))
        ));
        let unsafe_source = ConnectorDescriptor {
            capabilities: ConnectorCapabilities {
                actions: ActionCapabilities {
                    draft_creation: true,
                    ..ActionCapabilities::NONE
                },
                ..base.capabilities
            },
            ..base
        };
        assert!(matches!(
            validate_descriptor(&unsafe_source),
            Err(ConnectorRegistryError::ContextSourceNotReadOnly(_))
        ));
        let unsafe_source = ConnectorDescriptor {
            capabilities: ConnectorCapabilities {
                import_class: ImportClass::None,
                ..base.capabilities
            },
            ..base
        };
        assert!(matches!(
            validate_descriptor(&unsafe_source),
            Err(ConnectorRegistryError::ContextSourceMissingExplicitImport(
                _
            ))
        ));
        let unsafe_source = ConnectorDescriptor {
            capabilities: ConnectorCapabilities {
                mcp_dispatch: true,
                ..base.capabilities
            },
            ..base
        };
        assert!(matches!(
            validate_descriptor(&unsafe_source),
            Err(ConnectorRegistryError::ContextSourceNotReadOnly(_))
        ));
    }

    #[test]
    fn config_validation_is_fail_closed_for_policy_identity_feature_and_credentials() {
        let valid = local_import_config();
        validate_configurations(std::slice::from_ref(&valid)).unwrap();

        let denied = ConnectorConfiguration {
            policy: ConnectorPolicySnapshot::deny_all(),
            ..valid.clone()
        };
        assert!(matches!(
            validate_configurations(&[denied]),
            Err(ConnectorConfigurationError::InvalidPolicySnapshot(_))
        ));

        let duplicate = [valid.clone(), valid.clone()];
        assert!(matches!(
            validate_configurations(&duplicate),
            Err(ConnectorConfigurationError::DuplicateOrAmbiguousInstance(_))
        ));

        let with_credential = ConnectorConfiguration {
            credential_ref: Some(CredentialRef::new("secret/connectors/test-credential").unwrap()),
            ..valid.clone()
        };
        assert!(matches!(
            validate_configurations(&[with_credential]),
            Err(ConnectorConfigurationError::CredentialNotSupported(_))
        ));

        let experimental = ConnectorConfiguration {
            connector_id: ConnectorId::AgentReachResearch,
            ..valid
        };
        assert!(matches!(
            validate_configurations(&[experimental]),
            Err(ConnectorConfigurationError::FeatureDisabled(_))
        ));
    }

    #[test]
    fn context_accounts_cannot_enter_channel_mcp_or_action_routes() {
        let config = local_import_config();
        assert!(admit_entry_point(&config, ConnectorEntryPoint::ContextImport).is_ok());
        for entry_point in [
            ConnectorEntryPoint::ChannelRouting,
            ConnectorEntryPoint::McpDispatch,
            ConnectorEntryPoint::ActionExecution,
            ConnectorEntryPoint::DirectExecution,
        ] {
            assert!(matches!(
                admit_entry_point(&config, entry_point),
                Err(ConnectorAdmissionError::Forbidden { .. })
            ));
        }
    }

    #[test]
    fn action_capabilities_are_not_agent_authority() {
        let base = *descriptor(ConnectorId::LocalImport);
        let action_sink = ConnectorDescriptor {
            roles: ConnectorRoles::ACTION_SINK,
            capabilities: ConnectorCapabilities {
                context_access: ContextAccess::None,
                import_class: ImportClass::None,
                egress: EgressClass::None,
                credential_class: CredentialClass::None,
                side_effects: SideEffectClass::PermitBound,
                actions: ActionCapabilities {
                    draft_creation: true,
                    mutation: false,
                    communication: false,
                },
                direct_execution: false,
                mcp_dispatch: false,
            },
            ..base
        };
        validate_descriptor(&action_sink).unwrap();
        assert!(!action_sink.roles.contains(ConnectorRole::ContextSource));
        // CC-01 has no permit/execution seam: advertised capability remains
        // technical metadata, and all action admission stays denied.
        assert!(matches!(
            admit_entry_point(&local_import_config(), ConnectorEntryPoint::ActionExecution),
            Err(ConnectorAdmissionError::Forbidden { .. })
        ));
    }

    #[test]
    fn health_observation_has_no_authority_bearing_fields() {
        let health = HealthObservation {
            observed_at_unix_ms: 1,
            reachable: true,
            error_code: None,
        };
        let json = serde_json::to_string(&health).unwrap();
        assert!(json.contains("reachable"));
        assert!(!json.contains("ready"));
        assert!(!json.contains("credential"));
    }
}
