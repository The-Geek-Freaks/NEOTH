//! Canonical messaging-channel registry and account identity primitives.
//!
//! This module is the single source of truth for stable channel identifiers,
//! accepted operator aliases, migration aliases, setup metadata, and the
//! capabilities currently exposed by each production adapter.  Runtime state
//! remains on the legacy single-account layout for now; [`ChannelAccountId`]
//! and [`ChannelRef`] make the account dimension representable without a risky
//! persistence migration in the same change.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize};

use super::ChannelKind;

/// Stable typed channel identifier. `ChannelKind` remains the compatibility
/// name used by existing adapters; both names refer to the same closed enum.
pub type ChannelId = ChannelKind;

pub const CHANNEL_REGISTRY_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_CHANNEL_ACCOUNT_ID: &str = "default";
const MAX_CHANNEL_ACCOUNT_ID_LEN: usize = 64;

/// How NEOTH reaches the vendor transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelTransport {
    BotApi,
    SocketMode,
    WebhookApi,
    Gateway,
    LocalCompanion,
    LocalService,
    ClientApi,
    NativeSocket,
    Relay,
    PubSub,
}

/// Account support exposed by the current runtime. This is deliberately
/// honest: the new identity types exist, but the legacy credential store is
/// not relabelled multi-account until its transactional migration lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelAccountMode {
    LegacyDefaultOnly,
    MultiAccount,
}

/// Where the adapter implementation came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelProvenance {
    NeothNative,
    OpenClawOverlap,
    NeothDifferentiator,
}

/// Runtime prerequisite for an adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChannelRuntimeDependency {
    Embedded,
    FeatureGated { feature: &'static str },
    ManagedSidecar { binary: &'static str },
    OperatorService { service: &'static str },
}

/// Whether `channel test` can perform a side-effect-free live check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelLiveTest {
    ReadOnly,
    RuntimeGated,
    Unavailable,
}

/// Typed capabilities already exposed by the current adapter boundary.
///
/// False values are intentional. They keep unsupported rich-message controls
/// disabled before dispatch instead of advertising vendor features that the
/// NEOTH adapter has not wired yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ChannelCapabilities {
    pub direct_messages: bool,
    pub groups_or_rooms: bool,
    pub threads_or_topics: bool,
    pub text: bool,
    pub media: bool,
    pub replies: bool,
    pub reactions: bool,
    pub message_edits: bool,
    pub polls: bool,
    pub proactive: bool,
    pub static_probe: bool,
    pub live_test: ChannelLiveTest,
}

impl ChannelCapabilities {
    const fn current(
        direct_messages: bool,
        groups_or_rooms: bool,
        threads_or_topics: bool,
        media: bool,
        message_edits: bool,
        live_test: ChannelLiveTest,
    ) -> Self {
        Self {
            direct_messages,
            groups_or_rooms,
            threads_or_topics,
            text: true,
            media,
            // The current Channel trait has no typed reply/reaction/poll
            // dispatch seam. Keep these false even where the vendor API could
            // support them; later adapter slices must wire the seam first.
            replies: false,
            reactions: false,
            message_edits,
            polls: false,
            proactive: true,
            static_probe: true,
            live_test,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelSetupRequirement {
    Required,
    Optional,
    OneOf,
}

/// One public setup-schema field. `key` is the canonical NEOTH
/// config/credential key, never a display label or an OpenClaw source path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ChannelSetupField {
    pub key: &'static str,
    pub secret: bool,
    pub requirement: ChannelSetupRequirement,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub one_of_group: Option<&'static str>,
}

const fn required(key: &'static str, secret: bool) -> ChannelSetupField {
    ChannelSetupField {
        key,
        secret,
        requirement: ChannelSetupRequirement::Required,
        one_of_group: None,
    }
}

const fn optional(key: &'static str, secret: bool) -> ChannelSetupField {
    ChannelSetupField {
        key,
        secret,
        requirement: ChannelSetupRequirement::Optional,
        one_of_group: None,
    }
}

const fn one_of(key: &'static str, secret: bool, one_of_group: &'static str) -> ChannelSetupField {
    ChannelSetupField {
        key,
        secret,
        requirement: ChannelSetupRequirement::OneOf,
        one_of_group: Some(one_of_group),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ChannelLifecycleActions {
    pub add: bool,
    pub edit: bool,
    pub probe: bool,
    pub test: bool,
    pub remove: bool,
    pub repair: bool,
}

const CURRENT_LIFECYCLE: ChannelLifecycleActions = ChannelLifecycleActions {
    add: true,
    // Re-running add updates fields, but there is no typed edit action yet.
    edit: false,
    probe: true,
    test: true,
    remove: true,
    repair: false,
};

/// One canonical registry row. Every consumer projects from this slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ChannelDescriptor {
    pub id: ChannelId,
    pub display_name: &'static str,
    /// Accepted operator-facing aliases (`neoth channel ...`). Canonical IDs
    /// are never repeated here.
    pub aliases: &'static [&'static str],
    /// Source/import aliases. This namespace is separate because OpenClaw's
    /// `whatsapp` means Baileys while NEOTH's historical CLI alias means the
    /// Meta Business adapter.
    pub migration_aliases: &'static [&'static str],
    pub transport: ChannelTransport,
    pub account_mode: ChannelAccountMode,
    pub setup_fields: &'static [ChannelSetupField],
    pub capabilities: ChannelCapabilities,
    pub lifecycle: ChannelLifecycleActions,
    pub runtime: ChannelRuntimeDependency,
    pub provenance: ChannelProvenance,
}

const TELEGRAM_SETUP: &[ChannelSetupField] = &[
    required("telegram_token", true),
    required("telegram_user_id", false),
];
const SLACK_SETUP: &[ChannelSetupField] = &[
    required("slack_bot_token", true),
    required("slack_app_token", true),
];
const WHATSAPP_BUSINESS_SETUP: &[ChannelSetupField] = &[
    required("whatsapp_token", true),
    required("whatsapp_phone_id", false),
    required("whatsapp_verify_token", true),
    required("whatsapp_app_secret", true),
];
const WHATSAPP_BAILEYS_SETUP: &[ChannelSetupField] = &[
    required("whatsapp_baileys_url", false),
    required("whatsapp_baileys_token", true),
    required("whatsapp_baileys_allowed_senders", false),
    optional("whatsapp_baileys_allowed_groups", false),
];
const KEET_SETUP: &[ChannelSetupField] = &[
    required("keet_bridge_url", false),
    required("keet_bridge_bearer_token", true),
    required("keet_topic", true),
    required("keet_allowed_senders", false),
];
const DISCORD_SETUP: &[ChannelSetupField] = &[required("discord_bot_token", true)];
const SIGNAL_SETUP: &[ChannelSetupField] = &[
    required("signal_cli_url", false),
    required("signal_phone_number", false),
];
const BLUEBUBBLES_SETUP: &[ChannelSetupField] = &[
    required("bluebubbles_url", false),
    required("bluebubbles_password", true),
    required("imessage_allowed_sender", false),
    optional("bluebubbles_chat_guid", false),
];
const MATRIX_SETUP: &[ChannelSetupField] = &[
    required("matrix_homeserver", false),
    required("matrix_user_id", false),
    one_of("matrix_access_token", true, "matrix_auth"),
    one_of("matrix_password", true, "matrix_auth"),
    one_of("matrix_allowed_user_id", false, "matrix_inbound_policy"),
    one_of("matrix_allowed_room_ids", false, "matrix_inbound_policy"),
    optional("matrix_require_encryption", false),
];
const LINE_SETUP: &[ChannelSetupField] = &[
    required("line_channel_access_token", true),
    optional("line_channel_secret", true),
];
const IRC_SETUP: &[ChannelSetupField] = &[
    required("irc_server", false),
    required("irc_nick", false),
    optional("irc_password", true),
    optional("irc_channels", false),
    required("irc_allowed_account", false),
];
const MATTERMOST_SETUP: &[ChannelSetupField] = &[
    required("mattermost_url", false),
    required("mattermost_token", true),
    required("mattermost_allowed_user_id", false),
];
const TWITCH_SETUP: &[ChannelSetupField] = &[
    required("twitch_username", false),
    required("twitch_oauth_token", true),
    required("twitch_channels", false),
];
const NOSTR_SETUP: &[ChannelSetupField] = &[
    required("nostr_secret_key", true),
    required("nostr_relays", false),
    required("nostr_allowed_pubkey", false),
];
const GCHAT_SETUP: &[ChannelSetupField] = &[
    required("gchat_service_account_json", false),
    required("gchat_subscription", false),
    required("gchat_allowed_sender", false),
];

/// The only ordered inventory of production channel identifiers.
pub static CHANNEL_REGISTRY: &[ChannelDescriptor] = &[
    ChannelDescriptor {
        id: ChannelId::Telegram,
        display_name: "Telegram",
        aliases: &[],
        migration_aliases: &[],
        transport: ChannelTransport::BotApi,
        account_mode: ChannelAccountMode::LegacyDefaultOnly,
        setup_fields: TELEGRAM_SETUP,
        capabilities: ChannelCapabilities::current(
            true,
            true,
            true,
            true,
            true,
            ChannelLiveTest::ReadOnly,
        ),
        lifecycle: CURRENT_LIFECYCLE,
        runtime: ChannelRuntimeDependency::Embedded,
        provenance: ChannelProvenance::OpenClawOverlap,
    },
    ChannelDescriptor {
        id: ChannelId::Slack,
        display_name: "Slack",
        aliases: &[],
        migration_aliases: &[],
        transport: ChannelTransport::SocketMode,
        account_mode: ChannelAccountMode::LegacyDefaultOnly,
        setup_fields: SLACK_SETUP,
        capabilities: ChannelCapabilities::current(
            true,
            true,
            true,
            false,
            true,
            ChannelLiveTest::ReadOnly,
        ),
        lifecycle: CURRENT_LIFECYCLE,
        runtime: ChannelRuntimeDependency::Embedded,
        provenance: ChannelProvenance::OpenClawOverlap,
    },
    ChannelDescriptor {
        id: ChannelId::WhatsAppBusiness,
        display_name: "WhatsApp Business",
        aliases: &["whatsapp"],
        migration_aliases: &[],
        transport: ChannelTransport::WebhookApi,
        account_mode: ChannelAccountMode::LegacyDefaultOnly,
        setup_fields: WHATSAPP_BUSINESS_SETUP,
        capabilities: ChannelCapabilities::current(
            true,
            false,
            false,
            false,
            false,
            ChannelLiveTest::ReadOnly,
        ),
        lifecycle: CURRENT_LIFECYCLE,
        runtime: ChannelRuntimeDependency::Embedded,
        provenance: ChannelProvenance::NeothNative,
    },
    ChannelDescriptor {
        id: ChannelId::WhatsAppBaileys,
        display_name: "WhatsApp (Baileys)",
        aliases: &["baileys"],
        migration_aliases: &["whatsapp"],
        transport: ChannelTransport::LocalCompanion,
        account_mode: ChannelAccountMode::LegacyDefaultOnly,
        setup_fields: WHATSAPP_BAILEYS_SETUP,
        capabilities: ChannelCapabilities::current(
            true,
            true,
            false,
            true,
            false,
            ChannelLiveTest::RuntimeGated,
        ),
        lifecycle: CURRENT_LIFECYCLE,
        runtime: ChannelRuntimeDependency::ManagedSidecar {
            binary: "neoth-whatsapp-bridge",
        },
        provenance: ChannelProvenance::OpenClawOverlap,
    },
    ChannelDescriptor {
        id: ChannelId::Keet,
        display_name: "Keet",
        aliases: &[],
        migration_aliases: &[],
        transport: ChannelTransport::LocalCompanion,
        account_mode: ChannelAccountMode::LegacyDefaultOnly,
        setup_fields: KEET_SETUP,
        capabilities: ChannelCapabilities::current(
            true,
            true,
            true,
            false,
            false,
            ChannelLiveTest::RuntimeGated,
        ),
        lifecycle: CURRENT_LIFECYCLE,
        runtime: ChannelRuntimeDependency::ManagedSidecar {
            binary: "neoth-keet-bridge",
        },
        provenance: ChannelProvenance::NeothDifferentiator,
    },
    ChannelDescriptor {
        id: ChannelId::Discord,
        display_name: "Discord",
        aliases: &[],
        migration_aliases: &[],
        transport: ChannelTransport::Gateway,
        account_mode: ChannelAccountMode::LegacyDefaultOnly,
        setup_fields: DISCORD_SETUP,
        capabilities: ChannelCapabilities::current(
            true,
            true,
            true,
            false,
            false,
            ChannelLiveTest::ReadOnly,
        ),
        lifecycle: CURRENT_LIFECYCLE,
        runtime: ChannelRuntimeDependency::Embedded,
        provenance: ChannelProvenance::OpenClawOverlap,
    },
    ChannelDescriptor {
        id: ChannelId::Signal,
        display_name: "Signal",
        aliases: &[],
        migration_aliases: &[],
        transport: ChannelTransport::LocalService,
        account_mode: ChannelAccountMode::LegacyDefaultOnly,
        setup_fields: SIGNAL_SETUP,
        capabilities: ChannelCapabilities::current(
            true,
            true,
            false,
            false,
            false,
            ChannelLiveTest::RuntimeGated,
        ),
        lifecycle: CURRENT_LIFECYCLE,
        runtime: ChannelRuntimeDependency::OperatorService {
            service: "signal-cli-rest-api",
        },
        provenance: ChannelProvenance::OpenClawOverlap,
    },
    ChannelDescriptor {
        id: ChannelId::IMessageBlueBubbles,
        display_name: "iMessage (BlueBubbles)",
        aliases: &["imessage", "bluebubbles"],
        migration_aliases: &["imessage"],
        transport: ChannelTransport::LocalService,
        account_mode: ChannelAccountMode::LegacyDefaultOnly,
        setup_fields: BLUEBUBBLES_SETUP,
        capabilities: ChannelCapabilities::current(
            true,
            true,
            false,
            true,
            false,
            ChannelLiveTest::RuntimeGated,
        ),
        lifecycle: CURRENT_LIFECYCLE,
        runtime: ChannelRuntimeDependency::OperatorService {
            service: "BlueBubbles Server",
        },
        provenance: ChannelProvenance::OpenClawOverlap,
    },
    ChannelDescriptor {
        id: ChannelId::Matrix,
        display_name: "Matrix",
        aliases: &[],
        migration_aliases: &[],
        transport: ChannelTransport::ClientApi,
        account_mode: ChannelAccountMode::LegacyDefaultOnly,
        setup_fields: MATRIX_SETUP,
        capabilities: ChannelCapabilities::current(
            true,
            true,
            true,
            false,
            false,
            ChannelLiveTest::RuntimeGated,
        ),
        lifecycle: CURRENT_LIFECYCLE,
        runtime: ChannelRuntimeDependency::FeatureGated {
            feature: "matrix-channel",
        },
        provenance: ChannelProvenance::OpenClawOverlap,
    },
    ChannelDescriptor {
        id: ChannelId::Line,
        display_name: "LINE",
        aliases: &[],
        migration_aliases: &[],
        transport: ChannelTransport::WebhookApi,
        account_mode: ChannelAccountMode::LegacyDefaultOnly,
        setup_fields: LINE_SETUP,
        capabilities: ChannelCapabilities::current(
            true,
            true,
            false,
            false,
            false,
            ChannelLiveTest::ReadOnly,
        ),
        lifecycle: CURRENT_LIFECYCLE,
        runtime: ChannelRuntimeDependency::Embedded,
        provenance: ChannelProvenance::OpenClawOverlap,
    },
    ChannelDescriptor {
        id: ChannelId::Irc,
        display_name: "IRC",
        aliases: &[],
        migration_aliases: &[],
        transport: ChannelTransport::NativeSocket,
        account_mode: ChannelAccountMode::LegacyDefaultOnly,
        setup_fields: IRC_SETUP,
        capabilities: ChannelCapabilities::current(
            false,
            true,
            false,
            false,
            false,
            ChannelLiveTest::Unavailable,
        ),
        lifecycle: CURRENT_LIFECYCLE,
        runtime: ChannelRuntimeDependency::FeatureGated {
            feature: "irc-channel",
        },
        provenance: ChannelProvenance::OpenClawOverlap,
    },
    ChannelDescriptor {
        id: ChannelId::Mattermost,
        display_name: "Mattermost",
        aliases: &[],
        migration_aliases: &[],
        transport: ChannelTransport::SocketMode,
        account_mode: ChannelAccountMode::LegacyDefaultOnly,
        setup_fields: MATTERMOST_SETUP,
        capabilities: ChannelCapabilities::current(
            true,
            true,
            true,
            false,
            false,
            ChannelLiveTest::ReadOnly,
        ),
        lifecycle: CURRENT_LIFECYCLE,
        runtime: ChannelRuntimeDependency::Embedded,
        provenance: ChannelProvenance::OpenClawOverlap,
    },
    ChannelDescriptor {
        id: ChannelId::Twitch,
        display_name: "Twitch",
        aliases: &[],
        migration_aliases: &[],
        transport: ChannelTransport::NativeSocket,
        account_mode: ChannelAccountMode::LegacyDefaultOnly,
        setup_fields: TWITCH_SETUP,
        capabilities: ChannelCapabilities::current(
            false,
            true,
            false,
            false,
            false,
            ChannelLiveTest::ReadOnly,
        ),
        lifecycle: CURRENT_LIFECYCLE,
        runtime: ChannelRuntimeDependency::FeatureGated {
            feature: "irc-channel",
        },
        provenance: ChannelProvenance::OpenClawOverlap,
    },
    ChannelDescriptor {
        id: ChannelId::Nostr,
        display_name: "Nostr",
        aliases: &[],
        migration_aliases: &[],
        transport: ChannelTransport::Relay,
        account_mode: ChannelAccountMode::LegacyDefaultOnly,
        setup_fields: NOSTR_SETUP,
        capabilities: ChannelCapabilities::current(
            true,
            false,
            false,
            false,
            false,
            ChannelLiveTest::RuntimeGated,
        ),
        lifecycle: CURRENT_LIFECYCLE,
        runtime: ChannelRuntimeDependency::FeatureGated {
            feature: "nostr-channel",
        },
        provenance: ChannelProvenance::OpenClawOverlap,
    },
    ChannelDescriptor {
        id: ChannelId::GoogleChat,
        display_name: "Google Chat",
        aliases: &["google_chat"],
        migration_aliases: &["googlechat"],
        transport: ChannelTransport::PubSub,
        account_mode: ChannelAccountMode::LegacyDefaultOnly,
        setup_fields: GCHAT_SETUP,
        capabilities: ChannelCapabilities::current(
            true,
            true,
            true,
            false,
            false,
            ChannelLiveTest::RuntimeGated,
        ),
        lifecycle: CURRENT_LIFECYCLE,
        runtime: ChannelRuntimeDependency::FeatureGated {
            feature: "gchat-channel",
        },
        provenance: ChannelProvenance::OpenClawOverlap,
    },
];

pub fn channel_descriptors() -> &'static [ChannelDescriptor] {
    CHANNEL_REGISTRY
}

pub fn channel_ids() -> impl ExactSizeIterator<Item = ChannelId> + Clone {
    CHANNEL_REGISTRY.iter().map(|descriptor| descriptor.id)
}

pub fn descriptor(id: ChannelId) -> &'static ChannelDescriptor {
    CHANNEL_REGISTRY
        .iter()
        .find(|descriptor| descriptor.id == id)
        .expect("every closed ChannelId variant must have a registry descriptor")
}

fn canonical_token(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

pub fn resolve_channel_id(raw: &str) -> Option<ChannelId> {
    let token = canonical_token(raw);
    CHANNEL_REGISTRY
        .iter()
        .find(|descriptor| {
            descriptor.id.as_str() == token
                || descriptor.aliases.iter().any(|alias| *alias == token)
        })
        .map(|descriptor| descriptor.id)
}

pub fn resolve_migration_channel_id(raw: &str) -> Option<ChannelId> {
    let token = canonical_token(raw);
    CHANNEL_REGISTRY
        .iter()
        .find(|descriptor| {
            descriptor.id.as_str() == token
                || descriptor
                    .migration_aliases
                    .iter()
                    .any(|alias| *alias == token)
        })
        .map(|descriptor| descriptor.id)
}

impl FromStr for ChannelKind {
    type Err = UnknownChannelId;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        resolve_channel_id(value).ok_or_else(|| UnknownChannelId(value.trim().to_string()))
    }
}

impl<'de> Deserialize<'de> for ChannelKind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("unknown channel id or alias `{0}`")]
pub struct UnknownChannelId(String);

/// Validate the static registry. Startup consumers can call this before
/// projecting descriptors; tests call it directly so alias drift fails CI.
pub fn validate_registry() -> Result<(), ChannelRegistryError> {
    let mut canonical = BTreeSet::new();
    let mut descriptor_ids = BTreeSet::new();
    for descriptor in CHANNEL_REGISTRY {
        if !canonical.insert(descriptor.id.as_str()) || !descriptor_ids.insert(descriptor.id) {
            return Err(ChannelRegistryError::DuplicateCanonicalId(
                descriptor.id.as_str(),
            ));
        }
        if descriptor.setup_fields.is_empty() {
            return Err(ChannelRegistryError::MissingSetupSchema(
                descriptor.id.as_str(),
            ));
        }
        validate_setup_schema(descriptor)?;
    }

    for channel_id in ChannelKind::ALL {
        if !descriptor_ids.contains(channel_id) {
            return Err(ChannelRegistryError::MissingChannelDescriptor(
                channel_id.as_str(),
            ));
        }
    }

    let mut operator_names: BTreeMap<&str, ChannelId> = CHANNEL_REGISTRY
        .iter()
        .map(|descriptor| (descriptor.id.as_str(), descriptor.id))
        .collect();
    let mut migration_names = operator_names.clone();

    for descriptor in CHANNEL_REGISTRY {
        validate_aliases(
            descriptor,
            descriptor.aliases,
            &mut operator_names,
            "operator",
        )?;
        validate_aliases(
            descriptor,
            descriptor.migration_aliases,
            &mut migration_names,
            "migration",
        )?;
    }
    Ok(())
}

fn validate_setup_schema(descriptor: &ChannelDescriptor) -> Result<(), ChannelRegistryError> {
    let mut keys = BTreeSet::new();
    let mut one_of_groups = BTreeMap::new();

    for field in descriptor.setup_fields {
        if !valid_schema_key(field.key) {
            return Err(ChannelRegistryError::InvalidSetupFieldKey {
                channel: descriptor.id.as_str(),
                key: field.key,
            });
        }
        if !keys.insert(field.key) {
            return Err(ChannelRegistryError::DuplicateSetupFieldKey {
                channel: descriptor.id.as_str(),
                key: field.key,
            });
        }

        match (field.requirement, field.one_of_group) {
            (ChannelSetupRequirement::OneOf, Some(group)) => {
                if !valid_schema_key(group) {
                    return Err(ChannelRegistryError::InvalidOneOfGroup {
                        channel: descriptor.id.as_str(),
                        group,
                    });
                }
                *one_of_groups.entry(group).or_insert(0_usize) += 1;
            }
            (ChannelSetupRequirement::OneOf, None) => {
                return Err(ChannelRegistryError::MissingOneOfGroup {
                    channel: descriptor.id.as_str(),
                    key: field.key,
                });
            }
            (_, Some(group)) => {
                return Err(ChannelRegistryError::UnexpectedOneOfGroup {
                    channel: descriptor.id.as_str(),
                    key: field.key,
                    group,
                });
            }
            (_, None) => {}
        }
    }

    for (group, members) in one_of_groups {
        if members < 2 {
            return Err(ChannelRegistryError::UndersizedOneOfGroup {
                channel: descriptor.id.as_str(),
                group,
                members,
            });
        }
    }
    Ok(())
}

fn valid_schema_key(value: &str) -> bool {
    let bytes = value.as_bytes();
    let is_alnum = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    !bytes.is_empty()
        && is_alnum(bytes[0])
        && is_alnum(bytes[bytes.len() - 1])
        && bytes
            .iter()
            .copied()
            .all(|byte| is_alnum(byte) || byte == b'_')
}

fn validate_aliases(
    descriptor: &ChannelDescriptor,
    aliases: &'static [&'static str],
    names: &mut BTreeMap<&'static str, ChannelId>,
    namespace: &'static str,
) -> Result<(), ChannelRegistryError> {
    for alias in aliases {
        if alias.is_empty()
            || *alias != canonical_token(alias)
            || !alias
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(ChannelRegistryError::InvalidAlias {
                channel: descriptor.id.as_str(),
                alias,
                namespace,
            });
        }
        if let Some(existing) = names.insert(alias, descriptor.id) {
            return Err(ChannelRegistryError::DuplicateAlias {
                alias,
                namespace,
                first: existing.as_str(),
                second: descriptor.id.as_str(),
            });
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChannelRegistryError {
    #[error("duplicate canonical channel id `{0}`")]
    DuplicateCanonicalId(&'static str),
    #[error("channel enum value `{0}` has no registry descriptor")]
    MissingChannelDescriptor(&'static str),
    #[error("channel `{0}` has no setup schema")]
    MissingSetupSchema(&'static str),
    #[error("channel `{channel}` has invalid setup field key `{key}`")]
    InvalidSetupFieldKey {
        channel: &'static str,
        key: &'static str,
    },
    #[error("channel `{channel}` repeats setup field key `{key}`")]
    DuplicateSetupFieldKey {
        channel: &'static str,
        key: &'static str,
    },
    #[error("channel `{channel}` setup field `{key}` is one-of but has no group")]
    MissingOneOfGroup {
        channel: &'static str,
        key: &'static str,
    },
    #[error("channel `{channel}` setup field `{key}` has unexpected one-of group `{group}`")]
    UnexpectedOneOfGroup {
        channel: &'static str,
        key: &'static str,
        group: &'static str,
    },
    #[error("channel `{channel}` has invalid one-of group `{group}`")]
    InvalidOneOfGroup {
        channel: &'static str,
        group: &'static str,
    },
    #[error(
        "channel `{channel}` one-of group `{group}` has {members} member(s); at least two are required"
    )]
    UndersizedOneOfGroup {
        channel: &'static str,
        group: &'static str,
        members: usize,
    },
    #[error("channel `{channel}` has invalid {namespace} alias `{alias}`")]
    InvalidAlias {
        channel: &'static str,
        alias: &'static str,
        namespace: &'static str,
    },
    #[error("duplicate {namespace} alias `{alias}` maps to both `{first}` and `{second}`")]
    DuplicateAlias {
        alias: &'static str,
        namespace: &'static str,
        first: &'static str,
        second: &'static str,
    },
}

/// Stable, validated account identifier. Values are safe to embed in durable
/// keys and filenames: lowercase ASCII alphanumerics with internal `_`/`-`,
/// bounded to 64 bytes. Aliases are a channel concept and never accepted here.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ChannelAccountId(String);

impl ChannelAccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, ChannelAccountIdError> {
        let value = value.into();
        validate_channel_account_id(&value)?;
        Ok(Self(value))
    }

    pub fn default_account() -> Self {
        Self(DEFAULT_CHANNEL_ACCOUNT_ID.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn is_default(&self) -> bool {
        self.0 == DEFAULT_CHANNEL_ACCOUNT_ID
    }
}

impl Default for ChannelAccountId {
    fn default() -> Self {
        Self::default_account()
    }
}

impl fmt::Display for ChannelAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for ChannelAccountId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for ChannelAccountId {
    type Err = ChannelAccountIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for ChannelAccountId {
    type Error = ChannelAccountIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for ChannelAccountId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

fn validate_channel_account_id(value: &str) -> Result<(), ChannelAccountIdError> {
    if value.is_empty() {
        return Err(ChannelAccountIdError::Empty);
    }
    if value.len() > MAX_CHANNEL_ACCOUNT_ID_LEN {
        return Err(ChannelAccountIdError::TooLong {
            max: MAX_CHANNEL_ACCOUNT_ID_LEN,
        });
    }
    if !value.is_ascii() || value.trim() != value {
        return Err(ChannelAccountIdError::InvalidCharacters);
    }

    let bytes = value.as_bytes();
    let is_alnum = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    if !is_alnum(bytes[0]) || !is_alnum(bytes[bytes.len() - 1]) {
        return Err(ChannelAccountIdError::InvalidBoundary);
    }
    if !bytes
        .iter()
        .copied()
        .all(|byte| is_alnum(byte) || byte == b'_' || byte == b'-')
    {
        return Err(ChannelAccountIdError::InvalidCharacters);
    }
    Ok(())
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChannelAccountIdError {
    #[error("channel account id cannot be empty")]
    Empty,
    #[error("channel account id exceeds {max} bytes")]
    TooLong { max: usize },
    #[error("channel account id must start and end with a lowercase ASCII letter or digit")]
    InvalidBoundary,
    #[error(
        "channel account id accepts only lowercase ASCII letters, digits, `_`, and `-` without surrounding whitespace"
    )]
    InvalidCharacters,
}

/// Fully qualified channel account identity. Serialization always emits the
/// canonical channel ID and a validated account ID.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ChannelRef {
    pub channel_id: ChannelId,
    pub account_id: ChannelAccountId,
}

impl ChannelRef {
    pub fn new(channel_id: ChannelId, account_id: ChannelAccountId) -> Self {
        Self {
            channel_id,
            account_id,
        }
    }

    pub fn default_account(channel_id: ChannelId) -> Self {
        Self::new(channel_id, ChannelAccountId::default_account())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_unique_complete_and_aliases_round_trip_to_canonical_ids() {
        validate_registry().unwrap();

        let enum_ids = ChannelKind::ALL.iter().copied().collect::<BTreeSet<_>>();
        let ids = channel_ids().collect::<BTreeSet<_>>();
        assert_eq!(ChannelKind::ALL.len(), channel_descriptors().len());
        assert_eq!(enum_ids, ids);
        assert_eq!(ids.len(), channel_descriptors().len());
        for channel_descriptor in channel_descriptors() {
            assert_eq!(
                resolve_channel_id(channel_descriptor.id.as_str()),
                Some(channel_descriptor.id)
            );
            assert_eq!(descriptor(channel_descriptor.id).id, channel_descriptor.id);
            for alias in channel_descriptor.aliases {
                assert_eq!(resolve_channel_id(alias), Some(channel_descriptor.id));
                let encoded = serde_json::to_string(&resolve_channel_id(alias).unwrap()).unwrap();
                assert_eq!(encoded, format!("\"{}\"", channel_descriptor.id.as_str()));
            }
        }
    }

    #[test]
    fn setup_schema_validator_rejects_invalid_duplicate_and_undersized_fields() {
        const INVALID_KEY: &[ChannelSetupField] = &[required("Bad-Key", true)];
        const DUPLICATE_KEY: &[ChannelSetupField] = &[
            required("access_token", true),
            optional("access_token", true),
        ];
        const UNDERSIZED_ONE_OF: &[ChannelSetupField] =
            &[one_of("access_token", true, "authentication")];

        let base = CHANNEL_REGISTRY[0];
        assert!(matches!(
            validate_setup_schema(&ChannelDescriptor {
                setup_fields: INVALID_KEY,
                ..base
            }),
            Err(ChannelRegistryError::InvalidSetupFieldKey { .. })
        ));
        assert!(matches!(
            validate_setup_schema(&ChannelDescriptor {
                setup_fields: DUPLICATE_KEY,
                ..base
            }),
            Err(ChannelRegistryError::DuplicateSetupFieldKey { .. })
        ));
        assert!(matches!(
            validate_setup_schema(&ChannelDescriptor {
                setup_fields: UNDERSIZED_ONE_OF,
                ..base
            }),
            Err(ChannelRegistryError::UndersizedOneOfGroup { members: 1, .. })
        ));
    }

    #[test]
    fn operator_and_migration_alias_namespaces_preserve_whatsapp_transport() {
        assert_eq!(
            resolve_channel_id("whatsapp"),
            Some(ChannelId::WhatsAppBusiness)
        );
        assert_eq!(
            resolve_migration_channel_id("whatsapp"),
            Some(ChannelId::WhatsAppBaileys)
        );
        assert_eq!(
            resolve_channel_id(" BLUEBUBBLES "),
            Some(ChannelId::IMessageBlueBubbles)
        );
        assert_eq!(resolve_channel_id("unknown"), None);
    }

    #[test]
    fn account_ids_validate_boundaries_characters_length_and_default() {
        for valid in ["default", "work", "work_2", "family-chat", "a1"] {
            assert_eq!(ChannelAccountId::new(valid).unwrap().as_str(), valid);
        }
        assert!(ChannelAccountId::default_account().is_default());
        for invalid in [
            "",
            " Work",
            "work ",
            "Work",
            "_work",
            "work_",
            "work.chat",
            "ümlaut",
        ] {
            assert!(
                ChannelAccountId::new(invalid).is_err(),
                "`{invalid}` must be rejected"
            );
        }
        assert!(ChannelAccountId::new("a".repeat(65)).is_err());
    }

    #[test]
    fn serde_canonicalizes_channel_alias_and_rejects_invalid_account() {
        let parsed: ChannelRef =
            serde_json::from_str(r#"{"channel_id":"bluebubbles","account_id":"work_2"}"#).unwrap();
        assert_eq!(parsed.channel_id, ChannelId::IMessageBlueBubbles);
        assert_eq!(parsed.account_id.as_str(), "work_2");
        assert_eq!(
            serde_json::to_string(&parsed).unwrap(),
            r#"{"channel_id":"imessage_bluebubbles","account_id":"work_2"}"#
        );
        assert!(
            serde_json::from_str::<ChannelRef>(
                r#"{"channel_id":"telegram","account_id":"../escape"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn descriptor_projection_is_serializable_and_secret_free() {
        let projection = serde_json::to_value(channel_descriptors()).unwrap();
        assert_eq!(projection.as_array().unwrap().len(), ChannelKind::ALL.len());
        let text = projection.to_string();
        assert!(text.contains("telegram_token"));
        assert!(!text.contains("123:abc"));
    }
}
