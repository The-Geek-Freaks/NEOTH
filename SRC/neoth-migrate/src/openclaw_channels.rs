//! Strict, read-only OpenClaw configuration inspection.
//!
//! This module deliberately produces a migration *plan*, not target config.
//! Every effective configuration leaf (after OpenClaw include/merge semantics)
//! is accounted for without serialising its value. Unknown, unsupported,
//! transport-specific and runtime-specific fields remain explicit blockers so
//! a future apply path cannot silently weaken an OpenClaw setup.

use anyhow::{Context as _, Result};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};

const MAX_INCLUDE_DEPTH: usize = 10;
const MAX_INCLUDE_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_FILES: usize = 128;
const INSPECT_CONTRACT_VERSION: &str = "neoth-openclaw-inspect-v1";
const AUDITED_OPENCLAW_SCHEMA_COMMIT: &str = "4c667aac8859114bd8f0a589ac6cd1de8bfe1474";

/// OpenClaw keys backed by channel manifests in the audited source contract.
/// The OpenClaw schema is extension-owned and remains open-ended, so anything
/// outside this list is reported as `unknown` rather than discarded.
pub const KNOWN_CHANNEL_KEYS: &[&str] = &[
    "clickclack",
    "discord",
    "feishu",
    "googlechat",
    "imessage",
    "irc",
    "line",
    "matrix",
    "mattermost",
    "msteams",
    "nextcloud-talk",
    "nostr",
    "qa-channel",
    "qqbot",
    "raft",
    "reef",
    "signal",
    "slack",
    "sms",
    "synology-chat",
    "telegram",
    "tlon",
    "twitch",
    "whatsapp",
    "zalo",
    "zalouser",
];

/// Semantic source-to-target aliases. Most importantly, OpenClaw's
/// `whatsapp` is the Baileys/WhatsApp-Web transport, never Meta Business.
pub const CHANNEL_ALIASES: &[(&str, &str)] = &[
    ("telegram", "telegram"),
    ("slack", "slack"),
    ("whatsapp", "whatsapp_baileys"),
    ("discord", "discord"),
    ("signal", "signal"),
    ("imessage", "imessage_bluebubbles"),
    ("matrix", "matrix"),
    ("line", "line"),
    ("irc", "irc"),
    ("mattermost", "mattermost"),
    ("twitch", "twitch"),
    ("nostr", "nostr"),
    ("googlechat", "gchat"),
];

/// Known OpenClaw root keys. This importer currently maps channel credentials
/// only, but still ledgers every other effective leaf as an explicit blocker.
const KNOWN_ROOT_KEYS: &[&str] = &[
    "$schema",
    "meta",
    "auth",
    "accessGroups",
    "acp",
    "env",
    "wizard",
    "diagnostics",
    "logging",
    "cli",
    "crestodian",
    "update",
    "browser",
    "ui",
    "secrets",
    "skills",
    "plugins",
    "surfaces",
    "models",
    "nodeHost",
    "agents",
    "tools",
    "bindings",
    "broadcast",
    "audio",
    "media",
    "messages",
    "commands",
    "approvals",
    "session",
    "web",
    "channels",
    "cron",
    "commitments",
    "hooks",
    "discovery",
    "talk",
    "gateway",
    "memory",
    "mcp",
    "proxy",
];

const COMMON_CHANNEL_FIELDS: &[&str] = &[
    "name",
    "enabled",
    "accounts",
    "defaultAccount",
    "capabilities",
    "markdown",
    "configWrites",
    "commands",
    "dmPolicy",
    "allowFrom",
    "defaultTo",
    "groupAllowFrom",
    "groupPolicy",
    "contextVisibility",
    "groups",
    "historyLimit",
    "dmHistoryLimit",
    "dms",
    "textChunkLimit",
    "chunkMode",
    "blockStreaming",
    "blockStreamingCoalesce",
    "streaming",
    "mediaMaxMb",
    "replyToMode",
    "actions",
    "heartbeat",
    "healthMonitor",
    "responsePrefix",
    "ackReaction",
    "reactionLevel",
    "reactionNotifications",
    "threadBindings",
    "execApprovals",
    "botLoopProtection",
    "allowBots",
    "dangerouslyAllowNameMatching",
    "requireMention",
];

const TELEGRAM_FIELDS: &[&str] = &[
    "botToken",
    "tokenFile",
    "customCommands",
    "replyToMode",
    "dm",
    "direct",
    "groupAllowFrom",
    "timeoutSeconds",
    "mediaGroupFlushMs",
    "pollingStallThresholdMs",
    "retry",
    "network",
    "proxy",
    "webhookUrl",
    "webhookSecret",
    "webhookPath",
    "webhookHost",
    "webhookPort",
    "webhookCertPath",
    "reactionLevel",
    "linkPreview",
    "silentErrorReplies",
    "errorPolicy",
    "errorCooldownMs",
    "apiRoot",
    "trustedLocalFileRoots",
    "autoTopicLabel",
];

const SLACK_FIELDS: &[&str] = &[
    "mode",
    "socketMode",
    "signingSecret",
    "webhookPath",
    "botToken",
    "appToken",
    "userToken",
    "userTokenReadOnly",
    "unfurlLinks",
    "unfurlMedia",
    "reactionAllowlist",
    "replyToModeByChatType",
    "thread",
    "slashCommand",
    "dm",
    "channels",
    "typingReaction",
];

const WHATSAPP_FIELDS: &[&str] = &[
    "authDir",
    "sendReadReceipts",
    "messagePrefix",
    "selfChatMode",
    "direct",
    "debounceMs",
];

const DISCORD_FIELDS: &[&str] = &[
    "token",
    "applicationId",
    "proxy",
    "gatewayInfoTimeoutMs",
    "gatewayReadyTimeoutMs",
    "gatewayRuntimeReadyTimeoutMs",
    "mentionAliases",
    "maxLinesPerMessage",
    "thread",
    "dm",
    "guilds",
    "agentComponents",
    "ui",
    "slashCommand",
    "intents",
    "voice",
    "pluralkit",
    "ackReactionScope",
    "activity",
    "status",
    "autoPresence",
    "activityType",
    "activityUrl",
    "inboundWorker",
    "eventQueue",
];

const SIGNAL_FIELDS: &[&str] = &[
    "account",
    "accountUuid",
    "httpUrl",
    "httpHost",
    "httpPort",
    "cliPath",
    "autoStart",
    "startupTimeoutMs",
    "receiveMode",
    "ignoreAttachments",
    "ignoreStories",
    "sendReadReceipts",
    "reactionAllowlist",
    "apiMode",
];

const IMESSAGE_FIELDS: &[&str] = &[
    "cliPath",
    "dbPath",
    "remoteHost",
    "service",
    "region",
    "includeAttachments",
    "attachmentRoots",
    "remoteAttachmentRoots",
    "probeTimeoutMs",
    "sendReadReceipts",
    "coalesceSameSenderDms",
    "catchup",
];

const MATRIX_FIELDS: &[&str] = &[
    "homeserver",
    "network",
    "proxy",
    "userId",
    "accessToken",
    "password",
    "deviceId",
    "deviceName",
    "avatarUrl",
    "initialSyncLimit",
    "encryption",
    "allowlistOnly",
    "blockStreaming",
    "threadReplies",
    "ackReactionScope",
    "startupVerification",
    "startupVerificationCooldownHours",
    "autoJoin",
    "autoJoinAllowlist",
    "dm",
    "rooms",
];

const LINE_FIELDS: &[&str] = &[
    "channelAccessToken",
    "channelSecret",
    "tokenFile",
    "secretFile",
    "webhookPath",
];

const IRC_FIELDS: &[&str] = &[
    "host",
    "port",
    "tls",
    "nick",
    "username",
    "realname",
    "password",
    "passwordFile",
    "nickserv",
    "channels",
    "mentionPatterns",
];

const MATTERMOST_FIELDS: &[&str] = &[
    "botToken",
    "baseUrl",
    "chatmode",
    "oncharPrefixes",
    "chunkMode",
    "commands",
    "interactions",
    "network",
    "dmChannelRetry",
];

const TWITCH_FIELDS: &[&str] = &[
    "username",
    "accessToken",
    "clientId",
    "channel",
    "allowedRoles",
    "clientSecret",
    "refreshToken",
    "expiresIn",
    "obtainmentTimestamp",
];

const NOSTR_FIELDS: &[&str] = &["privateKey", "relays", "profile"];

const GOOGLECHAT_FIELDS: &[&str] = &[
    "serviceAccount",
    "serviceAccountRef",
    "serviceAccountFile",
    "audienceType",
    "audience",
    "appPrincipal",
    "webhookPath",
    "webhookUrl",
    "botUser",
    "dm",
    "typingIndicator",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportDisposition {
    Mapped,
    NeedsSecret,
    NeedsRelink,
    NeedsRuntime,
    Unsupported,
    Unknown,
}

impl ImportDisposition {
    fn as_str(self) -> &'static str {
        match self {
            Self::Mapped => "mapped",
            Self::NeedsSecret => "needs_secret",
            Self::NeedsRelink => "needs_relink",
            Self::NeedsRuntime => "needs_runtime",
            Self::Unsupported => "unsupported",
            Self::Unknown => "unknown",
        }
    }

    fn is_hard_blocker(self) -> bool {
        matches!(
            self,
            Self::NeedsRelink | Self::NeedsRuntime | Self::Unsupported | Self::Unknown
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FieldLedgerEntry {
    pub source_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_channel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_channel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_path: Option<String>,
    pub disposition: ImportDisposition,
    pub sensitive: bool,
    pub reason: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ImportSummary {
    pub total: usize,
    pub mapped: usize,
    pub needs_secret: usize,
    pub needs_relink: usize,
    pub needs_runtime: usize,
    pub unsupported: usize,
    pub unknown: usize,
    pub hard_blockers: usize,
    pub activation_blockers: usize,
}

impl ImportSummary {
    fn record(&mut self, disposition: ImportDisposition) {
        self.total += 1;
        match disposition {
            ImportDisposition::Mapped => self.mapped += 1,
            ImportDisposition::NeedsSecret => self.needs_secret += 1,
            ImportDisposition::NeedsRelink => self.needs_relink += 1,
            ImportDisposition::NeedsRuntime => self.needs_runtime += 1,
            ImportDisposition::Unsupported => self.unsupported += 1,
            ImportDisposition::Unknown => self.unknown += 1,
        }
        if disposition.is_hard_blocker() {
            self.hard_blockers += 1;
        }
        if disposition != ImportDisposition::Mapped {
            self.activation_blockers += 1;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChannelAlias {
    pub openclaw: &'static str,
    pub neoth: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SourceFileBinding {
    /// Canonical path relative to the directory containing `openclaw.json`.
    pub relative_path: String,
    pub sha256: String,
    pub byte_len: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct OpenClawImportReport {
    pub contract_version: &'static str,
    pub importer_version: &'static str,
    pub target_neoth_version: &'static str,
    pub audited_openclaw_schema_commit: &'static str,
    pub known_channel_inventory_sha256: String,
    pub source: String,
    pub format: &'static str,
    pub dry_run_only: bool,
    pub apply_available: bool,
    pub source_set_sha256: String,
    pub source_files: Vec<SourceFileBinding>,
    pub included_files: Vec<String>,
    pub known_channel_keys: Vec<&'static str>,
    pub channel_aliases: Vec<ChannelAlias>,
    pub ledger: Vec<FieldLedgerEntry>,
    pub summary: ImportSummary,
    /// Hard blockers prevent a future config apply. Secret prompts may still
    /// be staged, but `activation_blocked` remains true until they are supplied.
    pub apply_blocked: bool,
    pub activation_blocked: bool,
}

#[derive(Clone, Debug)]
enum PathPart {
    Key(String),
    Index(usize),
}

struct LoadedConfig {
    source: PathBuf,
    source_files: Vec<SourceFileBinding>,
    included_files: Vec<PathBuf>,
    value: Value,
}

/// `serde_json::Value` accepts duplicate object keys with last-value-wins
/// semantics. That would make a complete effective-field ledger ambiguous:
/// one declared key would disappear before classification. Parse through this
/// visitor instead so ambiguous OpenClaw config fails closed.
struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON5 value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("non-finite JSON5 numbers are not supported"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_string(value.to_string())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::with_capacity(object.size_hint().unwrap_or(0));
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON5 object key"));
            }
            let value = object.next_value::<StrictValue>()?;
            values.insert(key, value.0);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

struct IncludeLoader {
    root: PathBuf,
    active: Vec<PathBuf>,
    cache: BTreeMap<PathBuf, Value>,
    file_bindings: BTreeMap<PathBuf, (String, u64)>,
    loaded_files: BTreeSet<PathBuf>,
    total_bytes: u64,
}

/// Parse and inspect an OpenClaw `openclaw.json` without writing target state.
pub fn inspect_openclaw_config(path: &Path) -> Result<OpenClawImportReport> {
    let loaded = load_config(path)?;
    let mut ledger = Vec::new();
    walk_leaves(&loaded.value, &mut Vec::new(), &mut ledger);
    ledger.sort_by(|left, right| left.source_path.cmp(&right.source_path));

    let mut summary = ImportSummary::default();
    for entry in &ledger {
        summary.record(entry.disposition);
    }
    let apply_blocked = summary.hard_blockers > 0;
    let activation_blocked = summary.activation_blockers > 0;
    let known_channel_inventory_sha256 = known_channel_inventory_sha256();
    let source_set_sha256 = source_set_sha256(
        &loaded.source_files,
        known_channel_inventory_sha256.as_str(),
    );

    Ok(OpenClawImportReport {
        contract_version: INSPECT_CONTRACT_VERSION,
        importer_version: env!("CARGO_PKG_VERSION"),
        target_neoth_version: env!("CARGO_PKG_VERSION"),
        audited_openclaw_schema_commit: AUDITED_OPENCLAW_SCHEMA_COMMIT,
        known_channel_inventory_sha256,
        source: loaded.source.display().to_string(),
        format: "openclaw-json5",
        dry_run_only: true,
        apply_available: false,
        source_set_sha256,
        source_files: loaded.source_files,
        included_files: loaded
            .included_files
            .into_iter()
            .map(|included| included.display().to_string())
            .collect(),
        known_channel_keys: KNOWN_CHANNEL_KEYS.to_vec(),
        channel_aliases: CHANNEL_ALIASES
            .iter()
            .map(|(openclaw, neoth)| ChannelAlias { openclaw, neoth })
            .collect(),
        ledger,
        summary,
        apply_blocked,
        activation_blocked,
    })
}

pub fn render_human(report: &OpenClawImportReport) -> String {
    let mut output = String::new();
    output.push_str("OpenClaw migration inspect/plan (read-only; apply unavailable)\n");
    output.push_str(&format!("contract: {}\n", report.contract_version));
    output.push_str(&format!(
        "target NEOTH: {}; audited OpenClaw schema: {}\n",
        report.target_neoth_version, report.audited_openclaw_schema_commit
    ));
    output.push_str(&format!(
        "known-channel inventory sha256: {}\n",
        report.known_channel_inventory_sha256
    ));
    output.push_str(&format!("source: {}\n", report.source));
    output.push_str(&format!(
        "source-set sha256: {} ({} file(s))\n",
        report.source_set_sha256,
        report.source_files.len()
    ));
    output.push_str(&format!(
        "fields: {} total, {} mapped, {} need secret, {} hard blocker(s)\n",
        report.summary.total,
        report.summary.mapped,
        report.summary.needs_secret,
        report.summary.hard_blockers
    ));
    output.push_str(&format!(
        "apply blocked: {}; activation blocked: {}\n",
        report.apply_blocked, report.activation_blocked
    ));
    for entry in &report.ledger {
        output.push_str(&format!(
            "- [{}] {}",
            entry.disposition.as_str(),
            entry.source_path
        ));
        if let Some(target) = &entry.target_path {
            output.push_str(&format!(" -> {target}"));
        }
        if entry.sensitive {
            output.push_str(" [REDACTED]");
        }
        output.push_str(&format!(": {}\n", entry.reason));
    }
    output
}

fn load_config(path: &Path) -> Result<LoadedConfig> {
    anyhow::ensure!(
        path.file_name().and_then(|name| name.to_str()) == Some("openclaw.json"),
        "expected an OpenClaw config named openclaw.json: {}",
        path.display()
    );
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect OpenClaw config {}", path.display()))?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "the primary openclaw.json must be a regular file, not a symlink"
    );
    anyhow::ensure!(metadata.is_file(), "openclaw.json is not a regular file");

    let source = std::fs::canonicalize(path)
        .with_context(|| format!("resolve OpenClaw config {}", path.display()))?;
    let root = source
        .parent()
        .context("openclaw.json has no parent directory")?
        .to_path_buf();
    let mut loader = IncludeLoader {
        root,
        active: Vec::new(),
        cache: BTreeMap::new(),
        file_bindings: BTreeMap::new(),
        loaded_files: BTreeSet::new(),
        total_bytes: 0,
    };
    let value = loader.load_file(&source, 0)?;
    let source_files = loader
        .file_bindings
        .iter()
        .map(|(path, (sha256, byte_len))| {
            let relative = path.strip_prefix(&loader.root).with_context(|| {
                format!(
                    "loaded OpenClaw source escaped its canonical root: {}",
                    path.display()
                )
            })?;
            Ok(SourceFileBinding {
                relative_path: portable_relative_path(relative)?,
                sha256: sha256.clone(),
                byte_len: *byte_len,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let included_files = loader
        .loaded_files
        .into_iter()
        .filter(|loaded| loaded != &source)
        .collect();
    Ok(LoadedConfig {
        source,
        source_files,
        included_files,
        value,
    })
}

impl IncludeLoader {
    fn load_file(&mut self, path: &Path, depth: usize) -> Result<Value> {
        anyhow::ensure!(
            depth <= MAX_INCLUDE_DEPTH,
            "maximum OpenClaw include depth ({MAX_INCLUDE_DEPTH}) exceeded"
        );
        let canonical = std::fs::canonicalize(path)
            .with_context(|| format!("resolve included config {}", path.display()))?;
        anyhow::ensure!(
            path_within(&canonical, &self.root),
            "OpenClaw include resolves outside the config root: {}",
            path.display()
        );
        if let Some(position) = self.active.iter().position(|active| active == &canonical) {
            let mut chain = self.active[position..]
                .iter()
                .map(|entry| entry.display().to_string())
                .collect::<Vec<_>>();
            chain.push(canonical.display().to_string());
            anyhow::bail!("circular OpenClaw include: {}", chain.join(" -> "));
        }
        if let Some(cached) = self.cache.get(&canonical) {
            return Ok(cached.clone());
        }
        anyhow::ensure!(
            self.loaded_files.len() < MAX_FILES,
            "OpenClaw config exceeds the {MAX_FILES}-file include limit"
        );

        let metadata = std::fs::metadata(&canonical)
            .with_context(|| format!("inspect included config {}", canonical.display()))?;
        anyhow::ensure!(
            metadata.is_file(),
            "OpenClaw include is not a regular file: {}",
            canonical.display()
        );
        anyhow::ensure!(
            metadata.len() <= MAX_INCLUDE_FILE_BYTES,
            "OpenClaw include exceeds the {MAX_INCLUDE_FILE_BYTES}-byte file limit: {}",
            canonical.display()
        );

        let mut file = File::open(&canonical)
            .with_context(|| format!("open included config {}", canonical.display()))?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize + 1);
        file.by_ref()
            .take(MAX_INCLUDE_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("read included config {}", canonical.display()))?;
        anyhow::ensure!(
            bytes.len() as u64 <= MAX_INCLUDE_FILE_BYTES,
            "OpenClaw include grew beyond the {MAX_INCLUDE_FILE_BYTES}-byte file limit while reading"
        );
        self.total_bytes = self
            .total_bytes
            .checked_add(bytes.len() as u64)
            .context("OpenClaw include byte count overflow")?;
        anyhow::ensure!(
            self.total_bytes <= MAX_TOTAL_BYTES,
            "OpenClaw config exceeds the {MAX_TOTAL_BYTES}-byte total include limit"
        );
        self.file_bindings.insert(
            canonical.clone(),
            (sha256_bytes(&bytes), bytes.len() as u64),
        );
        let text = std::str::from_utf8(&bytes).map_err(|_| {
            anyhow::anyhow!(
                "OpenClaw config is not valid UTF-8: {}",
                canonical.display()
            )
        })?;
        // Never include the parser's source excerpt in the error: it can contain
        // inline tokens or passwords.
        let parsed: StrictValue = json5::from_str(text)
            .map_err(|_| anyhow::anyhow!("parse JSON5 failed in {}", canonical.display()))?;

        self.active.push(canonical.clone());
        self.loaded_files.insert(canonical.clone());
        let resolved = self.resolve_value(parsed.0, &canonical, depth)?;
        let popped = self.active.pop();
        debug_assert_eq!(popped.as_ref(), Some(&canonical));
        self.cache.insert(canonical, resolved.clone());
        Ok(resolved)
    }

    fn resolve_value(&mut self, value: Value, current_file: &Path, depth: usize) -> Result<Value> {
        match value {
            Value::Array(values) => {
                let resolved = values
                    .into_iter()
                    .map(|value| self.resolve_value(value, current_file, depth))
                    .collect::<Result<Vec<_>>>()?;
                Ok(Value::Array(resolved))
            }
            Value::Object(mut object) => {
                let Some(include) = object.remove("$include") else {
                    let mut resolved = Map::new();
                    for (key, value) in object {
                        resolved.insert(key, self.resolve_value(value, current_file, depth)?);
                    }
                    return Ok(Value::Object(resolved));
                };

                let mut included = self.resolve_include(include, current_file, depth + 1)?;
                if object.is_empty() {
                    return Ok(included);
                }
                anyhow::ensure!(
                    included.is_object(),
                    "OpenClaw include with sibling keys must resolve to an object"
                );
                let mut siblings = Map::new();
                for (key, value) in object {
                    siblings.insert(key, self.resolve_value(value, current_file, depth)?);
                }
                deep_merge(&mut included, Value::Object(siblings));
                Ok(included)
            }
            scalar => Ok(scalar),
        }
    }

    fn resolve_include(
        &mut self,
        include: Value,
        current_file: &Path,
        depth: usize,
    ) -> Result<Value> {
        match include {
            Value::String(path) => self.load_relative(current_file, &path, depth),
            Value::Array(paths) => {
                let mut merged = Value::Object(Map::new());
                for path in paths {
                    let Value::String(path) = path else {
                        anyhow::bail!("OpenClaw $include arrays may contain only path strings");
                    };
                    let next = self.load_relative(current_file, &path, depth)?;
                    deep_merge(&mut merged, next);
                }
                Ok(merged)
            }
            _ => {
                anyhow::bail!("OpenClaw $include must be a path string or an array of path strings")
            }
        }
    }

    fn load_relative(&mut self, current_file: &Path, include: &str, depth: usize) -> Result<Value> {
        anyhow::ensure!(
            !include.trim().is_empty(),
            "OpenClaw $include path is empty"
        );
        let include_path = Path::new(include);
        let candidate = if include_path.is_absolute() {
            include_path.to_path_buf()
        } else {
            current_file
                .parent()
                .context("included config has no parent directory")?
                .join(include_path)
        };
        self.load_file(&candidate, depth)
    }
}

fn portable_relative_path(path: &Path) -> Result<String> {
    Ok(path
        .components()
        .map(|component| {
            component
                .as_os_str()
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "OpenClaw source path is not valid Unicode and cannot be bound losslessly: {}",
                        path.display()
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?
        .join("/"))
}

fn source_set_sha256(files: &[SourceFileBinding], known_channel_inventory_sha256: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(INSPECT_CONTRACT_VERSION.as_bytes());
    hasher.update([0]);
    hasher.update(env!("CARGO_PKG_VERSION").as_bytes());
    hasher.update([0]);
    hasher.update(AUDITED_OPENCLAW_SCHEMA_COMMIT.as_bytes());
    hasher.update([0]);
    hasher.update(known_channel_inventory_sha256.as_bytes());
    hasher.update([0]);
    for file in files {
        hasher.update(file.relative_path.as_bytes());
        hasher.update([0]);
        hasher.update(file.byte_len.to_be_bytes());
        hasher.update([0]);
        hasher.update(file.sha256.as_bytes());
        hasher.update([0]);
    }
    format!("{:x}", hasher.finalize())
}

fn known_channel_inventory_sha256() -> String {
    let mut hasher = Sha256::new();
    hasher.update(AUDITED_OPENCLAW_SCHEMA_COMMIT.as_bytes());
    hasher.update([0]);
    for channel in KNOWN_CHANNEL_KEYS {
        hasher.update(channel.as_bytes());
        hasher.update([0]);
    }
    format!("{:x}", hasher.finalize())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn path_within(path: &Path, root: &Path) -> bool {
    #[cfg(windows)]
    {
        let path = path
            .to_string_lossy()
            .replace('\\', "/")
            .to_ascii_lowercase();
        let root = root
            .to_string_lossy()
            .replace('\\', "/")
            .to_ascii_lowercase();
        path == root
            || path
                .strip_prefix(&root)
                .is_some_and(|rest| rest.starts_with('/'))
    }
    #[cfg(not(windows))]
    {
        path.starts_with(root)
    }
}

fn deep_merge(target: &mut Value, source: Value) {
    match (target, source) {
        (Value::Array(target), Value::Array(source)) => target.extend(source),
        (Value::Object(target), Value::Object(source)) => {
            for (key, value) in source {
                if let Some(existing) = target.get_mut(&key) {
                    deep_merge(existing, value);
                } else {
                    target.insert(key, value);
                }
            }
        }
        (target, source) => *target = source,
    }
}

fn walk_leaves(value: &Value, path: &mut Vec<PathPart>, ledger: &mut Vec<FieldLedgerEntry>) {
    if is_secret_ref(value) {
        ledger.push(classify_leaf(path, true));
        return;
    }
    match value {
        Value::Object(object) if !object.is_empty() => {
            for (key, value) in object {
                path.push(PathPart::Key(key.clone()));
                walk_leaves(value, path, ledger);
                path.pop();
            }
        }
        Value::Array(values) if !values.is_empty() => {
            for (index, value) in values.iter().enumerate() {
                path.push(PathPart::Index(index));
                walk_leaves(value, path, ledger);
                path.pop();
            }
        }
        Value::Object(object) if object.is_empty() && path.is_empty() => {}
        Value::Array(values) if values.is_empty() && path.is_empty() => {}
        _ => ledger.push(classify_leaf(path, false)),
    }
}

fn classify_leaf(path: &[PathPart], secret_ref: bool) -> FieldLedgerEntry {
    let source_path = display_path(path);
    let sensitive = secret_ref || path_is_sensitive(path);
    let root = key_at(path, 0);
    if root != Some("channels") {
        let known = root.is_some_and(|root| KNOWN_ROOT_KEYS.contains(&root));
        return FieldLedgerEntry {
            source_path,
            source_channel: None,
            target_channel: None,
            target_path: None,
            disposition: if known {
                ImportDisposition::Unsupported
            } else {
                ImportDisposition::Unknown
            },
            sensitive,
            reason: if known {
                "known OpenClaw field is outside this channel-import slice".to_string()
            } else {
                "unknown OpenClaw root field".to_string()
            },
        };
    }

    let Some(channel) = key_at(path, 1) else {
        return FieldLedgerEntry {
            source_path,
            source_channel: None,
            target_channel: None,
            target_path: None,
            disposition: ImportDisposition::Mapped,
            sensitive,
            reason: "empty channel configuration".to_string(),
        };
    };
    if matches!(channel, "defaults" | "modelByChannel") {
        return FieldLedgerEntry {
            source_path,
            source_channel: Some(channel.to_string()),
            target_channel: None,
            target_path: None,
            disposition: ImportDisposition::Unsupported,
            sensitive,
            reason: format!("OpenClaw channels.{channel} has no NEOTH import target yet"),
        };
    }

    let target_channel = alias_target(channel);
    if !KNOWN_CHANNEL_KEYS.contains(&channel) {
        return FieldLedgerEntry {
            source_path,
            source_channel: Some(channel.to_string()),
            target_channel: None,
            target_path: None,
            disposition: ImportDisposition::Unknown,
            sensitive,
            reason: "unknown or third-party OpenClaw channel; explicit adoption is required"
                .to_string(),
        };
    }
    let Some(target_channel) = target_channel else {
        return FieldLedgerEntry {
            source_path,
            source_channel: Some(channel.to_string()),
            target_channel: None,
            target_path: None,
            disposition: ImportDisposition::Unsupported,
            sensitive,
            reason: "known OpenClaw channel has no NEOTH adapter".to_string(),
        };
    };

    let field = account_or_channel_field(path);
    let account_scoped = key_at(path, 2) == Some("accounts");
    if account_scoped {
        return FieldLedgerEntry {
            source_path,
            source_channel: Some(channel.to_string()),
            target_channel: Some(target_channel.to_string()),
            target_path: None,
            disposition: ImportDisposition::Unsupported,
            sensitive,
            reason: "OpenClaw multi-account config cannot be flattened into NEOTH's single account"
                .to_string(),
        };
    }
    let Some(field) = field else {
        return FieldLedgerEntry {
            source_path,
            source_channel: Some(channel.to_string()),
            target_channel: Some(target_channel.to_string()),
            target_path: None,
            disposition: ImportDisposition::Mapped,
            sensitive,
            reason: "empty channel object".to_string(),
        };
    };
    if !known_channel_field(channel, field) {
        return FieldLedgerEntry {
            source_path,
            source_channel: Some(channel.to_string()),
            target_channel: Some(target_channel.to_string()),
            target_path: None,
            disposition: ImportDisposition::Unknown,
            sensitive,
            reason: format!("unknown OpenClaw {channel} field `{field}`"),
        };
    }

    let (disposition, target_path, reason) = classify_known_field(channel, field, sensitive);
    FieldLedgerEntry {
        source_path,
        source_channel: Some(channel.to_string()),
        target_channel: Some(target_channel.to_string()),
        target_path: target_path.map(str::to_string),
        disposition,
        sensitive,
        reason: reason.to_string(),
    }
}

fn classify_known_field(
    channel: &str,
    field: &str,
    sensitive: bool,
) -> (ImportDisposition, Option<&'static str>, &'static str) {
    if channel == "whatsapp" && field == "authDir" {
        return (
            ImportDisposition::NeedsRelink,
            None,
            "OpenClaw WhatsApp auth state is not portable; relink the Baileys account by QR",
        );
    }
    if channel == "imessage"
        && matches!(
            field,
            "cliPath"
                | "dbPath"
                | "remoteHost"
                | "service"
                | "region"
                | "attachmentRoots"
                | "remoteAttachmentRoots"
        )
    {
        return (
            ImportDisposition::NeedsRelink,
            None,
            "OpenClaw uses imsg while NEOTH uses BlueBubbles; a guided transport relink is required",
        );
    }
    if channel == "signal"
        && matches!(
            field,
            "cliPath"
                | "autoStart"
                | "startupTimeoutMs"
                | "receiveMode"
                | "apiMode"
                | "httpHost"
                | "httpPort"
        )
    {
        return (
            ImportDisposition::NeedsRuntime,
            None,
            "Signal runtime lifecycle is not yet managed by the NEOTH installer",
        );
    }
    if channel == "googlechat"
        && matches!(
            field,
            "audienceType" | "audience" | "appPrincipal" | "webhookPath" | "webhookUrl" | "botUser"
        )
    {
        return (
            ImportDisposition::NeedsRuntime,
            None,
            "OpenClaw webhook config cannot supply NEOTH's required Pub/Sub subscription",
        );
    }

    if let Some(target) = mapped_target_path(channel, field) {
        return if sensitive {
            (
                ImportDisposition::NeedsSecret,
                Some(target),
                "secret value redacted; transfer through NEOTH's credential flow",
            )
        } else {
            (
                ImportDisposition::Mapped,
                Some(target),
                "field has a direct NEOTH credential mapping",
            )
        };
    }

    (
        ImportDisposition::Unsupported,
        None,
        "known OpenClaw field has no lossless NEOTH target yet",
    )
}

fn mapped_target_path(channel: &str, field: &str) -> Option<&'static str> {
    match (channel, field) {
        ("telegram", "botToken" | "tokenFile") => Some("credentials.telegram_token"),
        ("slack", "botToken") => Some("credentials.slack_bot_token"),
        ("slack", "appToken") => Some("credentials.slack_app_token"),
        ("discord", "token") => Some("credentials.discord_bot_token"),
        ("signal", "account") => Some("credentials.signal_phone_number"),
        ("signal", "httpUrl") => Some("credentials.signal_cli_url"),
        ("matrix", "homeserver") => Some("credentials.matrix_homeserver"),
        ("matrix", "userId") => Some("credentials.matrix_user_id"),
        ("matrix", "accessToken") => Some("credentials.matrix_access_token"),
        ("matrix", "password") => Some("credentials.matrix_password"),
        ("matrix", "encryption") => Some("credentials.matrix_require_encryption"),
        ("line", "channelAccessToken" | "tokenFile") => {
            Some("credentials.line_channel_access_token")
        }
        ("line", "channelSecret" | "secretFile") => Some("credentials.line_channel_secret"),
        ("irc", "host") => Some("credentials.irc_server"),
        ("irc", "port") => Some("credentials.irc_port"),
        ("irc", "tls") => Some("credentials.irc_tls"),
        ("irc", "nick") => Some("credentials.irc_nick"),
        ("irc", "password" | "passwordFile") => Some("credentials.irc_password"),
        ("irc", "channels") => Some("credentials.irc_channels"),
        ("mattermost", "baseUrl") => Some("credentials.mattermost_url"),
        ("mattermost", "botToken") => Some("credentials.mattermost_token"),
        ("twitch", "username") => Some("credentials.twitch_username"),
        ("twitch", "accessToken") => Some("credentials.twitch_oauth_token"),
        ("twitch", "channel") => Some("credentials.twitch_channels"),
        ("nostr", "privateKey") => Some("credentials.nostr_secret_key"),
        ("nostr", "relays") => Some("credentials.nostr_relays"),
        ("googlechat", "serviceAccount" | "serviceAccountRef" | "serviceAccountFile") => {
            Some("credentials.gchat_service_account_json")
        }
        _ => None,
    }
}

fn alias_target(channel: &str) -> Option<&'static str> {
    CHANNEL_ALIASES
        .iter()
        .find_map(|(source, target)| (*source == channel).then_some(*target))
}

fn known_channel_field(channel: &str, field: &str) -> bool {
    if COMMON_CHANNEL_FIELDS.contains(&field) {
        return true;
    }
    let fields = match channel {
        "telegram" => TELEGRAM_FIELDS,
        "slack" => SLACK_FIELDS,
        "whatsapp" => WHATSAPP_FIELDS,
        "discord" => DISCORD_FIELDS,
        "signal" => SIGNAL_FIELDS,
        "imessage" => IMESSAGE_FIELDS,
        "matrix" => MATRIX_FIELDS,
        "line" => LINE_FIELDS,
        "irc" => IRC_FIELDS,
        "mattermost" => MATTERMOST_FIELDS,
        "twitch" => TWITCH_FIELDS,
        "nostr" => NOSTR_FIELDS,
        "googlechat" => GOOGLECHAT_FIELDS,
        _ => &[],
    };
    fields.contains(&field)
}

fn account_or_channel_field(path: &[PathPart]) -> Option<&str> {
    if key_at(path, 2) == Some("accounts") {
        key_at(path, 4).or(Some("accounts"))
    } else {
        key_at(path, 2)
    }
}

fn key_at(path: &[PathPart], index: usize) -> Option<&str> {
    match path.get(index) {
        Some(PathPart::Key(key)) => Some(key),
        _ => None,
    }
}

fn display_path(path: &[PathPart]) -> String {
    if path.is_empty() {
        return "$".to_string();
    }
    let mut output = String::new();
    for (index, part) in path.iter().enumerate() {
        match part {
            PathPart::Key(key) => {
                if index > 0 {
                    output.push('.');
                }
                output.push_str(key);
            }
            PathPart::Index(value) => output.push_str(&format!("[{value}]")),
        }
    }
    output
}

fn is_secret_ref(value: &Value) -> bool {
    let Value::Object(object) = value else {
        return false;
    };
    matches!(
        object.get("source").and_then(Value::as_str),
        Some("env" | "file" | "exec")
    ) && object.get("id").and_then(Value::as_str).is_some()
}

fn path_is_sensitive(path: &[PathPart]) -> bool {
    path.iter().any(|part| {
        let PathPart::Key(key) = part else {
            return false;
        };
        let compact = key
            .chars()
            .filter(|character| character.is_ascii_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect::<String>();
        compact.contains("token")
            || compact.contains("secret")
            || compact.contains("password")
            || compact.contains("privatekey")
            || compact.contains("authdir")
            || compact == "serviceaccount"
            || compact == "serviceaccountref"
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_config(root: &Path, body: &str) -> PathBuf {
        let path = root.join("openclaw.json");
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn parses_json5_and_resolves_nested_includes_with_sibling_overrides() {
        let temp = tempdir().unwrap();
        std::fs::write(
            temp.path().join("telegram.json5"),
            "{ botToken: 'top-secret-token', enabled: true, }",
        )
        .unwrap();
        std::fs::write(
            temp.path().join("channels.json5"),
            "{ telegram: { $include: './telegram.json5', enabled: false }, }",
        )
        .unwrap();
        let path = write_config(
            temp.path(),
            "{ // JSON5 comment\n channels: { $include: './channels.json5', }, }",
        );

        let report = inspect_openclaw_config(&path).unwrap();
        assert_eq!(report.included_files.len(), 2);
        assert!(report.ledger.iter().any(|entry| {
            entry.source_path == "channels.telegram.enabled"
                && entry.disposition == ImportDisposition::Unsupported
        }));
        let token = report
            .ledger
            .iter()
            .find(|entry| entry.source_path == "channels.telegram.botToken")
            .unwrap();
        assert_eq!(token.disposition, ImportDisposition::NeedsSecret);
        assert!(token.sensitive);
    }

    #[test]
    fn include_arrays_deep_merge_objects_and_concatenate_arrays() {
        let temp = tempdir().unwrap();
        std::fs::write(
            temp.path().join("first.json5"),
            "{ irc: { host: 'irc.example', channels: ['#one'] } }",
        )
        .unwrap();
        std::fs::write(
            temp.path().join("second.json5"),
            "{ irc: { tls: true, channels: ['#two'] } }",
        )
        .unwrap();
        let path = write_config(
            temp.path(),
            "{ channels: { $include: ['./first.json5', './second.json5'] } }",
        );
        let report = inspect_openclaw_config(&path).unwrap();
        let paths = report
            .ledger
            .iter()
            .map(|entry| entry.source_path.as_str())
            .collect::<BTreeSet<_>>();
        assert!(paths.contains("channels.irc.host"));
        assert!(paths.contains("channels.irc.tls"));
        assert!(paths.contains("channels.irc.channels[0]"));
        assert!(paths.contains("channels.irc.channels[1]"));
    }

    #[test]
    fn source_set_binding_covers_primary_and_included_bytes() {
        let temp = tempdir().unwrap();
        let included = temp.path().join("telegram.json5");
        std::fs::write(&included, "{ telegram: { enabled: true } }").unwrap();
        let path = write_config(
            temp.path(),
            "{ channels: { $include: './telegram.json5' } }",
        );

        let first = inspect_openclaw_config(&path).unwrap();
        assert_eq!(first.contract_version, INSPECT_CONTRACT_VERSION);
        assert_eq!(first.target_neoth_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(
            first.audited_openclaw_schema_commit,
            AUDITED_OPENCLAW_SCHEMA_COMMIT
        );
        assert_eq!(first.known_channel_inventory_sha256.len(), 64);
        assert!(!first.apply_available);
        assert_eq!(
            first
                .source_files
                .iter()
                .map(|file| file.relative_path.as_str())
                .collect::<Vec<_>>(),
            vec!["openclaw.json", "telegram.json5"]
        );
        assert!(
            first
                .source_files
                .iter()
                .all(|file| file.sha256.len() == 64 && file.byte_len > 0)
        );

        std::fs::write(&included, "{ telegram: { enabled: false } }").unwrap();
        let second = inspect_openclaw_config(&path).unwrap();
        assert_ne!(first.source_set_sha256, second.source_set_sha256);
        assert_eq!(first.source_set_sha256.len(), 64);
        assert_eq!(second.source_set_sha256.len(), 64);
    }

    #[cfg(unix)]
    #[test]
    fn source_binding_rejects_non_unicode_relative_paths() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;

        let path = PathBuf::from(OsString::from_vec(b"source-\xff.json5".to_vec()));
        let error = portable_relative_path(&path).unwrap_err();
        assert!(error.to_string().contains("cannot be bound losslessly"));
    }

    #[test]
    fn rejects_include_outside_root() {
        let temp = tempdir().unwrap();
        let config_root = temp.path().join("config");
        std::fs::create_dir_all(&config_root).unwrap();
        std::fs::write(temp.path().join("outside.json5"), "{ telegram: {} }").unwrap();
        let path = write_config(
            &config_root,
            "{ channels: { $include: '../outside.json5' } }",
        );
        let error = inspect_openclaw_config(&path).unwrap_err();
        assert!(format!("{error:#}").contains("outside the config root"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_include_escape() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().unwrap();
        let config_root = temp.path().join("config");
        std::fs::create_dir_all(&config_root).unwrap();
        let outside = temp.path().join("outside.json5");
        std::fs::write(&outside, "{ telegram: {} }").unwrap();
        symlink(&outside, config_root.join("escape.json5")).unwrap();
        let path = write_config(&config_root, "{ channels: { $include: './escape.json5' } }");
        assert!(inspect_openclaw_config(&path).is_err());
    }

    #[test]
    fn rejects_include_cycles() {
        let temp = tempdir().unwrap();
        std::fs::write(temp.path().join("a.json5"), "{ $include: './b.json5' }").unwrap();
        std::fs::write(temp.path().join("b.json5"), "{ $include: './a.json5' }").unwrap();
        let path = write_config(temp.path(), "{ channels: { $include: './a.json5' } }");
        let error = inspect_openclaw_config(&path).unwrap_err();
        assert!(format!("{error:#}").contains("circular OpenClaw include"));
    }

    #[test]
    fn rejects_include_depth_and_file_size_limits() {
        let temp = tempdir().unwrap();
        for index in 0..=MAX_INCLUDE_DEPTH {
            let next = index + 1;
            std::fs::write(
                temp.path().join(format!("depth-{index}.json5")),
                format!("{{ $include: './depth-{next}.json5' }}"),
            )
            .unwrap();
        }
        std::fs::write(
            temp.path()
                .join(format!("depth-{}.json5", MAX_INCLUDE_DEPTH + 1)),
            "{}",
        )
        .unwrap();
        let path = write_config(temp.path(), "{ channels: { $include: './depth-0.json5' } }");
        assert!(inspect_openclaw_config(&path).is_err());

        let oversized = " ".repeat(MAX_INCLUDE_FILE_BYTES as usize + 1);
        std::fs::write(temp.path().join("oversized.json5"), oversized).unwrap();
        std::fs::write(&path, "{ channels: { $include: './oversized.json5' } }").unwrap();
        assert!(inspect_openclaw_config(&path).is_err());
    }

    #[test]
    fn rejects_total_include_size_limit_before_parsing() {
        let temp = tempdir().unwrap();
        let included = temp.path().join("small.json5");
        std::fs::write(&included, "{}").unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let mut loader = IncludeLoader {
            root,
            active: Vec::new(),
            cache: BTreeMap::new(),
            file_bindings: BTreeMap::new(),
            loaded_files: BTreeSet::new(),
            total_bytes: MAX_TOTAL_BYTES,
        };
        let error = loader.load_file(&included, 0).unwrap_err();
        assert!(format!("{error:#}").contains("total include limit"));
    }

    #[test]
    fn whatsapp_alias_is_baileys_and_auth_requires_relink() {
        let temp = tempdir().unwrap();
        let path = write_config(
            temp.path(),
            "{ channels: { whatsapp: { authDir: './auth/primary' } } }",
        );
        let report = inspect_openclaw_config(&path).unwrap();
        let auth = report
            .ledger
            .iter()
            .find(|entry| entry.source_path == "channels.whatsapp.authDir")
            .unwrap();
        assert_eq!(auth.target_channel.as_deref(), Some("whatsapp_baileys"));
        assert_eq!(auth.disposition, ImportDisposition::NeedsRelink);
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("whatsapp_business")
        );
    }

    #[test]
    fn direct_targets_use_real_neoth_credential_keys() {
        assert_eq!(
            mapped_target_path("line", "channelAccessToken"),
            Some("credentials.line_channel_access_token")
        );
        assert_eq!(
            mapped_target_path("googlechat", "serviceAccountFile"),
            Some("credentials.gchat_service_account_json")
        );
        assert_eq!(
            mapped_target_path("matrix", "encryption"),
            Some("credentials.matrix_require_encryption")
        );
    }

    #[test]
    fn manifest_evidenced_channel_inventory_includes_raft_reef_and_sms() {
        assert_eq!(
            KNOWN_CHANNEL_KEYS,
            &[
                "clickclack",
                "discord",
                "feishu",
                "googlechat",
                "imessage",
                "irc",
                "line",
                "matrix",
                "mattermost",
                "msteams",
                "nextcloud-talk",
                "nostr",
                "qa-channel",
                "qqbot",
                "raft",
                "reef",
                "signal",
                "slack",
                "sms",
                "synology-chat",
                "telegram",
                "tlon",
                "twitch",
                "whatsapp",
                "zalo",
                "zalouser",
            ]
        );

        let temp = tempdir().unwrap();
        let path = write_config(
            temp.path(),
            "{ channels: { raft: { enabled: true }, reef: { enabled: true }, sms: { enabled: true } } }",
        );
        let report = inspect_openclaw_config(&path).unwrap();
        assert_eq!(report.summary.unknown, 0);
        assert_eq!(report.summary.unsupported, 3);
        assert!(report.apply_blocked);
    }

    #[test]
    fn runtime_and_multi_account_gaps_are_hard_blockers() {
        let temp = tempdir().unwrap();
        let path = write_config(
            temp.path(),
            "{ channels: {
                signal: { cliPath: '/usr/bin/signal-cli' },
                telegram: { accounts: { work: { botToken: 'secret-work-token' } } }
            } }",
        );
        let report = inspect_openclaw_config(&path).unwrap();
        assert!(report.apply_blocked);
        assert!(report.ledger.iter().any(|entry| {
            entry.source_path == "channels.signal.cliPath"
                && entry.disposition == ImportDisposition::NeedsRuntime
        }));
        let account_token = report
            .ledger
            .iter()
            .find(|entry| entry.source_path == "channels.telegram.accounts.work.botToken")
            .unwrap();
        assert_eq!(account_token.disposition, ImportDisposition::Unsupported);
        assert!(account_token.sensitive);
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("secret-work-token")
        );
    }

    #[test]
    fn unknown_channel_and_nested_field_are_fail_closed() {
        let temp = tempdir().unwrap();
        let path = write_config(
            temp.path(),
            "{ channels: { telegram: { typoTokenPolicy: true }, futurechat: { enabled: true } } }",
        );
        let report = inspect_openclaw_config(&path).unwrap();
        assert!(report.apply_blocked);
        assert_eq!(report.summary.unknown, 2);
        assert!(report.ledger.iter().all(|entry| {
            entry.disposition == ImportDisposition::Unknown && entry.sensitive
                || entry.source_path == "channels.futurechat.enabled"
        }));
    }

    #[test]
    fn unknown_account_secret_and_root_blockers_keep_exact_source_paths() {
        let temp = tempdir().unwrap();
        let account_secret = "account-secret-never-render";
        let direct_secret = "direct-secret-never-render";
        let future_secret = "future-secret-never-render";
        let path = write_config(
            temp.path(),
            &format!(
                "{{
                    models: {{ providers: [{{ kind: 'openai' }}] }},
                    channels: {{
                        telegram: {{
                            botToken: '{direct_secret}',
                            accounts: {{ work: {{ botToken: '{account_secret}' }} }},
                            unknownTokenPolicy: true
                        }},
                        futurechat: {{ accounts: {{ personal: {{ accessToken: '{future_secret}' }} }} }}
                    }}
                }}"
            ),
        );

        let report = inspect_openclaw_config(&path).unwrap();
        let dispositions = report
            .ledger
            .iter()
            .map(|entry| (entry.source_path.as_str(), entry.disposition))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            dispositions.get("models.providers[0].kind"),
            Some(&ImportDisposition::Unsupported)
        );
        assert_eq!(
            dispositions.get("channels.telegram.botToken"),
            Some(&ImportDisposition::NeedsSecret)
        );
        assert_eq!(
            dispositions.get("channels.telegram.accounts.work.botToken"),
            Some(&ImportDisposition::Unsupported)
        );
        assert_eq!(
            dispositions.get("channels.telegram.unknownTokenPolicy"),
            Some(&ImportDisposition::Unknown)
        );
        assert_eq!(
            dispositions.get("channels.futurechat.accounts.personal.accessToken"),
            Some(&ImportDisposition::Unknown)
        );
        assert!(report.apply_blocked);
        assert!(report.activation_blocked);
        let rendered = format!(
            "{}\n{}",
            serde_json::to_string(&report).unwrap(),
            render_human(&report)
        );
        for secret in [account_secret, direct_secret, future_secret] {
            assert!(!rendered.contains(secret));
        }
        for source_path in dispositions.keys() {
            assert!(rendered.contains(source_path));
        }
    }

    #[test]
    fn every_effective_leaf_including_empty_containers_is_ledgered_once() {
        let temp = tempdir().unwrap();
        let path = write_config(
            temp.path(),
            "{
                meta: { lastTouchedVersion: '1.2.3' },
                channels: {
                    telegram: {
                        enabled: false,
                        allowFrom: [],
                        groups: { trusted: { requireMention: true } }
                    }
                }
            }",
        );
        let report = inspect_openclaw_config(&path).unwrap();
        let paths = report
            .ledger
            .iter()
            .map(|entry| entry.source_path.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            paths.len(),
            report.ledger.len(),
            "ledger paths must be unique"
        );
        assert_eq!(report.ledger.len(), 4);
        assert!(paths.contains("meta.lastTouchedVersion"));
        assert!(paths.contains("channels.telegram.enabled"));
        assert!(paths.contains("channels.telegram.allowFrom"));
        assert!(paths.contains("channels.telegram.groups.trusted.requireMention"));
    }

    #[test]
    fn secret_values_and_parser_excerpts_never_leak() {
        let temp = tempdir().unwrap();
        let secret = "must-never-appear-in-output";
        let path = write_config(
            temp.path(),
            &format!("{{ channels: {{ telegram: {{ botToken: '{secret}' }} }} }}"),
        );
        let report = inspect_openclaw_config(&path).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let human = render_human(&report);
        assert!(!json.contains(secret));
        assert!(!human.contains(secret));
        assert!(human.contains("[REDACTED]"));

        std::fs::write(
            &path,
            format!("{{ channels: {{ telegram: {{ botToken: '{secret}', broken: }} }} }}"),
        )
        .unwrap();
        let error = inspect_openclaw_config(&path).unwrap_err();
        assert!(!format!("{error:#}").contains(secret));
    }

    #[test]
    fn duplicate_keys_fail_closed_without_leaking_values() {
        let temp = tempdir().unwrap();
        let secret = "duplicate-key-secret-must-stay-hidden";
        let path = write_config(
            temp.path(),
            &format!(
                "{{ channels: {{ telegram: {{ botToken: '{secret}', botToken: 'other' }} }} }}"
            ),
        );
        let error = inspect_openclaw_config(&path).unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("parse JSON5 failed"));
        assert!(!rendered.contains(secret));
    }

    #[test]
    fn unusual_object_keys_are_ledgered_instead_of_silently_dropped() {
        let temp = tempdir().unwrap();
        std::fs::write(
            temp.path().join("telegram.json5"),
            "{ telegram: { constructor: true, __proto__: false } }",
        )
        .unwrap();
        let path = write_config(
            temp.path(),
            "{ channels: { $include: './telegram.json5' } }",
        );
        let report = inspect_openclaw_config(&path).unwrap();
        let paths = report
            .ledger
            .iter()
            .map(|entry| entry.source_path.as_str())
            .collect::<BTreeSet<_>>();
        assert!(paths.contains("channels.telegram.constructor"));
        assert!(paths.contains("channels.telegram.__proto__"));
        assert_eq!(report.summary.unknown, 2);
    }

    #[test]
    fn secret_ref_is_one_redacted_ledger_leaf() {
        let temp = tempdir().unwrap();
        let path = write_config(
            temp.path(),
            "{ channels: { telegram: { botToken: { source: 'env', provider: 'default', id: 'BOT_TOKEN' } } } }",
        );
        let report = inspect_openclaw_config(&path).unwrap();
        assert_eq!(report.ledger.len(), 1);
        assert_eq!(report.ledger[0].source_path, "channels.telegram.botToken");
        assert_eq!(report.ledger[0].disposition, ImportDisposition::NeedsSecret);
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains("BOT_TOKEN"));
    }
}
