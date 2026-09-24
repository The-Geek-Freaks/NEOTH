//! Strict, read-only OpenClaw configuration inspection.
//!
//! This module deliberately produces a migration *plan*, not target config.
//! Every effective configuration leaf (after OpenClaw include/merge semantics)
//! is accounted for without serialising its value. Unknown, unsupported,
//! transport-specific and runtime-specific fields remain explicit blockers so
//! a future apply path cannot silently weaken an OpenClaw setup.

pub mod pinned_inventory;
pub mod pinned_schema;

use anyhow::{Context as _, Result};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const MAX_INCLUDE_DEPTH: usize = 10;
const MAX_INCLUDE_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_FILES: usize = 128;
pub const INSPECT_CONTRACT_VERSION: &str = "neoth-openclaw-inspect-v1";
pub const AUDITED_OPENCLAW_SCHEMA_COMMIT: &str = "4c667aac8859114bd8f0a589ac6cd1de8bfe1474";

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_account_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_value_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_binding: Option<SchemaLedgerBinding>,
}

/// Additive redacted W169 provenance for one ledger row. It identifies the
/// frozen schema row and declared custody action, never the source value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SchemaLedgerBinding {
    pub schema_id: String,
    pub path_template: String,
    pub scope: String,
    pub action_id: String,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SourceSetBinding {
    pub contract_version: &'static str,
    pub audited_openclaw_schema_commit: &'static str,
    pub known_channel_inventory_sha256: String,
    pub source_set_sha256: String,
    pub source_files: Vec<SourceFileBinding>,
}

pub struct OpenClawSecret(Zeroizing<String>);

impl OpenClawSecret {
    pub fn with_exposed<R>(self, consume: impl FnOnce(&str) -> R) -> R {
        consume(&self.0)
    }
}

pub struct SelectedTelegramAccount {
    source_account_label: String,
    source_token_path: String,
    source_set: SourceSetBinding,
    token: OpenClawSecret,
}

/// One explicitly selected OpenClaw Slack account whose two direct tokens may
/// cross into the authenticated NEOTH Slack-account candidate path. This
/// opaque value never serializes the source tokens or exposes the merged
/// OpenClaw document.
pub struct SelectedSlackAccount {
    source_account_label: String,
    source_set: SourceSetBinding,
    bot_token: OpenClawSecret,
    app_token: OpenClawSecret,
}

impl SelectedSlackAccount {
    pub fn source_account_label(&self) -> &str {
        &self.source_account_label
    }

    pub fn source_set(&self) -> &SourceSetBinding {
        &self.source_set
    }

    pub fn into_tokens(self) -> (OpenClawSecret, OpenClawSecret) {
        (self.bot_token, self.app_token)
    }
}

impl SelectedTelegramAccount {
    pub fn source_account_label(&self) -> &str {
        &self.source_account_label
    }

    pub fn source_token_path(&self) -> &str {
        &self.source_token_path
    }

    pub fn source_set(&self) -> &SourceSetBinding {
        &self.source_set
    }

    pub fn into_token(self) -> OpenClawSecret {
        self.token
    }
}

/// Opaque parsed source document. The merged OpenClaw value remains private;
/// report inspection is intentionally available only through the redacted
/// report API below.
pub struct LoadedOpenClawDocument {
    merged: Value,
    source_set: SourceSetBinding,
}

impl LoadedOpenClawDocument {
    pub fn source_set(&self) -> &SourceSetBinding {
        &self.source_set
    }

    pub fn select_telegram_account(
        &self,
        source_account_label: &str,
    ) -> Result<SelectedTelegramAccount> {
        select_from_merged(&self.merged, source_account_label, self.source_set.clone())
    }

    pub fn select_slack_account(
        &self,
        source_account_label: &str,
    ) -> Result<SelectedSlackAccount> {
        select_slack_from_merged(&self.merged, source_account_label, self.source_set.clone())
    }
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
    pinned_inventory::validate_pinned_channel_inventory()?;
    pinned_schema::validate_pinned_schema()?;
    let loaded = load_config(path)?;
    let mut ledger = Vec::new();
    walk_leaves(&loaded.value, &mut Vec::new(), &mut ledger)?;
    ledger.sort_by(|left, right| left.source_path.cmp(&right.source_path));

    let mut summary = ImportSummary::default();
    for entry in &ledger {
        summary.record(entry.disposition);
    }
    let apply_blocked = summary.hard_blockers > 0;
    let activation_blocked = summary.activation_blockers > 0;
    let known_channel_inventory_sha256 = canonical_known_channel_inventory_sha256();
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

pub fn load_openclaw_document(
    config: &Path,
    inventory_sha256: &str,
) -> Result<LoadedOpenClawDocument> {
    pinned_inventory::validate_pinned_channel_inventory()?;
    anyhow::ensure!(
        inventory_sha256 == canonical_known_channel_inventory_sha256(),
        "OpenClaw known-channel inventory binding does not match the audited custody contract"
    );
    let loaded = load_config(config)?;
    let source_set = source_set_binding(&loaded.source_files, inventory_sha256);
    Ok(LoadedOpenClawDocument {
        merged: loaded.value,
        source_set,
    })
}

pub fn inspect_source_set(config: &Path, inventory_sha256: &str) -> Result<SourceSetBinding> {
    Ok(load_openclaw_document(config, inventory_sha256)?
        .source_set
        .clone())
}

pub fn select_telegram_account(
    config: &Path,
    source_account_label: &str,
    inventory_sha256: &str,
) -> Result<SelectedTelegramAccount> {
    load_openclaw_document(config, inventory_sha256)?.select_telegram_account(source_account_label)
}

/// Select one exact OpenClaw Slack account for the account-scoped migration
/// path. Only the two direct account tokens are admitted; broad/default Slack
/// state, references and extra settings need an explicit separate adoption.
pub fn select_slack_account(
    config: &Path,
    source_account_label: &str,
    inventory_sha256: &str,
) -> Result<SelectedSlackAccount> {
    load_openclaw_document(config, inventory_sha256)?.select_slack_account(source_account_label)
}

fn select_from_merged(
    merged: &Value,
    source_account_label: &str,
    source_set: SourceSetBinding,
) -> Result<SelectedTelegramAccount> {
    anyhow::ensure!(
        !source_account_label.trim().is_empty(),
        "OpenClaw Telegram source account label is empty"
    );
    let channels = merged
        .get("channels")
        .and_then(Value::as_object)
        .context("OpenClaw channels must be an object")?;
    let telegram = channels
        .get("telegram")
        .and_then(Value::as_object)
        .context("OpenClaw channels.telegram must be an object")?;
    for forbidden in ["botToken", "tokenFile", "defaultAccount"] {
        anyhow::ensure!(
            !telegram.contains_key(forbidden),
            "OpenClaw channels.telegram.{forbidden} is unsupported for account selection"
        );
    }
    let accounts = telegram
        .get("accounts")
        .and_then(Value::as_object)
        .context("OpenClaw channels.telegram.accounts must be an object")?;
    let selected = accounts
        .get(source_account_label)
        .and_then(Value::as_object)
        .with_context(|| {
            format!("OpenClaw channels.telegram.accounts.{source_account_label} must be an object")
        })?;
    anyhow::ensure!(
        selected.len() == 1 && selected.contains_key("botToken"),
        "selected OpenClaw Telegram account must contain only botToken"
    );
    let token = selected
        .get("botToken")
        .and_then(Value::as_str)
        .context("selected OpenClaw Telegram botToken must be a string")?;
    anyhow::ensure!(
        !token.trim().is_empty(),
        "selected OpenClaw Telegram botToken is blank"
    );
    Ok(SelectedTelegramAccount {
        source_account_label: source_account_label.to_owned(),
        source_token_path: format!("channels.telegram.accounts.{source_account_label}.botToken"),
        source_set,
        token: OpenClawSecret(Zeroizing::new(token.to_owned())),
    })
}

fn select_slack_from_merged(
    merged: &Value,
    source_account_label: &str,
    source_set: SourceSetBinding,
) -> Result<SelectedSlackAccount> {
    anyhow::ensure!(
        !source_account_label.trim().is_empty(),
        "OpenClaw Slack source account label is empty"
    );
    let channels = merged
        .get("channels")
        .and_then(Value::as_object)
        .context("OpenClaw channels must be an object")?;
    let slack = channels
        .get("slack")
        .and_then(Value::as_object)
        .context("OpenClaw channels.slack must be an object")?;
    anyhow::ensure!(
        slack.len() == 1 && slack.contains_key("accounts"),
        "OpenClaw channels.slack must contain only accounts for account selection"
    );
    let accounts = slack
        .get("accounts")
        .and_then(Value::as_object)
        .context("OpenClaw channels.slack.accounts must be an object")?;
    let selected = accounts
        .get(source_account_label)
        .and_then(Value::as_object)
        .with_context(|| {
            format!("OpenClaw channels.slack.accounts.{source_account_label} must be an object")
        })?;
    anyhow::ensure!(
        selected.len() == 2 && selected.contains_key("botToken") && selected.contains_key("appToken"),
        "selected OpenClaw Slack account must contain only botToken and appToken"
    );
    let bot_token = selected
        .get("botToken")
        .and_then(Value::as_str)
        .context("selected OpenClaw Slack botToken must be a direct string")?;
    let app_token = selected
        .get("appToken")
        .and_then(Value::as_str)
        .context("selected OpenClaw Slack appToken must be a direct string")?;
    anyhow::ensure!(
        !bot_token.trim().is_empty(),
        "selected OpenClaw Slack botToken is blank"
    );
    anyhow::ensure!(
        !app_token.trim().is_empty(),
        "selected OpenClaw Slack appToken is blank"
    );
    Ok(SelectedSlackAccount {
        source_account_label: source_account_label.to_owned(),
        source_set,
        bot_token: OpenClawSecret(Zeroizing::new(bot_token.to_owned())),
        app_token: OpenClawSecret(Zeroizing::new(app_token.to_owned())),
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

fn source_set_binding(
    source_files: &[SourceFileBinding],
    known_channel_inventory_sha256: &str,
) -> SourceSetBinding {
    SourceSetBinding {
        contract_version: INSPECT_CONTRACT_VERSION,
        audited_openclaw_schema_commit: AUDITED_OPENCLAW_SCHEMA_COMMIT,
        known_channel_inventory_sha256: known_channel_inventory_sha256.to_owned(),
        source_set_sha256: source_set_sha256(source_files, known_channel_inventory_sha256),
        source_files: source_files.to_vec(),
    }
}

pub fn canonical_known_channel_inventory_sha256() -> String {
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

fn walk_leaves(
    value: &Value,
    path: &mut Vec<PathPart>,
    ledger: &mut Vec<FieldLedgerEntry>,
) -> Result<()> {
    match secret_ref_state(value) {
        SecretRefState::Valid => {
            ledger.push(classify_leaf(value, path, true, false)?);
            return Ok(());
        }
        SecretRefState::InvalidCandidate => {
            ledger.push(classify_leaf(value, path, false, true)?);
            return Ok(());
        }
        SecretRefState::NotSecretRef => {}
    }
    let opaque_subtree = schema_lookup(path, value)?
        .is_some_and(|schema| schema.scope == pinned_schema::SchemaScope::OpaqueSubtree);
    if opaque_subtree
        && (!(value.is_object() || value.is_array()) || !schema_has_typed_descendant(path)?)
    {
        ledger.push(classify_leaf(value, path, false, false)?);
        return Ok(());
    }
    if is_account_container(path, value) {
        ledger.push(classify_account_container(path)?);
        if value.as_object().is_some_and(|object| object.is_empty()) {
            return Ok(());
        }
    }
    match value {
        Value::Object(object) if !object.is_empty() => {
            for (key, value) in object {
                path.push(PathPart::Key(key.clone()));
                walk_leaves(value, path, ledger)?;
                path.pop();
            }
        }
        Value::Array(values) if !values.is_empty() => {
            for (index, value) in values.iter().enumerate() {
                path.push(PathPart::Index(index));
                walk_leaves(value, path, ledger)?;
                path.pop();
            }
        }
        Value::Object(object) if object.is_empty() && path.is_empty() => {}
        Value::Array(values) if values.is_empty() && path.is_empty() => {}
        _ => ledger.push(classify_leaf(value, path, false, false)?),
    }
    Ok(())
}

fn classify_leaf(
    value: &Value,
    path: &[PathPart],
    secret_ref: bool,
    invalid_secret_ref: bool,
) -> Result<FieldLedgerEntry> {
    let source_path = display_path(path);
    let sensitive = secret_ref || invalid_secret_ref || path_is_sensitive(path);
    let account_label = source_account_label(path);
    let root = key_at(path, 0);
    if root != Some("channels") {
        let known = root.is_some_and(|root| KNOWN_ROOT_KEYS.contains(&root));
        return Ok(FieldLedgerEntry {
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
            source_account_label: None,
            effective_value_sha256: None,
            schema_binding: None,
        });
    }

    let Some(channel) = key_at(path, 1) else {
        return Ok(FieldLedgerEntry {
            source_path,
            source_channel: None,
            target_channel: None,
            target_path: None,
            disposition: ImportDisposition::Mapped,
            sensitive,
            reason: "empty channel configuration".to_string(),
            source_account_label: None,
            effective_value_sha256: None,
            schema_binding: None,
        });
    };
    if matches!(channel, "defaults" | "modelByChannel") {
        return Ok(FieldLedgerEntry {
            source_path,
            source_channel: Some(channel.to_string()),
            target_channel: None,
            target_path: None,
            disposition: ImportDisposition::Unsupported,
            sensitive,
            reason: format!("OpenClaw channels.{channel} has no NEOTH import target yet"),
            source_account_label: None,
            effective_value_sha256: None,
            schema_binding: None,
        });
    }

    let target_channel = alias_target(channel);
    if !KNOWN_CHANNEL_KEYS.contains(&channel) {
        return Ok(FieldLedgerEntry {
            source_path,
            source_channel: Some(channel.to_string()),
            target_channel: None,
            target_path: None,
            disposition: ImportDisposition::Unknown,
            sensitive,
            reason: "unknown or third-party OpenClaw channel; explicit adoption is required"
                .to_string(),
            source_account_label: None,
            effective_value_sha256: None,
            schema_binding: None,
        });
    }

    if invalid_secret_ref {
        return Ok(FieldLedgerEntry {
            source_path,
            source_channel: Some(channel.to_string()),
            target_channel: target_channel.map(str::to_string),
            target_path: None,
            disposition: ImportDisposition::Unknown,
            sensitive: true,
            reason:
                "invalid OpenClaw SecretRef shape; explicit schema-compatible reference is required"
                    .to_string(),
            source_account_label: account_label,
            effective_value_sha256: None,
            schema_binding: None,
        });
    }

    let direct_field = direct_channel_field(path);
    if channel == "whatsapp" && direct_field == Some("authDir") && value.is_string() {
        let (disposition, target_path, reason) =
            classify_known_field(channel, "authDir", sensitive);
        return Ok(FieldLedgerEntry {
            source_path,
            source_channel: Some(channel.to_string()),
            target_channel: target_channel.map(str::to_string),
            target_path: target_path.map(str::to_string),
            disposition,
            sensitive,
            reason: reason.to_string(),
            source_account_label: None,
            effective_value_sha256: None,
            schema_binding: None,
        });
    }

    let schema = schema_lookup(path, value)?;
    let Some(schema) = schema else {
        return Ok(FieldLedgerEntry {
            source_path,
            source_channel: Some(channel.to_string()),
            target_channel: target_channel.map(str::to_string),
            target_path: None,
            disposition: ImportDisposition::Unknown,
            sensitive,
            reason: format!("unknown OpenClaw {channel} field or incompatible schema type"),
            source_account_label: account_label,
            effective_value_sha256: None,
            schema_binding: None,
        });
    };
    if schema.scope == pinned_schema::SchemaScope::OpaqueSubtree {
        return Ok(FieldLedgerEntry {
            source_path,
            source_channel: Some(channel.to_string()),
            target_channel: target_channel.map(str::to_string),
            target_path: None,
            disposition: ImportDisposition::Unknown,
            sensitive,
            reason:
                "pinned OpenClaw schema has an opaque subtree; explicit leaf mapping is required"
                    .to_string(),
            source_account_label: account_label,
            effective_value_sha256: None,
            schema_binding: Some(schema_binding(
                schema,
                "blocked_requires_explicit_leaf_mapping",
            )),
        });
    }
    let Some(target_channel) = target_channel else {
        return Ok(FieldLedgerEntry {
            source_path,
            source_channel: Some(channel.to_string()),
            target_channel: None,
            target_path: None,
            disposition: ImportDisposition::Unsupported,
            sensitive,
            reason: "known OpenClaw channel has no NEOTH adapter".to_string(),
            source_account_label: account_label,
            effective_value_sha256: value_binding(value, path, sensitive),
            schema_binding: Some(schema_binding(schema, "requires_neoth_adapter")),
        });
    };
    if account_label.is_some() {
        return Ok(FieldLedgerEntry {
            source_path,
            source_channel: Some(channel.to_string()),
            target_channel: Some(target_channel.to_string()),
            target_path: None,
            disposition: ImportDisposition::Unsupported,
            sensitive,
            reason: "OpenClaw account-scoped config has no NEOTH account-scoped runtime target"
                .to_string(),
            source_account_label: account_label,
            effective_value_sha256: value_binding(value, path, sensitive),
            schema_binding: Some(schema_binding(schema, "requires_account_scoped_runtime")),
        });
    }

    let (disposition, target_path, reason) = match direct_field {
        Some(field) => classify_known_field(channel, field, sensitive),
        None => (
            ImportDisposition::Unsupported,
            None,
            "recognized pinned OpenClaw schema leaf has no direct NEOTH target yet",
        ),
    };
    let action_id = action_id(disposition, target_path, direct_field);
    Ok(FieldLedgerEntry {
        source_path,
        source_channel: Some(channel.to_string()),
        target_channel: Some(target_channel.to_string()),
        target_path: target_path.map(str::to_string),
        disposition,
        sensitive,
        reason: reason.to_string(),
        source_account_label: None,
        effective_value_sha256: value_binding(value, path, sensitive),
        schema_binding: Some(schema_binding(schema, action_id)),
    })
}

fn classify_account_container(path: &[PathPart]) -> Result<FieldLedgerEntry> {
    let source_path = display_path(path);
    let channel = key_at(path, 1).context("account container missing channel")?;
    let account_label =
        source_account_label(path).context("account container missing account label")?;
    let target_channel = alias_target(channel);
    let schema = pinned_schema::account_container(channel)?;
    let (disposition, reason, action_id) = if schema.is_some() && target_channel.is_some() {
        (
            ImportDisposition::Unsupported,
            "configured OpenClaw account has no NEOTH account-scoped runtime target",
            "requires_account_scoped_runtime",
        )
    } else {
        (
            ImportDisposition::Unknown,
            "configured OpenClaw account is not represented by the pinned channel schema",
            "blocked_requires_explicit_account_mapping",
        )
    };
    Ok(FieldLedgerEntry {
        source_path,
        source_channel: Some(channel.to_string()),
        target_channel: target_channel.map(str::to_string),
        target_path: None,
        disposition,
        sensitive: false,
        reason: reason.to_string(),
        source_account_label: Some(account_label),
        effective_value_sha256: None,
        schema_binding: schema.map(|schema| schema_binding(schema, action_id)),
    })
}

fn schema_lookup(path: &[PathPart], value: &Value) -> Result<Option<pinned_schema::SchemaMatch>> {
    if key_at(path, 0) != Some("channels") {
        return Ok(None);
    }
    let Some(channel) = key_at(path, 1) else {
        return Ok(None);
    };
    let parts: Vec<_> = path[2..]
        .iter()
        .map(|part| match part {
            PathPart::Key(key) => pinned_schema::PathPart::Key(key),
            PathPart::Index(_) => pinned_schema::PathPart::Index,
        })
        .collect();
    pinned_schema::lookup(channel, &parts, observed_json_type(value))
}

fn schema_has_typed_descendant(path: &[PathPart]) -> Result<bool> {
    if key_at(path, 0) != Some("channels") {
        return Ok(false);
    }
    let Some(channel) = key_at(path, 1) else {
        return Ok(false);
    };
    let parts: Vec<_> = path[2..]
        .iter()
        .map(|part| match part {
            PathPart::Key(key) => pinned_schema::PathPart::Key(key),
            PathPart::Index(_) => pinned_schema::PathPart::Index,
        })
        .collect();
    pinned_schema::has_typed_descendant(channel, &parts)
}

fn observed_json_type(value: &Value) -> &'static str {
    if is_secret_ref(value) {
        "secret_ref"
    } else if value.is_string() {
        "string"
    } else if value.is_boolean() {
        "boolean"
    } else if value.is_i64() || value.is_u64() {
        "integer"
    } else if value.is_number() {
        "number"
    } else if value.is_null() {
        "null"
    } else if value.is_array() {
        "array"
    } else {
        "object"
    }
}

fn is_account_container(path: &[PathPart], value: &Value) -> bool {
    value.is_object()
        && key_at(path, 0) == Some("channels")
        && key_at(path, 2) == Some("accounts")
        && key_at(path, 3).is_some()
        && path.len() == 4
}

fn source_account_label(path: &[PathPart]) -> Option<String> {
    (key_at(path, 0) == Some("channels") && key_at(path, 2) == Some("accounts"))
        .then(|| key_at(path, 3).map(str::to_string))
        .flatten()
}

fn direct_channel_field(path: &[PathPart]) -> Option<&str> {
    (path.len() == 3).then(|| key_at(path, 2)).flatten()
}

fn schema_binding(schema: pinned_schema::SchemaMatch, action_id: &str) -> SchemaLedgerBinding {
    SchemaLedgerBinding {
        schema_id: schema.schema_id,
        path_template: schema.path_template,
        scope: match schema.scope {
            pinned_schema::SchemaScope::TypedLeaf => "typed_leaf",
            pinned_schema::SchemaScope::OpaqueSubtree => "opaque_subtree",
            pinned_schema::SchemaScope::AccountContainer => "account_container",
        }
        .to_string(),
        action_id: action_id.to_string(),
    }
}

fn value_binding(value: &Value, path: &[PathPart], sensitive: bool) -> Option<String> {
    if sensitive
        || source_account_label(path).is_some()
        || !(value.is_boolean() || value.is_number())
    {
        return None;
    }
    let canonical = serde_json::to_vec(value).ok()?;
    let mut digest = Sha256::new();
    digest.update(b"neoth-w169-effective-value-v1\0");
    digest.update(display_path(path).as_bytes());
    digest.update(b"\0");
    digest.update(pinned_schema::FIXTURE_SHA256.as_bytes());
    digest.update(b"\0");
    digest.update(canonical);
    Some(format!("{:x}", digest.finalize()))
}

fn action_id(
    disposition: ImportDisposition,
    target_path: Option<&str>,
    direct_field: Option<&str>,
) -> &'static str {
    match (disposition, target_path, direct_field) {
        (ImportDisposition::Mapped, Some(_), _) => "direct_credential_mapping",
        (ImportDisposition::NeedsSecret, Some(_), _) => "neoth_credential_flow",
        (ImportDisposition::NeedsRelink, _, _) => "relink_required",
        (ImportDisposition::NeedsRuntime, _, _) => "runtime_prerequisite_required",
        (ImportDisposition::Unsupported, _, Some(_)) => "requires_target_contract",
        (ImportDisposition::Unsupported, _, None) => "requires_target_contract",
        (ImportDisposition::Unknown, _, _) => "blocked_requires_explicit_leaf_mapping",
        (ImportDisposition::Mapped, None, _) => "mapped",
        (ImportDisposition::NeedsSecret, None, _) => "neoth_credential_flow",
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
        "recognized pinned OpenClaw schema field has no direct NEOTH target yet",
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SecretRefState {
    NotSecretRef,
    Valid,
    InvalidCandidate,
}

fn secret_ref_state(value: &Value) -> SecretRefState {
    let Value::Object(object) = value else {
        return SecretRefState::NotSecretRef;
    };
    let source = object.get("source").and_then(Value::as_str);
    let id = object.get("id").and_then(Value::as_str);
    if !matches!(source, Some("env" | "file" | "exec")) || id.is_none() {
        return SecretRefState::NotSecretRef;
    }
    let allowed = ["source", "provider", "id"];
    if object.len() == allowed.len()
        && allowed.iter().all(|key| object.contains_key(*key))
        && object.get("provider").and_then(Value::as_str).is_some()
    {
        SecretRefState::Valid
    } else {
        SecretRefState::InvalidCandidate
    }
}

fn is_secret_ref(value: &Value) -> bool {
    secret_ref_state(value) == SecretRefState::Valid
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
        assert!(auth.sensitive);
        assert!(auth.effective_value_sha256.is_none());
        assert!(auth.schema_binding.is_none());
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("whatsapp_business")
        );
    }

    #[test]
    fn whatsapp_auth_dir_requires_the_legacy_string_shape() {
        let temp = tempdir().unwrap();
        let path = write_config(temp.path(), "{ channels: { whatsapp: { authDir: 42 } } }");
        let report = inspect_openclaw_config(&path).unwrap();
        let auth = report
            .ledger
            .iter()
            .find(|entry| entry.source_path == "channels.whatsapp.authDir")
            .unwrap();
        assert_eq!(auth.target_channel.as_deref(), Some("whatsapp_baileys"));
        assert_eq!(auth.disposition, ImportDisposition::Unknown);
        assert!(auth.sensitive);
        assert!(auth.effective_value_sha256.is_none());
        assert!(auth.schema_binding.is_none());
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

    #[test]
    fn report_keeps_canonical_primary_and_include_paths_from_relative_invocation() {
        static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _cwd_guard = CWD_LOCK.lock().unwrap();
        let temp = tempdir().unwrap();
        let include_dir = temp.path().join("nested");
        std::fs::create_dir_all(&include_dir).unwrap();
        let included = include_dir.join("telegram.json5");
        std::fs::write(&included, "{ telegram: { enabled: true } }").unwrap();
        let config = write_config(
            temp.path(),
            "{ channels: { $include: './nested/telegram.json5' } }",
        );
        let original_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(temp.path()).unwrap();
        let report = inspect_openclaw_config(Path::new("./openclaw.json")).unwrap();
        std::env::set_current_dir(original_cwd).unwrap();

        assert_eq!(
            report.source,
            std::fs::canonicalize(&config)
                .unwrap()
                .display()
                .to_string()
        );
        assert_eq!(
            report.included_files,
            vec![
                std::fs::canonicalize(included)
                    .unwrap()
                    .display()
                    .to_string()
            ]
        );
    }

    #[test]
    fn selected_telegram_account_is_exact_and_never_serializes_its_token() {
        let temp = tempdir().unwrap();
        let secret = "selected-token-must-not-render";
        let path = write_config(
            temp.path(),
            &format!(
                "{{ channels: {{ telegram: {{ accounts: {{ work: {{ botToken: '{secret}' }}, other: {{ botToken: 'other-token' }} }} }} }} }}"
            ),
        );
        let selected =
            select_telegram_account(&path, "work", &canonical_known_channel_inventory_sha256())
                .unwrap();
        assert_eq!(selected.source_account_label(), "work");
        assert_eq!(
            selected.source_token_path(),
            "channels.telegram.accounts.work.botToken"
        );
        assert!(!format!("{:?}", selected.source_set()).contains(secret));
        assert_eq!(selected.into_token().with_exposed(str::to_owned), secret);
    }

    #[test]
    fn selected_slack_account_is_exact_and_never_serializes_its_tokens() {
        let temp = tempdir().unwrap();
        let bot_token = "selected-slack-bot-token-must-not-render";
        let app_token = "selected-slack-app-token-must-not-render";
        let path = write_config(
            temp.path(),
            &format!(
                "{{ channels: {{ slack: {{ accounts: {{ work: {{ botToken: '{bot_token}', appToken: '{app_token}' }}, other: {{ botToken: 'other-bot-token', appToken: 'other-app-token' }} }} }} }} }}"
            ),
        );

        let selected =
            select_slack_account(&path, "work", &canonical_known_channel_inventory_sha256())
                .unwrap();
        assert_eq!(selected.source_account_label(), "work");
        let source_set = format!("{:?}", selected.source_set());
        assert!(!source_set.contains(bot_token));
        assert!(!source_set.contains(app_token));
        let (selected_bot_token, selected_app_token) = selected.into_tokens();
        assert_eq!(selected_bot_token.with_exposed(str::to_owned), bot_token);
        assert_eq!(selected_app_token.with_exposed(str::to_owned), app_token);
    }

    #[test]
    fn selected_slack_account_rejects_broad_or_ambiguous_shapes_without_tokens_in_error() {
        let bot_token = "slack-selection-bot-token-must-not-render";
        let app_token = "slack-selection-app-token-must-not-render";
        let cases = [
            (
                "outer token",
                format!(
                    "{{ channels: {{ slack: {{ botToken: '{bot_token}', accounts: {{ work: {{ botToken: '{bot_token}', appToken: '{app_token}' }} }} }} }} }}"
                ),
                "work",
            ),
            (
                "default account",
                format!(
                    "{{ channels: {{ slack: {{ defaultAccount: 'work', accounts: {{ work: {{ botToken: '{bot_token}', appToken: '{app_token}' }} }} }} }} }}"
                ),
                "work",
            ),
            (
                "allow-from policy",
                format!(
                    "{{ channels: {{ slack: {{ allowFrom: ['U123'], accounts: {{ work: {{ botToken: '{bot_token}', appToken: '{app_token}' }} }} }} }} }}"
                ),
                "work",
            ),
            (
                "group policy",
                format!(
                    "{{ channels: {{ slack: {{ groupPolicy: 'open', accounts: {{ work: {{ botToken: '{bot_token}', appToken: '{app_token}' }} }} }} }} }}"
                ),
                "work",
            ),
            (
                "mode policy",
                format!(
                    "{{ channels: {{ slack: {{ mode: 'socket', accounts: {{ work: {{ botToken: '{bot_token}', appToken: '{app_token}' }} }} }} }} }}"
                ),
                "work",
            ),
            (
                "unknown sibling",
                format!(
                    "{{ channels: {{ slack: {{ unknownSettings: {{ inherit: true }}, accounts: {{ work: {{ botToken: '{bot_token}', appToken: '{app_token}' }} }} }} }} }}"
                ),
                "work",
            ),
            (
                "extra field",
                format!(
                    "{{ channels: {{ slack: {{ accounts: {{ work: {{ botToken: '{bot_token}', appToken: '{app_token}', enabled: true }} }} }} }} }}"
                ),
                "work",
            ),
            (
                "missing app token",
                format!(
                    "{{ channels: {{ slack: {{ accounts: {{ work: {{ botToken: '{bot_token}' }} }} }} }} }}"
                ),
                "work",
            ),
            (
                "secret reference",
                format!(
                    "{{ channels: {{ slack: {{ accounts: {{ work: {{ botToken: {{ source: 'env', provider: 'default', id: 'SLACK_BOT_TOKEN' }}, appToken: '{app_token}' }} }} }} }} }}"
                ),
                "work",
            ),
            (
                "unknown account",
                format!(
                    "{{ channels: {{ slack: {{ accounts: {{ work: {{ botToken: '{bot_token}', appToken: '{app_token}' }} }} }} }} }}"
                ),
                "missing",
            ),
        ];

        for (case, body, source_account_label) in cases {
            let temp = tempdir().unwrap();
            let path = write_config(temp.path(), &body);
            let error = match select_slack_account(
                &path,
                source_account_label,
                &canonical_known_channel_inventory_sha256(),
            ) {
                Ok(_) => panic!("{case} must fail"),
                Err(error) => error,
            };
            let rendered = format!("{error:#}");
            assert!(!rendered.contains(bot_token), "{case}: bot token leaked");
            assert!(!rendered.contains(app_token), "{case}: app token leaked");
        }
    }

    #[test]
    fn selected_slack_account_keeps_the_exact_loaded_source_set() {
        let temp = tempdir().unwrap();
        let included = temp.path().join("slack.json5");
        std::fs::write(
            &included,
            "{ slack: { accounts: { work: { botToken: 'original-bot-token', appToken: 'original-app-token' } } } }",
        )
        .unwrap();
        let path = write_config(
            temp.path(),
            "{ channels: { $include: './slack.json5' } }",
        );

        let loaded =
            load_openclaw_document(&path, &canonical_known_channel_inventory_sha256()).unwrap();
        let expected_source_set_sha256 = loaded.source_set().source_set_sha256.clone();
        let selected = loaded.select_slack_account("work").unwrap();
        assert_eq!(
            selected.source_set().source_set_sha256,
            expected_source_set_sha256
        );

        std::fs::write(
            &included,
            "{ slack: { accounts: { work: { botToken: 'changed-bot-token', appToken: 'changed-app-token' } } } }",
        )
        .unwrap();
        let current = inspect_openclaw_config(&path).unwrap();
        assert_ne!(
            selected.source_set().source_set_sha256,
            current.source_set_sha256
        );
    }

    #[test]
    fn selected_account_rejects_direct_or_extra_shapes_without_token_in_error() {
        let temp = tempdir().unwrap();
        let secret = "selection-error-token-must-not-render";
        let path = write_config(
            temp.path(),
            &format!(
                "{{ channels: {{ telegram: {{ botToken: '{secret}', accounts: {{ work: {{ botToken: '{secret}', tokenFile: '/tmp/x' }} }} }} }} }}"
            ),
        );
        let error = match select_telegram_account(
            &path,
            "work",
            &canonical_known_channel_inventory_sha256(),
        ) {
            Ok(_) => panic!("unsupported selected shape must fail"),
            Err(error) => error,
        };
        assert!(!format!("{error:#}").contains(secret));
    }

    #[test]
    fn w169_ledgers_separate_account_containers_and_redacts_account_secrets() {
        let temp = tempdir().unwrap();
        let path = write_config(
            temp.path(),
            "{ channels: { telegram: { accounts: { work: { botToken: 'work-secret' }, personal: { botToken: 'personal-secret' } } } } }",
        );
        let report = inspect_openclaw_config(&path).unwrap();
        for label in ["work", "personal"] {
            let container = report
                .ledger
                .iter()
                .find(|entry| entry.source_path == format!("channels.telegram.accounts.{label}"))
                .unwrap();
            assert_eq!(container.source_account_label.as_deref(), Some(label));
            assert_eq!(container.disposition, ImportDisposition::Unsupported);
            assert_eq!(
                container
                    .schema_binding
                    .as_ref()
                    .map(|binding| binding.scope.as_str()),
                Some("account_container")
            );
            assert_eq!(
                container
                    .schema_binding
                    .as_ref()
                    .map(|binding| binding.action_id.as_str()),
                Some("requires_account_scoped_runtime")
            );
            let token = report
                .ledger
                .iter()
                .find(|entry| {
                    entry.source_path == format!("channels.telegram.accounts.{label}.botToken")
                })
                .unwrap();
            assert!(token.sensitive);
            assert!(token.effective_value_sha256.is_none());
            assert_eq!(token.source_account_label.as_deref(), Some(label));
        }
        let rendered = serde_json::to_string(&report).unwrap();
        assert!(!rendered.contains("work-secret"));
        assert!(!rendered.contains("personal-secret"));
    }

    #[test]
    fn w169_opaque_subtree_blocks_at_its_exact_account_path() {
        let temp = tempdir().unwrap();
        let path = write_config(
            temp.path(),
            "{ channels: { matrix: { accounts: { work: { arbitraryFutureOption: true } } } } }",
        );
        let report = inspect_openclaw_config(&path).unwrap();
        let entry = report
            .ledger
            .iter()
            .find(|entry| entry.source_path == "channels.matrix.accounts.work")
            .unwrap();
        assert_eq!(entry.disposition, ImportDisposition::Unknown);
        assert_eq!(entry.source_account_label.as_deref(), Some("work"));
        assert!(entry.effective_value_sha256.is_none());
        assert_eq!(
            entry
                .schema_binding
                .as_ref()
                .map(|binding| binding.scope.as_str()),
            Some("opaque_subtree")
        );
    }

    #[test]
    fn w169_walks_typed_descendants_under_opaque_map_prefixes() {
        let temp = tempdir().unwrap();
        let path = write_config(
            temp.path(),
            "{ channels: { qqbot: { accounts: { work: { audioFormatPolicy: { transcodeEnabled: true }, arbitraryFutureOption: true } } } } }",
        );
        let report = inspect_openclaw_config(&path).unwrap();
        let typed = report
            .ledger
            .iter()
            .find(|entry| {
                entry.source_path
                    == "channels.qqbot.accounts.work.audioFormatPolicy.transcodeEnabled"
            })
            .unwrap();
        assert_eq!(
            typed
                .schema_binding
                .as_ref()
                .map(|binding| binding.scope.as_str()),
            Some("typed_leaf")
        );

        let opaque = report
            .ledger
            .iter()
            .find(|entry| entry.source_path == "channels.qqbot.accounts.work.arbitraryFutureOption")
            .unwrap();
        assert_eq!(opaque.disposition, ImportDisposition::Unknown);
        assert_eq!(
            opaque
                .schema_binding
                .as_ref()
                .map(|binding| binding.scope.as_str()),
            Some("opaque_subtree")
        );
    }

    #[test]
    fn w169_typed_nonsecret_leaf_has_schema_binding_and_value_binding() {
        let temp = tempdir().unwrap();
        let path = write_config(temp.path(), "{ channels: { telegram: { enabled: true } } }");
        let report = inspect_openclaw_config(&path).unwrap();
        let entry = report
            .ledger
            .iter()
            .find(|entry| entry.source_path == "channels.telegram.enabled")
            .unwrap();
        assert!(!entry.sensitive);
        assert!(entry.effective_value_sha256.is_some());
        assert_eq!(
            entry
                .schema_binding
                .as_ref()
                .map(|binding| binding.scope.as_str()),
            Some("typed_leaf")
        );
        assert_ne!(entry.disposition, ImportDisposition::Mapped);
    }

    #[test]
    fn w169_rejects_unbacked_or_malformed_secret_refs_without_serializing_ids() {
        let temp = tempdir().unwrap();
        let path = write_config(
            temp.path(),
            "{ channels: { telegram: { proxy: { source: 'env', provider: 'default', id: 'PROXY_SECRET' }, botToken: { source: 'env', provider: 'default', id: 'EXTRA_SECRET', unexpected: true } } } }",
        );
        let report = inspect_openclaw_config(&path).unwrap();
        for source_path in ["channels.telegram.proxy", "channels.telegram.botToken"] {
            let entry = report
                .ledger
                .iter()
                .find(|entry| entry.source_path == source_path)
                .unwrap();
            assert_eq!(entry.disposition, ImportDisposition::Unknown);
            assert!(entry.sensitive);
            assert!(entry.effective_value_sha256.is_none());
            assert!(entry.schema_binding.is_none());
        }
        let rendered = format!(
            "{}\n{}",
            serde_json::to_string(&report).unwrap(),
            render_human(&report)
        );
        assert!(!rendered.contains("PROXY_SECRET"));
        assert!(!rendered.contains("EXTRA_SECRET"));
    }

    #[test]
    fn w169_never_binds_credential_bearing_string_urls() {
        let temp = tempdir().unwrap();
        let credential_url = "http://operator:private-password@proxy.example.invalid";
        let path = write_config(
            temp.path(),
            &format!("{{ channels: {{ telegram: {{ proxy: '{credential_url}' }} }} }}"),
        );
        let report = inspect_openclaw_config(&path).unwrap();
        let entry = report
            .ledger
            .iter()
            .find(|entry| entry.source_path == "channels.telegram.proxy")
            .unwrap();
        assert!(entry.schema_binding.is_some());
        assert!(entry.effective_value_sha256.is_none());
        let rendered = format!(
            "{}\n{}",
            serde_json::to_string(&report).unwrap(),
            render_human(&report)
        );
        assert!(!rendered.contains(credential_url));
    }
}
