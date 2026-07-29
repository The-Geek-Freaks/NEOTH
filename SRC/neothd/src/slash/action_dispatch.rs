//! Slash-action dispatcher.
//!
//! Built-in actions are resolved before any provider call. Read paths return
//! their real data; mutation paths call the same typed helpers as the CLI and
//! persist through locked, atomic stores. Channel-originated mutations are
//! rejected before parsing secrets or touching disk.

use std::path::Path;

use anyhow::{Context, Result};

use super::schema::{CommandSource, SlashAction};
use crate::channels::registry::{ChannelId, channel_descriptors, resolve_channel_id};
use crate::cli::OutputFormat;
use crate::config::FreedomConfig;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionOutcome {
    Handled { text: String },
    Failed { text: String },
    InvalidArgs { text: String },
    Exit,
    ChannelPrivilegeBlocked { text: String },
}

impl ActionOutcome {
    pub fn text(&self) -> &str {
        match self {
            Self::Handled { text }
            | Self::Failed { text }
            | Self::InvalidArgs { text }
            | Self::ChannelPrivilegeBlocked { text } => text,
            Self::Exit => "Exiting NEOTH chat session.",
        }
    }

    pub fn should_exit(&self) -> bool {
        matches!(self, Self::Exit)
    }

    pub fn is_channel_blocked(&self) -> bool {
        matches!(self, Self::ChannelPrivilegeBlocked { .. })
    }

    pub fn is_failure(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }
}

/// Dispatch one action. Async is required because onboarding, credential
/// verification, audited consent/autonomy changes, and memory erasure all have
/// real async boundaries.
pub async fn dispatch_action(
    action: SlashAction,
    args: &str,
    config: &FreedomConfig,
    source: CommandSource,
) -> ActionOutcome {
    let home = FreedomConfig::default_neoth_home();
    let config_path = home.join("freedom.yaml");
    dispatch_action_with_paths(action, args, config, source, &home, &config_path).await
}

async fn dispatch_action_at(
    action: SlashAction,
    args: &str,
    config: &FreedomConfig,
    source: CommandSource,
    home: &Path,
) -> ActionOutcome {
    dispatch_action_with_paths(
        action,
        args,
        config,
        source,
        home,
        &home.join("freedom.yaml"),
    )
    .await
}

/// Instance-bound dispatcher used by custom-config chat and daemon surfaces.
/// `config` is the exact accepted generation and `config_path` is the only
/// file mutations may update.
pub(crate) async fn dispatch_action_with_paths(
    action: SlashAction,
    args: &str,
    config: &FreedomConfig,
    source: CommandSource,
    home: &Path,
    config_path: &Path,
) -> ActionOutcome {
    let trimmed = args.trim();
    if source.is_channel() && action.is_destructive_with_args(trimmed) {
        return ActionOutcome::ChannelPrivilegeBlocked {
            text: format!(
                "`/{}` changes operator state and cannot run from a channel. Run it in the local NEOTH CLI.",
                action.as_str()
            ),
        };
    }

    match action {
        SlashAction::RestartWizard => handle_wizard(home).await,
        SlashAction::ConfigGet | SlashAction::ConfigSet => handle_config(trimmed, config, home),
        SlashAction::ProviderSwitch => handle_provider_switch(trimmed, home).await,
        SlashAction::ConnectChannel => handle_connect(trimmed, home).await,
        SlashAction::DisconnectChannel => handle_disconnect(trimmed, home),
        SlashAction::SkillRegistry => handle_skill(trimmed, home, config, config_path).await,
        SlashAction::PluginRegistry => handle_plugin(trimmed, home),
        SlashAction::MemoryView => handle_memory(trimmed, home).await,
        SlashAction::ConsentManage => handle_consent(trimmed, config, home).await,
        SlashAction::ReloadConfig => handle_reload(home),
        SlashAction::AutonomyLevel => handle_autonomy(trimmed, config, home).await,
        SlashAction::Quit => ActionOutcome::Exit,
        SlashAction::BackgroundRun { btw } => handle_background_run(trimmed, btw),
    }
}

fn failed(action: &str, error: impl std::fmt::Display) -> ActionOutcome {
    ActionOutcome::Failed {
        text: crate::security::redact::redact_text(&format!("{action} failed: {error}")),
    }
}

fn request_reload_at(home: &Path) -> Result<()> {
    let sentinel = home.join(crate::config::reload::RELOAD_SENTINEL_NAME);
    crate::util::atomic_write::atomic_write(&sentinel, b"reload\n")
        .with_context(|| format!("write reload sentinel at {}", sentinel.display()))
}

fn handled_after_reload(home: &Path, text: String) -> ActionOutcome {
    match request_reload_at(home) {
        Ok(()) => ActionOutcome::Handled {
            text: format!("{text}\nLive-config reload requested."),
        },
        Err(error) => failed("state persisted, but live-config reload request", error),
    }
}

async fn handle_wizard(home: &Path) -> ActionOutcome {
    let args = crate::cli::init::InitArgs {
        cli: true,
        force: true,
        ..Default::default()
    };
    match crate::cli::init::run_init(args).await {
        Ok(()) => handled_after_reload(home, "Onboarding wizard completed.".into()),
        Err(error) => failed("/wizard", error),
    }
}

fn handle_config(args: &str, config: &FreedomConfig, home: &Path) -> ActionOutcome {
    if args.is_empty() {
        return match redacted_config_value(config) {
            Ok(value) => match serde_yaml::to_string(&value) {
                Ok(yaml) => ActionOutcome::Handled {
                    text: format!("Current freedom.yaml values:\n{}", yaml.trim()),
                },
                Err(error) => failed("/config", error),
            },
            Err(error) => failed("/config", error),
        };
    }

    let mut split = args.splitn(2, char::is_whitespace);
    let key = split.next().unwrap_or("").trim();
    let Some(raw_value) = split
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return match redacted_config_value(config).and_then(|value| {
            let field = yaml_value_at(&value, key)?;
            serde_yaml::to_string(field).context("render config field")
        }) {
            Ok(value) => ActionOutcome::Handled {
                text: format!("{key}: {}", value.trim()),
            },
            Err(error) => ActionOutcome::InvalidArgs {
                text: format!("/config: {error}"),
            },
        };
    };

    if secret_config_path(key) {
        return ActionOutcome::InvalidArgs {
            text: format!(
                "`{key}` is a secret field. Use `neoth credential` or the channel/provider credential flow; secrets are never accepted by `/config`."
            ),
        };
    }
    let replacement: serde_yaml::Value = match serde_yaml::from_str(raw_value) {
        Ok(value) => value,
        Err(error) => {
            return ActionOutcome::InvalidArgs {
                text: format!("/config {key}: invalid YAML value: {error}"),
            };
        }
    };
    let path = home.join("freedom.yaml");
    let result = FreedomConfig::update_at(&path, |current| {
        let mut value = serde_yaml::to_value(&*current).context("encode current config")?;
        set_yaml_value_at(&mut value, key, replacement)?;
        *current = serde_yaml::from_value(value)
            .with_context(|| format!("value for `{key}` does not match the config schema"))?;
        Ok(())
    });
    match result {
        Ok(()) => handled_after_reload(home, format!("Config field `{key}` updated atomically.")),
        Err(error) => failed("/config", error),
    }
}

fn redacted_config_value(config: &FreedomConfig) -> Result<serde_yaml::Value> {
    let mut value = serde_yaml::to_value(config).context("encode config for display")?;
    redact_yaml_secrets(&mut value);
    Ok(value)
}

fn redact_yaml_secrets(value: &mut serde_yaml::Value) {
    match value {
        serde_yaml::Value::Mapping(mapping) => {
            for (key, child) in mapping.iter_mut() {
                let secret = key.as_str().map(secret_field_name).unwrap_or(false);
                if secret {
                    *child = serde_yaml::Value::String("[REDACTED]".into());
                } else {
                    redact_yaml_secrets(child);
                }
            }
        }
        serde_yaml::Value::Sequence(items) => {
            for item in items {
                redact_yaml_secrets(item);
            }
        }
        _ => {}
    }
}

fn secret_field_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    matches!(
        name.as_str(),
        "key" | "secret" | "password" | "provider_key" | "telegram_token" | "api_key"
    ) || name.ends_with("_token")
        || name.ends_with("_secret")
        || name.ends_with("_password")
        || name.ends_with("_api_key")
}

fn secret_config_path(path: &str) -> bool {
    path.split('.').any(secret_field_name)
}

fn yaml_value_at<'a>(value: &'a serde_yaml::Value, path: &str) -> Result<&'a serde_yaml::Value> {
    let mut current = value;
    for part in path.split('.').filter(|part| !part.is_empty()) {
        current = match current {
            serde_yaml::Value::Mapping(mapping) => {
                let key = serde_yaml::Value::String(part.to_string());
                mapping
                    .get(&key)
                    .ok_or_else(|| anyhow::anyhow!("unknown config field `{path}`"))?
            }
            serde_yaml::Value::Sequence(items) => {
                let index = part
                    .parse::<usize>()
                    .with_context(|| format!("`{part}` is not a list index in `{path}`"))?;
                items.get(index).ok_or_else(|| {
                    anyhow::anyhow!("list index {index} is out of range in `{path}`")
                })?
            }
            _ => anyhow::bail!("`{part}` traverses a scalar in `{path}`"),
        };
    }
    Ok(current)
}

fn set_yaml_value_at(
    value: &mut serde_yaml::Value,
    path: &str,
    replacement: serde_yaml::Value,
) -> Result<()> {
    let parts: Vec<&str> = path.split('.').filter(|part| !part.is_empty()).collect();
    if parts.is_empty() {
        anyhow::bail!("config field must not be empty");
    }
    set_yaml_parts(value, &parts, replacement, path)
}

fn set_yaml_parts(
    current: &mut serde_yaml::Value,
    parts: &[&str],
    replacement: serde_yaml::Value,
    full_path: &str,
) -> Result<()> {
    let part = parts[0];
    let target = match current {
        serde_yaml::Value::Mapping(mapping) => {
            let key = serde_yaml::Value::String(part.to_string());
            mapping
                .get_mut(&key)
                .ok_or_else(|| anyhow::anyhow!("unknown config field `{full_path}`"))?
        }
        serde_yaml::Value::Sequence(items) => {
            let index = part
                .parse::<usize>()
                .with_context(|| format!("`{part}` is not a list index in `{full_path}`"))?;
            items.get_mut(index).ok_or_else(|| {
                anyhow::anyhow!("list index {index} is out of range in `{full_path}`")
            })?
        }
        _ => anyhow::bail!("`{part}` traverses a scalar in `{full_path}`"),
    };
    if parts.len() == 1 {
        *target = replacement;
        Ok(())
    } else {
        set_yaml_parts(target, &parts[1..], replacement, full_path)
    }
}

struct ProviderRequest {
    role: String,
    provider: String,
    model: Option<String>,
    key: Option<String>,
    endpoint: Option<String>,
}

fn parse_provider_request(args: &str) -> Result<ProviderRequest> {
    let tokens: Vec<&str> = args.split_whitespace().collect();
    if tokens.is_empty() {
        anyhow::bail!(
            "usage: /provider [left|right|cerebellum] <kind> [--model M] [--key K] [--endpoint URL]"
        );
    }
    let role_token = matches!(
        tokens[0].to_ascii_lowercase().as_str(),
        "left" | "l" | "right" | "r" | "cerebellum" | "c" | "cb"
    );
    let (role, provider_index) = if role_token {
        (tokens[0].to_string(), 1)
    } else {
        ("left".to_string(), 0)
    };
    let provider = tokens
        .get(provider_index)
        .filter(|token| !token.starts_with("--"))
        .ok_or_else(|| anyhow::anyhow!("provider kind is required"))?
        .to_string();
    let mut model = None;
    let mut key = None;
    let mut endpoint = None;
    let mut index = provider_index + 1;
    while index < tokens.len() {
        let slot = match tokens[index] {
            "--model" => &mut model,
            "--key" => &mut key,
            "--endpoint" => &mut endpoint,
            other => anyhow::bail!("unknown provider option `{other}`"),
        };
        let value = tokens
            .get(index + 1)
            .filter(|value| !value.starts_with("--"))
            .ok_or_else(|| anyhow::anyhow!("{} requires a value", tokens[index]))?;
        if slot.is_some() {
            anyhow::bail!("{} may only be supplied once", tokens[index]);
        }
        *slot = Some((*value).to_string());
        index += 2;
    }
    Ok(ProviderRequest {
        role,
        provider,
        model,
        key,
        endpoint,
    })
}

async fn handle_provider_switch(args: &str, home: &Path) -> ActionOutcome {
    let request = match parse_provider_request(args) {
        Ok(request) => request,
        Err(error) => {
            return ActionOutcome::InvalidArgs {
                text: format!("/provider: {error}"),
            };
        }
    };
    match crate::cli::hemispheres::rebind_at(
        home,
        &request.role,
        &request.provider,
        request.model,
        request.key,
        request.endpoint,
    )
    .await
    {
        Ok(result) => handled_after_reload(
            home,
            format!(
                "Hemisphere `{}` rebound from `{}` to `{}`. Audit: {}",
                result.role.as_str(),
                result
                    .prior
                    .provider
                    .map(|provider| provider.as_str())
                    .unwrap_or("default"),
                result.provider.as_str(),
                result.audit_segment.display()
            ),
        ),
        Err(error) => failed("/provider", error),
    }
}

fn channel_arg<'a>(args: &'a str, command: &str) -> std::result::Result<&'a str, ActionOutcome> {
    let parts: Vec<&str> = args.split_whitespace().collect();
    if parts.len() != 1 {
        return Err(ActionOutcome::InvalidArgs {
            text: format!("/{command} — usage: `/{command} <channel>`"),
        });
    }
    Ok(parts[0])
}

fn known_slash_channel_names() -> String {
    channel_descriptors()
        .iter()
        .flat_map(|descriptor| {
            std::iter::once(descriptor.id.as_str()).chain(descriptor.aliases.iter().copied())
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn resolve_slash_channel(
    args: &str,
    command: &str,
) -> std::result::Result<ChannelId, ActionOutcome> {
    let channel = channel_arg(args, command)?;
    resolve_channel_id(channel).ok_or_else(|| ActionOutcome::InvalidArgs {
        text: format!(
            "/{command} {channel} — unknown channel. Available canonical IDs and aliases: {}",
            known_slash_channel_names()
        ),
    })
}

async fn handle_connect(args: &str, home: &Path) -> ActionOutcome {
    let channel_id = match resolve_slash_channel(args, "connect") {
        Ok(channel_id) => channel_id,
        Err(outcome) => return outcome,
    };
    let channel = channel_id.as_str();
    let prepared = match crate::cli::channel::prepare_channel_add_at(
        home,
        channel,
        &crate::cli::channel::ChannelAddFlags::default(),
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(error) => return failed("/connect candidate preparation", error),
    };
    debug_assert_eq!(prepared.channel_id(), channel_id);
    let verification = match crate::cli::channel::test_prepared_channel(&prepared).await {
        Ok(result) => result,
        Err(error) => return failed("/connect candidate verification; nothing was saved", error),
    };

    let verified = match connect_probe_disposition(verification.status) {
        ConnectProbeDisposition::Verified => true,
        ConnectProbeDisposition::Unavailable => false,
        ConnectProbeDisposition::Reject => {
            return ActionOutcome::Failed {
                text: format!(
                    "/connect {channel} verification failed: {}. Candidate credentials were not saved; existing channel state is unchanged.",
                    verification.detail
                ),
            };
        }
    };

    if let Err(error) = crate::cli::channel::commit_prepared_channel_add_at(home, prepared) {
        return failed("/connect verified-candidate commit", error);
    }

    let status = if verified {
        format!(
            "credentials saved after a successful live check: {}",
            verification.detail
        )
    } else {
        format!(
            "credentials saved, but no side-effect-free live verification was available: {}. NEOTH does not claim this adapter is live; check daemon runtime status after reload",
            verification.detail
        )
    };
    handled_after_reload(home, format!("Channel `{channel}` {status}."))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectProbeDisposition {
    Verified,
    Unavailable,
    Reject,
}

fn connect_probe_disposition(status: &str) -> ConnectProbeDisposition {
    match status {
        "ok" => ConnectProbeDisposition::Verified,
        "unavailable" => ConnectProbeDisposition::Unavailable,
        _ => ConnectProbeDisposition::Reject,
    }
}

fn handle_disconnect(args: &str, home: &Path) -> ActionOutcome {
    let channel_id = match resolve_slash_channel(args, "disconnect") {
        Ok(channel_id) => channel_id,
        Err(outcome) => return outcome,
    };
    let channel = channel_id.as_str();
    match crate::cli::channel::run_remove_at(home, channel, &OutputFormat::Table) {
        Ok(()) => handled_after_reload(home, format!("Channel `{channel}` disconnected.")),
        Err(error) => failed("/disconnect", error),
    }
}

async fn handle_skill(
    args: &str,
    home: &Path,
    accepted_config: &FreedomConfig,
    config_path: &Path,
) -> ActionOutcome {
    let tokens: Vec<&str> = args.split_whitespace().collect();
    let sub = tokens.first().copied().unwrap_or("list");
    let inventory = match crate::skills::loader::diagnostic_inventory_for_accepted_config(
        &home.join("skills"),
        accepted_config.clone(),
        config_path.to_path_buf(),
    )
    .await
    {
        Ok(inventory) => inventory,
        Err(error) => return failed("/skill", error),
    };
    let runtime_label = |state: crate::skills::loader::SkillInventoryRuntimeState| match state {
        crate::skills::loader::SkillInventoryRuntimeState::TrustedBundledActive => "bundled-active",
        crate::skills::loader::SkillInventoryRuntimeState::InstalledActive => "installed-active",
        crate::skills::loader::SkillInventoryRuntimeState::BundledFallbackActive => {
            "bundled-fallback-active"
        }
        crate::skills::loader::SkillInventoryRuntimeState::Disabled => "disabled/quarantined",
    };
    match sub {
        "list" if tokens.len() <= 1 => {
            let mut lines = vec![format!("Skills and diagnostics ({}):", inventory.len())];
            for row in &inventory {
                match row {
                    crate::skills::loader::SkillInventoryRow::Healthy {
                        manifest,
                        origin,
                        runtime_state,
                        ..
                    } => lines.push(format!(
                        "  {}  [{}]  [{}]  {}",
                        manifest.id,
                        runtime_label(*runtime_state),
                        match origin {
                            crate::skills::loader::SkillInventoryOrigin::Bundled => "bundled",
                            crate::skills::loader::SkillInventoryOrigin::User => "installed",
                        },
                        manifest.description
                    )),
                    crate::skills::loader::SkillInventoryRow::Broken {
                        id,
                        error,
                        runtime_state,
                        ..
                    } => lines.push(format!(
                        "  {id}  [broken candidate; runtime={}]  {error}",
                        runtime_label(*runtime_state)
                    )),
                }
            }
            ActionOutcome::Handled {
                text: lines.join("\n"),
            }
        }
        "info" | "enable" | "disable" | "revoke" if tokens.len() == 2 => {
            let id = tokens[1];
            let Some(row) = inventory
                .iter()
                .find(|row| row.id().eq_ignore_ascii_case(id))
            else {
                return ActionOutcome::InvalidArgs {
                    text: format!("/skill: no installed skill with id `{id}`"),
                };
            };
            let (
                manifest,
                origin,
                runtime_state,
                package_generation_sha256,
                install_incarnation,
                install_terminal_receipt_sha256,
            ) = match row {
                crate::skills::loader::SkillInventoryRow::Healthy {
                    manifest,
                    origin,
                    runtime_state,
                    package_generation_sha256,
                    install_incarnation,
                    install_terminal_receipt_sha256,
                    ..
                } => (
                    manifest,
                    origin,
                    runtime_state,
                    package_generation_sha256,
                    install_incarnation,
                    install_terminal_receipt_sha256,
                ),
                crate::skills::loader::SkillInventoryRow::Broken {
                    error,
                    runtime_state,
                    ..
                } => {
                    if sub == "info" {
                        return ActionOutcome::Handled {
                            text: format!(
                                "Skill `{id}`\ninstalled candidate: broken\nruntime: {}\nerror: {error}",
                                runtime_label(*runtime_state)
                            ),
                        };
                    }
                    if sub == "disable"
                        && *runtime_state
                            == crate::skills::loader::SkillInventoryRuntimeState::BundledFallbackActive
                    {
                        return match crate::cli::skills::set_skill_authority_at_config_with_expectation(
                            home,
                            config_path,
                            id,
                            crate::cli::skills::SkillAuthorityTarget::Disabled,
                            crate::skills::authority::SkillAuthorityDecisionSource::OperatorBuddy,
                            None,
                        )
                        .await
                        {
                            Ok(outcome) => ActionOutcome::Handled {
                                text: format!(
                                    "Skill `{}` bundled fallback disabled (policy committed; live reload requested).",
                                    outcome.id
                                ),
                            },
                            Err(error) => failed("/skill", error),
                        };
                    }
                    return ActionOutcome::InvalidArgs {
                        text: format!(
                            "/skill: installed candidate `{id}` is broken ({error}); effective runtime is {}",
                            runtime_label(*runtime_state)
                        ),
                    };
                }
            };
            if sub == "info" {
                return ActionOutcome::Handled {
                    text: format!(
                        "Skill `{}`\nruntime: {}\norigin: {}\npolicy: {}\nversion: {}\ndescription: {}\ntriggers: {}\ntools: {}\nmodel: {}",
                        manifest.id,
                        runtime_label(*runtime_state),
                        match origin {
                            crate::skills::loader::SkillInventoryOrigin::Bundled => "bundled",
                            crate::skills::loader::SkillInventoryOrigin::User => "installed",
                        },
                        if manifest.enabled {
                            "enabled"
                        } else {
                            "disabled"
                        },
                        manifest.version,
                        manifest.description,
                        manifest.trigger_keywords.join(", "),
                        if manifest.tool_allowlist.is_empty() {
                            "none".into()
                        } else {
                            manifest.tool_allowlist.join(", ")
                        },
                        manifest.model.as_deref().unwrap_or("default"),
                    ),
                };
            }
            let target = match sub {
                "enable" => crate::cli::skills::SkillAuthorityTarget::Enabled,
                "disable" => crate::cli::skills::SkillAuthorityTarget::Disabled,
                "revoke" => crate::cli::skills::SkillAuthorityTarget::Revoked,
                _ => unreachable!("guarded Skill action"),
            };
            let expectation = match origin {
                crate::skills::loader::SkillInventoryOrigin::Bundled => None,
                crate::skills::loader::SkillInventoryOrigin::User => {
                    let (Some(generation), Some(incarnation), Some(receipt)) = (
                        package_generation_sha256.as_ref(),
                        *install_incarnation,
                        install_terminal_receipt_sha256.as_ref(),
                    ) else {
                        return ActionOutcome::Failed {
                            text: format!(
                                "/skill: installed candidate `{id}` has no authenticated install receipt; reinstall it before changing authority"
                            ),
                        };
                    };
                    match crate::skills::authority::InstalledSkillDecisionExpectation::new(
                        generation.clone(),
                        incarnation,
                        receipt.clone(),
                    ) {
                        Ok(expectation) => Some(expectation),
                        Err(error) => return failed("/skill", error),
                    }
                }
            };
            match crate::cli::skills::set_skill_authority_at_config_with_expectation(
                home,
                config_path,
                id,
                target,
                crate::skills::authority::SkillAuthorityDecisionSource::OperatorBuddy,
                expectation,
            )
            .await
            {
                Ok(outcome) => ActionOutcome::Handled {
                    text: format!(
                        "Skill `{}` {} ({} authority; live reload requested).",
                        outcome.id, outcome.state, outcome.origin
                    ),
                },
                Err(error) => failed("/skill", error),
            }
        }
        _ => ActionOutcome::InvalidArgs {
            text: "/skill — use: list | info <id> | enable <id> | disable <id> | revoke <id>"
                .into(),
        },
    }
}

fn plugin_activation_label(
    config: &FreedomConfig,
    plugin: &crate::wasm_plugin::discovery::DiscoveredPlugin,
) -> String {
    use crate::wasm_plugin::discovery::PluginActivation;
    let record = config
        .plugins
        .wasm
        .activations
        .get(&plugin.manifest.id)
        .cloned()
        .unwrap_or_default();
    if record.state == PluginActivation::Active
        && let Err(error) = record.validate_for(plugin)
    {
        return format!("reconsent_required ({error})");
    }
    record.state.as_str().to_string()
}

fn handle_plugin(args: &str, home: &Path) -> ActionOutcome {
    let tokens: Vec<&str> = args.split_whitespace().collect();
    let sub = tokens.first().copied().unwrap_or("list");
    let config = match FreedomConfig::load_from_path(&home.join("freedom.yaml")) {
        Ok(config) => config,
        Err(error) => return failed("/plugin", error),
    };
    let report = crate::wasm_plugin::discovery::discover(&home.join("plugins"));
    match sub {
        "list" if tokens.len() <= 1 => {
            let mut lines = vec![format!(
                "Plugins: {} loaded, {} rejected",
                report.loaded.len(),
                report.rejected.len()
            )];
            for plugin in &report.loaded {
                lines.push(format!(
                    "  {}  [{}]  permission={}  {}",
                    plugin.manifest.id,
                    plugin_activation_label(&config, plugin),
                    plugin.manifest.requested_permissions.as_str(),
                    plugin.manifest.name,
                ));
            }
            for error in &report.rejected {
                lines.push(format!("  rejected: {error}"));
            }
            ActionOutcome::Handled {
                text: lines.join("\n"),
            }
        }
        "info" | "enable" | "disable" if tokens.len() == 2 => {
            let id = tokens[1];
            let Some(plugin) = report.loaded.iter().find(|plugin| plugin.manifest.id == id) else {
                return ActionOutcome::InvalidArgs {
                    text: format!("/plugin: no discovered plugin with id `{id}`"),
                };
            };
            if sub == "info" {
                return ActionOutcome::Handled {
                    text: format!(
                        "Plugin `{}`\nname: {}\nversion: {}\nstate: {}\ndescription: {}\nrequested_permission: {}\nhook_stages: {:?}\nmanifest_sha256: {}\nwasm_sha256: {}",
                        id,
                        plugin.manifest.name,
                        plugin.manifest.version,
                        plugin_activation_label(&config, plugin),
                        plugin.manifest.description.as_deref().unwrap_or("(none)"),
                        plugin.manifest.requested_permissions.as_str(),
                        plugin.manifest.hook_stages,
                        plugin.manifest_hash,
                        plugin.content_hash,
                    ),
                };
            }
            let enabled = sub == "enable";
            match crate::cli::plugin::set_activation_for_action(home, id, enabled) {
                Ok(text) => handled_after_reload(home, text),
                Err(error) => failed("/plugin", error),
            }
        }
        _ => ActionOutcome::InvalidArgs {
            text: "/plugin — use: list | info <id> | enable <id> | disable <id>".into(),
        },
    }
}

fn query_memory(home: &Path, tier: Option<&str>, topic: Option<&str>) -> Result<String> {
    let connection = crate::memory::store::open(&home.join("views.db"))?;
    let pattern = topic.map(|topic| format!("%{}%", crate::memory::escape_like(topic)));
    let mut statement = connection.prepare(
        "SELECT tier, event_id, text, importance FROM (\
           SELECT 'hot' AS tier, event_id, text, importance, ts_ns AS ts FROM idx_episode \
           UNION ALL \
           SELECT 'warm', COALESCE(event_id, id), text, importance, consolidated_ts FROM idx_consolidated \
           UNION ALL \
           SELECT 'cold', event_id, text, importance, promoted_ts FROM idx_longterm \
           UNION ALL \
           SELECT 'groundtruth', id, statement, 1.0, asserted_at FROM idx_groundtruth WHERE revoked_at IS NULL\
         ) WHERE (?1 IS NULL OR tier = ?1) \
           AND (?2 IS NULL OR text COLLATE NOCASE LIKE ?2 ESCAPE '\\') \
         ORDER BY importance DESC, ts DESC LIMIT 20",
    )?;
    let rows = statement
        .query_map(rusqlite::params![tier, pattern], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, f64>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if rows.is_empty() {
        return Ok(match (tier, topic) {
            (Some(tier), Some(topic)) => format!("No `{tier}` memory matched `{topic}`."),
            (Some(tier), None) => format!("No `{tier}` memory entries."),
            (None, Some(topic)) => format!("No memory matched `{topic}`."),
            (None, None) => "No memory entries.".into(),
        });
    }
    let mut lines = vec![format!("Memory matches ({}):", rows.len())];
    for (tier, id, text, importance) in rows {
        let preview: String = text.chars().take(120).collect();
        lines.push(format!("  [{tier}:{id}] imp={importance:.3}  {preview}"));
    }
    Ok(lines.join("\n"))
}

async fn handle_memory(args: &str, home: &Path) -> ActionOutcome {
    let mut parts = args.split_whitespace();
    let sub = parts.next().unwrap_or("view");
    match sub {
        "view" => {
            let topic = args
                .strip_prefix("view")
                .map(str::trim)
                .filter(|topic| !topic.is_empty());
            match query_memory(home, None, topic) {
                Ok(text) => ActionOutcome::Handled { text },
                Err(error) => failed("/memory view", error),
            }
        }
        "tier" => {
            let tier = parts.next();
            if parts.next().is_some()
                || !matches!(tier, Some("hot" | "warm" | "cold" | "groundtruth"))
            {
                return ActionOutcome::InvalidArgs {
                    text: "/memory tier — expected hot | warm | cold | groundtruth".into(),
                };
            }
            match query_memory(home, tier, None) {
                Ok(text) => ActionOutcome::Handled { text },
                Err(error) => failed("/memory tier", error),
            }
        }
        "forget" => {
            let rest = args.strip_prefix("forget").unwrap_or("").trim();
            let mut confirmed = false;
            let mut topic_parts = Vec::new();
            for part in rest.split_whitespace() {
                if part == "--confirm" {
                    confirmed = true;
                } else if part.starts_with("--") {
                    return ActionOutcome::InvalidArgs {
                        text: format!("/memory forget — unknown option `{part}`"),
                    };
                } else {
                    topic_parts.push(part);
                }
            }
            let topic = topic_parts.join(" ");
            if topic.is_empty() {
                return ActionOutcome::InvalidArgs {
                    text: "/memory forget — usage: `/memory forget <topic> [--confirm]`".into(),
                };
            }
            let args = crate::cli::memory::MemoryArgs {
                forget: Some(topic.clone()),
                confirm: confirmed,
                db: Some(home.join("views.db")),
                limit: 20,
                output: OutputFormat::Table,
                ..Default::default()
            };
            match crate::cli::memory::run_memory(args).await {
                Ok(()) if confirmed => ActionOutcome::Handled {
                    text: format!("Memory erasure completed for topic `{topic}`."),
                },
                Ok(()) => ActionOutcome::Handled {
                    text: format!(
                        "Forget preview completed for `{topic}`; no data changed. Add `--confirm` to this slash command to execute the audited erasure."
                    ),
                },
                Err(error) => failed("/memory forget", error),
            }
        }
        other => ActionOutcome::InvalidArgs {
            text: format!(
                "/memory — unknown subcommand `{other}`. Use view [topic] | tier <name> | forget <topic> [--confirm]."
            ),
        },
    }
}

async fn handle_consent(args: &str, config: &FreedomConfig, home: &Path) -> ActionOutcome {
    let tokens: Vec<&str> = args.split_whitespace().collect();
    let sub = tokens.first().copied().unwrap_or("list");
    match sub {
        "list" if tokens.len() <= 1 => {
            match crate::cli::consent::consent_status_rows(home, Some(config)) {
                Ok(rows) if rows.is_empty() => ActionOutcome::Handled {
                    text: "No configured or recorded outbound-provider consent routes.".into(),
                },
                Ok(rows) => ActionOutcome::Handled {
                    text: rows
                        .into_iter()
                        .map(|row| {
                            let configured = if row.configured_endpoint_origins.is_empty() {
                                String::new()
                            } else {
                                format!(
                                    " configured=[{}]",
                                    row.configured_endpoint_origins.join(", ")
                                )
                            };
                            let granted = if row.granted_endpoint_origins.is_empty() {
                                String::new()
                            } else {
                                format!(" granted=[{}]", row.granted_endpoint_origins.join(", "))
                            };
                            let stale = if row.stale_endpoint_origins.is_empty() {
                                String::new()
                            } else {
                                format!(" stale=[{}]", row.stale_endpoint_origins.join(", "))
                            };
                            let audit = if row.audit_pending {
                                " audit=pending"
                            } else {
                                ""
                            };
                            let error = row
                                .error
                                .as_deref()
                                .map(|error| format!(" error={error}"))
                                .unwrap_or_default();
                            format!(
                                "{}: {}{configured}{granted}{stale}{audit}{error}",
                                row.provider, row.status
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n"),
                },
                Err(error) => failed("/consent list", error),
            }
        }
        "grant" | "revoke" if tokens.len() == 2 => {
            let Some(provider) = crate::consent::kind_from_slug(tokens[1]) else {
                return ActionOutcome::InvalidArgs {
                    text: format!("/consent: unknown provider `{}`", tokens[1]),
                };
            };
            let grant = sub == "grant";
            match crate::cli::consent::change_consent_with_config_at(
                home,
                provider,
                grant,
                config,
                crate::cli::consent::ConsentMutationSource::Slash,
            )
            .await
            {
                Ok(change) => ActionOutcome::Handled {
                    text: if grant {
                        let routes = if change.endpoint_origins.is_empty() {
                            String::new()
                        } else {
                            format!(" Routes: {}.", change.endpoint_origins.join(", "))
                        };
                        format!(
                            "Consent granted for `{}`.{routes}",
                            crate::consent::slug(provider)
                        )
                    } else if change.was_granted {
                        format!("Consent revoked for `{}`.", crate::consent::slug(provider))
                    } else {
                        format!(
                            "No consent grant existed for `{}`; state unchanged.",
                            crate::consent::slug(provider)
                        )
                    },
                },
                Err(error) => failed("/consent", error),
            }
        }
        _ => ActionOutcome::InvalidArgs {
            text: "/consent — use: list | grant <provider> | revoke <provider>".into(),
        },
    }
}

fn handle_reload(home: &Path) -> ActionOutcome {
    match request_reload_at(home) {
        Ok(()) => ActionOutcome::Handled {
            text: "Live-config reload requested; the daemon will validate and swap the new config atomically.".into(),
        },
        Err(error) => failed("/reload", error),
    }
}

fn handle_background_run(prompt: &str, btw: bool) -> ActionOutcome {
    let command = if btw { "btw" } else { "background" };
    if prompt.is_empty() {
        return ActionOutcome::InvalidArgs {
            text: format!("/{command} — usage: `/{command} <prompt>`"),
        };
    }
    // Current chat/serve callers spawn before generic action dispatch.
    ActionOutcome::Handled {
        text: format!("[neoth] /{command}: background session queued — result at next idle"),
    }
}

async fn handle_autonomy(args: &str, config: &FreedomConfig, home: &Path) -> ActionOutcome {
    if args.is_empty() {
        return ActionOutcome::Handled {
            text: format!("Current autonomy: {}", config.autonomy.as_str()),
        };
    }
    if args.split_whitespace().count() != 1 {
        return ActionOutcome::InvalidArgs {
            text: "/autonomy — expected strict | standard | elevated | full | custom".into(),
        };
    }
    match crate::cli::autonomy::set_level_at(home, &home.join("freedom.yaml"), args).await {
        Ok((previous, applied)) => handled_after_reload(
            home,
            if previous == applied {
                format!("Autonomy unchanged: {}.", applied.as_str())
            } else {
                format!(
                    "Autonomy changed: {} -> {}.",
                    previous.as_str(),
                    applied.as_str()
                )
            },
        ),
        Err(error) if error.to_string().contains("invalid autonomy level") => {
            ActionOutcome::InvalidArgs {
                text: error.to_string(),
            }
        }
        Err(error) => failed("/autonomy", error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_config(home: &Path, config: &FreedomConfig) {
        std::fs::create_dir_all(home).unwrap();
        std::fs::write(
            home.join("freedom.yaml"),
            serde_yaml::to_string(config).unwrap(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn quit_returns_exit_outcome() {
        let out = dispatch_action_at(
            SlashAction::Quit,
            "",
            &FreedomConfig::default(),
            CommandSource::Cli,
            Path::new("."),
        )
        .await;
        assert!(out.should_exit());
    }

    #[test]
    fn config_list_redacts_merged_secrets() {
        let mut config = FreedomConfig::default();
        config.provider_key = Some(crate::secret::SecretString::from("sk-must-not-leak"));
        let out = handle_config("", &config, Path::new("."));
        assert!(matches!(out, ActionOutcome::Handled { .. }));
        assert!(!out.text().contains("sk-must-not-leak"));
        assert!(out.text().contains("[REDACTED]"));
    }

    #[test]
    fn config_single_field_is_a_real_read() {
        let mut config = FreedomConfig::default();
        config.operator_id = Some("alex".into());
        let out = handle_config("operator_id", &config, Path::new("."));
        assert_eq!(out.text(), "operator_id: alex");
    }

    #[test]
    fn config_set_persists_and_requests_reload() {
        let dir = tempfile::tempdir().unwrap();
        let config = FreedomConfig::default();
        write_config(dir.path(), &config);

        let out = handle_config("operator_id alex", &config, dir.path());

        assert!(matches!(out, ActionOutcome::Handled { .. }), "{out:?}");
        let loaded = FreedomConfig::load_from_path(&dir.path().join("freedom.yaml")).unwrap();
        assert_eq!(loaded.operator_id.as_deref(), Some("alex"));
        assert!(
            dir.path()
                .join(crate::config::reload::RELOAD_SENTINEL_NAME)
                .exists()
        );
    }

    #[test]
    fn config_set_rejects_secret_paths_without_touching_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let config = FreedomConfig::default();
        write_config(dir.path(), &config);
        let path = dir.path().join("freedom.yaml");
        let before = std::fs::read(&path).unwrap();

        let out = handle_config("provider_key sk-nope", &config, dir.path());

        assert!(matches!(out, ActionOutcome::InvalidArgs { .. }));
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    #[test]
    fn config_set_preserves_malformed_state_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        let malformed = b"operator_id: [broken\n";
        std::fs::write(&path, malformed).unwrap();

        let out = handle_config("operator_id alex", &FreedomConfig::default(), dir.path());

        assert!(matches!(out, ActionOutcome::Failed { .. }));
        assert_eq!(std::fs::read(path).unwrap(), malformed);
    }

    #[test]
    fn config_nested_list_index_mutation_is_typed() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = FreedomConfig::default();
        config
            .webhook_manager
            .endpoints
            .push(crate::config::automation::WebhookEndpointConfig {
                url: "https://old.example/hook".into(),
                ..Default::default()
            });
        write_config(dir.path(), &config);

        let out = handle_config(
            "webhook_manager.endpoints.0.url https://new.example/hook",
            &config,
            dir.path(),
        );

        assert!(matches!(out, ActionOutcome::Handled { .. }), "{out:?}");
        let loaded = FreedomConfig::load_from_path(&dir.path().join("freedom.yaml")).unwrap();
        assert_eq!(
            loaded.webhook_manager.endpoints[0].url,
            "https://new.example/hook"
        );
    }

    #[test]
    fn provider_parser_defaults_left_and_never_requires_key() {
        let request = parse_provider_request("local_qwen --model qwen3").unwrap();
        assert_eq!(request.role, "left");
        assert_eq!(request.provider, "local_qwen");
        assert_eq!(request.model.as_deref(), Some("qwen3"));
        assert!(request.key.is_none());
    }

    #[test]
    fn provider_parser_accepts_role_key_and_endpoint() {
        let request = parse_provider_request(
            "right openai_compat --model local/model --endpoint http://127.0.0.1:1234 --key secret",
        )
        .unwrap();
        assert_eq!(request.role, "right");
        assert_eq!(request.provider, "openai_compat");
        assert_eq!(request.endpoint.as_deref(), Some("http://127.0.0.1:1234"));
        assert_eq!(request.key.as_deref(), Some("secret"));
    }

    #[test]
    fn provider_parser_rejects_missing_option_value() {
        assert!(parse_provider_request("left openai_api --key").is_err());
    }

    #[tokio::test]
    async fn provider_switch_writes_role_config_and_secret_store() {
        let dir = tempfile::tempdir().unwrap();
        let config = FreedomConfig::default();
        write_config(dir.path(), &config);

        let out = handle_provider_switch(
            "right openai_api --model gpt-test --key sk-role-secret",
            dir.path(),
        )
        .await;

        assert!(matches!(out, ActionOutcome::Handled { .. }), "{out:?}");
        let loaded = FreedomConfig::load_from_path(&dir.path().join("freedom.yaml")).unwrap();
        assert_eq!(
            loaded.inference.right.provider,
            Some(crate::config::inference::InferenceProvider::OpenAi)
        );
        assert_eq!(loaded.inference.right.model.as_deref(), Some("gpt-test"));
        let credentials = crate::config::credentials::Credentials::load_or_default(
            &dir.path().join("credentials.yaml"),
        )
        .unwrap();
        assert_eq!(
            credentials
                .inference_right_key
                .as_ref()
                .map(|secret| secret.expose()),
            Some("sk-role-secret")
        );
        assert!(
            !std::fs::read_to_string(dir.path().join("freedom.yaml"))
                .unwrap()
                .contains("sk-role-secret")
        );
    }

    #[test]
    fn disconnect_rejects_unknown_channel_without_mutation() {
        let out = handle_disconnect("carrier-pigeon", Path::new("."));
        assert!(matches!(out, ActionOutcome::InvalidArgs { .. }));
        assert!(out.text().contains("whatsapp_baileys"));
        assert!(out.text().contains("imessage_bluebubbles"));
    }

    #[test]
    fn connect_probe_disposition_never_treats_fail_or_skipped_as_committable() {
        assert_eq!(
            connect_probe_disposition("ok"),
            ConnectProbeDisposition::Verified
        );
        assert_eq!(
            connect_probe_disposition("unavailable"),
            ConnectProbeDisposition::Unavailable
        );
        for status in ["fail", "skipped", "", "future-status"] {
            assert_eq!(
                connect_probe_disposition(status),
                ConnectProbeDisposition::Reject
            );
        }
    }

    #[test]
    fn slash_channel_resolution_covers_all_canonical_ids_and_operator_aliases() {
        let descriptors = channel_descriptors();
        assert_eq!(descriptors.len(), 15, "v1 channel inventory drifted");

        for descriptor in descriptors {
            assert_eq!(
                resolve_slash_channel(descriptor.id.as_str(), "connect").unwrap(),
                descriptor.id,
                "canonical slash resolution drifted for {}",
                descriptor.id.as_str()
            );
            for alias in descriptor.aliases {
                assert_eq!(
                    resolve_slash_channel(alias, "disconnect").unwrap(),
                    descriptor.id,
                    "operator alias `{alias}` drifted for {}",
                    descriptor.id.as_str()
                );
            }
        }

        assert_eq!(
            resolve_slash_channel("  GoOgLe_ChAt  ", "connect").unwrap(),
            crate::channels::ChannelKind::GoogleChat
        );
    }

    #[tokio::test]
    async fn skill_enable_is_persisted_through_locked_helper() {
        let dir = tempfile::tempdir().unwrap();
        let config = FreedomConfig::default();
        write_config(dir.path(), &config);

        let out = handle_skill(
            "enable raskal",
            dir.path(),
            &config,
            &dir.path().join("freedom.yaml"),
        )
        .await;

        assert!(matches!(out, ActionOutcome::Handled { .. }), "{out:?}");
        let loaded = FreedomConfig::load_from_path(&dir.path().join("freedom.yaml")).unwrap();
        assert!(loaded.skills.enabled.contains(&"raskal".to_string()));
        assert!(!loaded.skills.disabled.contains(&"raskal".to_string()));
    }

    #[tokio::test]
    async fn skill_action_mutates_only_the_selected_custom_config() {
        let dir = tempfile::tempdir().unwrap();
        let mut adjacent = FreedomConfig::default();
        adjacent.skills.disabled.push("raskal".to_string());
        write_config(dir.path(), &adjacent);
        let custom_path = dir.path().join("operator-instance.yaml");
        let custom = FreedomConfig::default();
        std::fs::write(&custom_path, serde_yaml::to_string(&custom).unwrap()).unwrap();

        let out = handle_skill("enable raskal", dir.path(), &custom, &custom_path).await;

        assert!(matches!(out, ActionOutcome::Handled { .. }), "{out:?}");
        let adjacent_after =
            FreedomConfig::load_from_path(&dir.path().join("freedom.yaml")).unwrap();
        assert!(
            adjacent_after
                .skills
                .disabled
                .contains(&"raskal".to_string()),
            "the adjacent default config must not be mutated"
        );
        let custom_after = FreedomConfig::load_from_path(&custom_path).unwrap();
        assert!(custom_after.skills.enabled.contains(&"raskal".to_string()));
        assert!(!custom_after.skills.disabled.contains(&"raskal".to_string()));
    }

    #[test]
    fn plugin_enable_persists_exact_approval_binding() {
        use crate::wasm_plugin::discovery::PluginActivation;

        let dir = tempfile::tempdir().unwrap();
        let config = FreedomConfig::default();
        write_config(dir.path(), &config);
        let plugin_dir = dir.path().join("plugins").join("demo_plugin");
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(
            plugin_dir.join("plugin.toml"),
            "id = \"demo_plugin\"\nname = \"Demo\"\nversion = \"1.0.0\"\nrequested_permissions = \"read_only\"\n",
        )
        .unwrap();
        std::fs::write(
            plugin_dir.join("plugin.wasm"),
            [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
        )
        .unwrap();

        let out = handle_plugin("enable demo_plugin", dir.path());

        assert!(matches!(out, ActionOutcome::Handled { .. }), "{out:?}");
        let loaded = FreedomConfig::load_from_path(&dir.path().join("freedom.yaml")).unwrap();
        let record = loaded.plugins.wasm.activations.get("demo_plugin").unwrap();
        assert_eq!(record.state, PluginActivation::Active);
        let discovered = crate::wasm_plugin::discovery::discover(&dir.path().join("plugins"));
        record.validate_for(&discovered.loaded[0]).unwrap();
    }

    #[test]
    fn memory_view_returns_real_matching_rows() {
        let dir = tempfile::tempdir().unwrap();
        let connection = crate::memory::store::open(&dir.path().join("views.db")).unwrap();
        connection
            .execute(
                "INSERT INTO idx_episode \
                 (event_id, event_type, ts_ns, text, text_hash, importance) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![7_i64, 1_i64, 99_i64, "Alexander likes Rust", "hash", 0.8],
            )
            .unwrap();

        let text = query_memory(dir.path(), None, Some("rust")).unwrap();

        assert!(text.contains("hot:7"));
        assert!(text.contains("Alexander likes Rust"));
    }

    #[test]
    fn memory_groundtruth_tier_is_wired() {
        let dir = tempfile::tempdir().unwrap();
        let connection = crate::memory::store::open(&dir.path().join("views.db")).unwrap();
        connection
            .execute(
                "INSERT INTO idx_groundtruth \
                 (statement, source, scope, asserted_at) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params!["NEOTH is local-first", "test", "operator", 42_i64],
            )
            .unwrap();

        let text = query_memory(dir.path(), Some("groundtruth"), None).unwrap();

        assert!(text.contains("groundtruth:"));
        assert!(text.contains("NEOTH is local-first"));
    }

    #[tokio::test]
    async fn consent_mutation_fails_closed_on_malformed_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        let malformed = b"audit_rpc: [broken\n";
        std::fs::write(&path, malformed).unwrap();

        let out = handle_consent("grant openai_api", &FreedomConfig::default(), dir.path()).await;

        assert!(matches!(out, ActionOutcome::Failed { .. }));
        assert_eq!(std::fs::read(path).unwrap(), malformed);
        assert!(
            !crate::consent::marker_path(dir.path(), crate::cli::init::ProviderKind::OpenaiApi)
                .exists()
        );
    }

    #[test]
    fn destructive_ceiling_is_subcommand_aware() {
        assert!(SlashAction::RestartWizard.is_destructive_with_args(""));
        assert!(SlashAction::ConfigGet.is_destructive_with_args("operator_id alex"));
        assert!(!SlashAction::ConfigGet.is_destructive_with_args("operator_id"));
        assert!(SlashAction::SkillRegistry.is_destructive_with_args("enable foo"));
        assert!(SlashAction::SkillRegistry.is_destructive_with_args("revoke foo"));
        assert!(!SlashAction::SkillRegistry.is_destructive_with_args("info foo"));
        assert!(SlashAction::PluginRegistry.is_destructive_with_args("disable foo"));
        assert!(!SlashAction::PluginRegistry.is_destructive_with_args("revoke foo"));
        assert!(!SlashAction::PluginRegistry.is_destructive_with_args("list"));
        assert!(SlashAction::MemoryView.is_destructive_with_args("forget x --confirm"));
        assert!(!SlashAction::MemoryView.is_destructive_with_args("tier hot"));
        assert!(SlashAction::ConsentManage.is_destructive_with_args("grant openai_api"));
        assert!(!SlashAction::ConsentManage.is_destructive_with_args("list"));
        assert!(SlashAction::AutonomyLevel.is_destructive_with_args("full"));
        assert!(!SlashAction::AutonomyLevel.is_destructive_with_args(""));
    }

    #[tokio::test]
    async fn channel_config_write_is_blocked_before_disk_access() {
        let out = dispatch_action_at(
            SlashAction::ConfigGet,
            "operator_id attacker",
            &FreedomConfig::default(),
            CommandSource::Channel,
            Path::new("does-not-exist"),
        )
        .await;
        assert!(out.is_channel_blocked());
    }

    #[tokio::test]
    async fn channel_skill_revoke_is_blocked_before_disk_access() {
        let out = dispatch_action_at(
            SlashAction::SkillRegistry,
            "revoke attacker-controlled",
            &FreedomConfig::default(),
            CommandSource::Channel,
            Path::new("does-not-exist"),
        )
        .await;
        assert!(out.is_channel_blocked());
    }

    #[tokio::test]
    async fn channel_read_only_config_get_remains_allowed() {
        let mut config = FreedomConfig::default();
        config.operator_id = Some("alex".into());
        let out = dispatch_action_at(
            SlashAction::ConfigGet,
            "operator_id",
            &config,
            CommandSource::Channel,
            Path::new("does-not-exist"),
        )
        .await;
        assert!(matches!(out, ActionOutcome::Handled { .. }));
        assert!(out.text().contains("alex"));
    }

    #[test]
    fn every_outcome_has_operator_visible_text() {
        for outcome in [
            ActionOutcome::Handled { text: "ok".into() },
            ActionOutcome::Failed {
                text: "failed".into(),
            },
            ActionOutcome::InvalidArgs { text: "bad".into() },
            ActionOutcome::ChannelPrivilegeBlocked {
                text: "blocked".into(),
            },
            ActionOutcome::Exit,
        ] {
            assert!(!outcome.text().is_empty());
        }
    }

    #[test]
    fn background_requires_prompt_and_acknowledges_queue() {
        let empty = handle_background_run("", false);
        assert!(matches!(empty, ActionOutcome::InvalidArgs { .. }));
        let queued = handle_background_run("review this", true);
        assert!(matches!(queued, ActionOutcome::Handled { .. }));
        assert!(queued.text().contains("background session queued"));
    }
}
