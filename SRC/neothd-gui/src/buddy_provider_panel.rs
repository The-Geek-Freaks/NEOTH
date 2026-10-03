//! Pure, redacted Buddy provider/fallback panel contract.
//!
//! This candidate deliberately owns no process execution, configuration write,
//! credential, endpoint, or raw command-output storage.  The bridge executes
//! only `argv()` output and replaces the visible snapshot after a successful
//! typed readback.

use std::collections::BTreeSet;

use serde_json::Value;

const MAX_IDENTIFIER_LEN: usize = 128;
const MAX_MODEL_LEN: usize = 192;
const MAX_QUESTION_LEN: usize = 512;
const MAX_INSTANCES: usize = 32;
const MAX_DRAFT_FALLBACKS: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuddyPanelError {
    MalformedReadback,
    UnsupportedSchema,
    InvalidRole,
    InvalidProvider,
    InvalidPreset,
    InvalidInstance,
    InvalidMode,
    DuplicateFallback,
    FallbackNotNamed,
    TooManyItems,
    InvalidQuestion,
    LiveConfirmationRequired,
    InvalidOutcome,
}

/// A safe, displayable projection of an existing named provider authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuddyProviderInstance {
    pub id: String,
    pub provider: String,
    pub model: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuddyRoleBinding {
    pub role: String,
    pub binding_source: BuddyBindingSource,
    pub provider_instance_id: Option<String>,
    pub provider: String,
    pub model: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuddyFallbackEntry {
    pub position: usize,
    pub binding_source: BuddyBindingSource,
    pub provider_instance_id: Option<String>,
    pub provider: String,
    pub model: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuddyBindingSource { NamedInstance, LegacyInline }

/// Redacted `buddy_gui` readback nested in `neoth buddy provider show --output json`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuddyProviderReadback {
    pub mode: String,
    pub roles: Vec<BuddyRoleBinding>,
    pub available_provider_instances: Vec<BuddyProviderInstance>,
    pub fallback_max_hops: u32,
    pub fallback: Vec<BuddyFallbackEntry>,
}

/// Parses only the additive, redacted `buddy_gui` projection.  Any malformed
/// payload returns a non-descriptive error so callers retain the last display
/// and never surface raw stdout/stderr, endpoints, paths, or credentials.
pub fn parse_buddy_provider_readback(raw: &str) -> Result<BuddyProviderReadback, BuddyPanelError> {
    let root: Value = serde_json::from_str(raw).map_err(|_| BuddyPanelError::MalformedReadback)?;
    let gui = root.get("buddy_gui").ok_or(BuddyPanelError::MalformedReadback)?;
    let object = gui.as_object().ok_or(BuddyPanelError::MalformedReadback)?;
    if object.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err(BuddyPanelError::UnsupportedSchema);
    }
    let mode = read_identifier(object.get("mode"), BuddyPanelError::InvalidMode)?;
    if !matches!(mode.as_str(), "triplet" | "single" | "custom") {
        return Err(BuddyPanelError::InvalidMode);
    }

    let instances = object
        .get("available_provider_instances")
        .and_then(Value::as_array)
        .ok_or(BuddyPanelError::MalformedReadback)?;
    if instances.len() > MAX_INSTANCES {
        return Err(BuddyPanelError::TooManyItems);
    }
    let mut known_ids = BTreeSet::new();
    let available_provider_instances = instances
        .iter()
        .map(|value| {
            let value = value.as_object().ok_or(BuddyPanelError::MalformedReadback)?;
            let id = read_identifier(value.get("id"), BuddyPanelError::InvalidInstance)?;
            if !known_ids.insert(id.clone()) {
                return Err(BuddyPanelError::DuplicateFallback);
            }
            Ok(BuddyProviderInstance {
                id,
                provider: read_provider(value.get("provider"))?,
                model: read_model(value.get("model"))?,
            })
        })
        .collect::<Result<Vec<_>, BuddyPanelError>>()?;

    let roles = object
        .get("roles")
        .and_then(Value::as_array)
        .ok_or(BuddyPanelError::MalformedReadback)?;
    if roles.len() != 3 {
        return Err(BuddyPanelError::MalformedReadback);
    }
    let mut known_roles = BTreeSet::new();
    let roles = roles
        .iter()
        .map(|value| {
            let value = value.as_object().ok_or(BuddyPanelError::MalformedReadback)?;
            let role = read_role(value.get("role"))?;
            let binding_source = match value.get("binding_source").and_then(Value::as_str) { Some("named_instance") => BuddyBindingSource::NamedInstance, Some("legacy_inline") => BuddyBindingSource::LegacyInline, _ => return Err(BuddyPanelError::MalformedReadback) };
            if !known_roles.insert(role.clone()) {
                return Err(BuddyPanelError::InvalidRole);
            }
            let provider_instance_id = match value.get("provider_instance_id") {
                Some(Value::Null) | None => None,
                Some(value) => Some(read_identifier(Some(value), BuddyPanelError::InvalidInstance)?),
            };
            if let Some(id) = &provider_instance_id {
                if !known_ids.contains(id) {
                    return Err(BuddyPanelError::FallbackNotNamed);
                }
            }
            if (matches!(binding_source, BuddyBindingSource::NamedInstance) && provider_instance_id.is_none()) || (matches!(binding_source, BuddyBindingSource::LegacyInline) && provider_instance_id.is_some()) { return Err(BuddyPanelError::MalformedReadback); }
            Ok(BuddyRoleBinding {
                role,
                binding_source,
                provider_instance_id,
                provider: read_provider(value.get("provider"))?,
                model: read_model(value.get("model"))?,
            })
        })
        .collect::<Result<Vec<_>, BuddyPanelError>>()?;
    if known_roles != BTreeSet::from(["left".to_owned(), "right".to_owned(), "cerebellum".to_owned()]) {
        return Err(BuddyPanelError::InvalidRole);
    }

    let fallback = object
        .get("fallback")
        .and_then(Value::as_object)
        .ok_or(BuddyPanelError::MalformedReadback)?;
    let fallback_max_hops = fallback
        .get("max_hops")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(BuddyPanelError::MalformedReadback)?;
    let selectors = fallback
        .get("selectors")
        .and_then(Value::as_array)
        .ok_or(BuddyPanelError::MalformedReadback)?;
    let mut selected_ids = BTreeSet::new();
    let fallback = selectors
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let value = value.as_object().ok_or(BuddyPanelError::MalformedReadback)?;
            if value.get("position").and_then(Value::as_u64) != Some(index as u64) {
                return Err(BuddyPanelError::MalformedReadback);
            }
            let binding_source = match value.get("binding_source").and_then(Value::as_str) {
                Some("named_instance") => BuddyBindingSource::NamedInstance,
                Some("legacy_inline") => BuddyBindingSource::LegacyInline,
                _ => return Err(BuddyPanelError::MalformedReadback),
            };
            // Legacy inline selectors are deliberately not editable through this GUI.
            let id = match value.get("provider_instance_id") {
                Some(Value::String(_)) => Some(read_identifier(value.get("provider_instance_id"), BuddyPanelError::InvalidInstance)?),
                Some(Value::Null) => None,
                _ => return Err(BuddyPanelError::MalformedReadback),
            };
            if matches!(binding_source, BuddyBindingSource::NamedInstance) && id.as_ref().is_none_or(|id| !known_ids.contains(id)) {
                return Err(BuddyPanelError::FallbackNotNamed);
            }
            if (matches!(binding_source, BuddyBindingSource::NamedInstance) && id.is_none()) || (matches!(binding_source, BuddyBindingSource::LegacyInline) && id.is_some()) { return Err(BuddyPanelError::MalformedReadback); }
            if let Some(id) = &id { if !selected_ids.insert(id.clone()) {
                return Err(BuddyPanelError::DuplicateFallback);
            }}
            Ok(BuddyFallbackEntry {
                position: index,
                binding_source,
                provider_instance_id: id,
                provider: read_provider(value.get("provider"))?,
                model: read_model(value.get("model"))?,
            })
        })
        .collect::<Result<Vec<_>, BuddyPanelError>>()?;

    Ok(BuddyProviderReadback { mode, roles, available_provider_instances, fallback_max_hops, fallback })
}

fn read_role(value: Option<&Value>) -> Result<String, BuddyPanelError> {
    let role = read_identifier(value, BuddyPanelError::InvalidRole)?;
    if matches!(role.as_str(), "left" | "right" | "cerebellum") { Ok(role) } else { Err(BuddyPanelError::InvalidRole) }
}

fn read_provider(value: Option<&Value>) -> Result<String, BuddyPanelError> {
    let provider = read_identifier(value, BuddyPanelError::InvalidProvider)?;
    if provider.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') { Ok(provider) } else { Err(BuddyPanelError::InvalidProvider) }
}

fn read_identifier(value: Option<&Value>, error: BuddyPanelError) -> Result<String, BuddyPanelError> {
    let value = value.and_then(Value::as_str).ok_or(error.clone())?;
    if value.is_empty() || value.len() > MAX_IDENTIFIER_LEN || !value.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')) {
        return Err(error);
    }
    Ok(value.to_owned())
}

fn read_model(value: Option<&Value>) -> Result<Option<String>, BuddyPanelError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(model)) if !model.is_empty() && model.len() <= MAX_MODEL_LEN && model.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':' | '/' | '@')) => Ok(Some(model.clone())),
        _ => Err(BuddyPanelError::MalformedReadback),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuddyProviderCommand {
    Show,
    Set { role: String, provider: String, model: Option<String> },
    Select { role: String, provider_instance_id: String },
    Mode { provider: String, model: Option<String> },
    Preset { name: String, vram: Option<u32>, count: Option<u8> },
    Test { role: String, question: Option<String>, dry_run: bool },
    FallbackReplace { provider_instance_ids: Vec<String> },
    FallbackClear,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuddyCommandPreview { pub argv: Vec<String>, pub requires_live_confirmation: bool }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuddyLiveConfirmation { _private: () }
impl BuddyLiveConfirmation { pub fn confirmed() -> Self { Self { _private: () } } }

/// Creates an exact, harmless preview. A test with no question is always
/// construction-only; a supplied question is always previewed with `--dry-run`.
pub fn preview_buddy_command(command: &BuddyProviderCommand) -> Result<BuddyCommandPreview, BuddyPanelError> {
    let mut argv = vec!["neoth".to_owned(), "buddy".to_owned()];
    let mut requires_live_confirmation = false;
    match command {
        BuddyProviderCommand::Show => argv.extend(["provider".into(), "show".into(), "--output".into(), "json".into()]),
        BuddyProviderCommand::Set { role, provider, model } => { validate_role(role)?; validate_provider(provider)?; argv.extend(["provider".into(), "set".into(), "--role".into(), role.clone(), "--provider".into(), provider.clone()]); append_model(&mut argv, model)?; argv.extend(["--output".into(), "json".into()]); }
        BuddyProviderCommand::Select { role, provider_instance_id } => { validate_role(role)?; validate_identifier(provider_instance_id)?; argv.extend(["provider".into(), "select".into(), "--role".into(), role.clone(), "--provider-instance-id".into(), provider_instance_id.clone(), "--output".into(), "json".into()]); }
        BuddyProviderCommand::Mode { provider, model } => { validate_provider(provider)?; argv.extend(["provider".into(), "mode".into(), "--provider".into(), provider.clone()]); append_model(&mut argv, model)?; argv.extend(["--output".into(), "json".into()]); }
        BuddyProviderCommand::Preset { name, vram, count } => { validate_preset(name)?; argv.extend(["provider".into(), "preset".into(), name.clone()]); if let Some(vram) = vram { argv.extend(["--vram".into(), vram.to_string()]); } if let Some(count) = count { argv.extend(["--count".into(), count.to_string()]); } argv.extend(["--output".into(), "json".into()]); }
        BuddyProviderCommand::Test { role, question, dry_run } => { validate_role(role)?; if let Some(question) = question { validate_question(question)?; requires_live_confirmation = !dry_run; argv.extend(["provider".into(), "test".into(), "--role".into(), role.clone(), format!("--question={question}"), "--dry-run".into(), "--output".into(), "json".into()]); } else { argv.extend(["provider".into(), "test".into(), "--role".into(), role.clone(), "--output".into(), "json".into()]); } }
        BuddyProviderCommand::FallbackReplace { provider_instance_ids } => { validate_fallback(provider_instance_ids)?; argv.extend(["fallback".into(), "replace".into()]); for id in provider_instance_ids { argv.extend(["--provider-instance-id".into(), id.clone()]); } argv.extend(["--output".into(), "json".into()]); }
        BuddyProviderCommand::FallbackClear => argv.extend(["fallback".into(), "clear".into(), "--output".into(), "json".into()]),
    }
    Ok(BuddyCommandPreview { argv, requires_live_confirmation })
}

/// Produces live argv only after explicit UI confirmation.  Live questions
/// remove `--dry-run`; all other commands are returned unchanged.
pub fn live_buddy_command(command: &BuddyProviderCommand, confirmation: Option<BuddyLiveConfirmation>) -> Result<Vec<String>, BuddyPanelError> {
    let preview = preview_buddy_command(command)?;
    if !preview.requires_live_confirmation { return Ok(preview.argv); }
    if confirmation.is_none() { return Err(BuddyPanelError::LiveConfirmationRequired); }
    match command { BuddyProviderCommand::Test { role, question: Some(question), .. } => Ok(vec!["neoth".into(), "buddy".into(), "provider".into(), "test".into(), "--role".into(), role.clone(), format!("--question={question}"), "--output".into(), "json".into()]), _ => Ok(preview.argv) }
}

pub fn fallback_add(current: &[String], id: &str, _max_hops: u32) -> Result<Vec<String>, BuddyPanelError> {
    validate_identifier(id)?;
    let mut next = current.to_vec(); next.push(id.to_owned()); validate_fallback_cap(&next)?; Ok(next)
}
pub fn fallback_remove(current: &[String], index: usize) -> Result<Vec<String>, BuddyPanelError> {
    if index >= current.len() { return Err(BuddyPanelError::InvalidInstance); }
    let mut next = current.to_vec(); next.remove(index); Ok(next)
}
pub fn fallback_move(current: &[String], from: usize, to: usize) -> Result<Vec<String>, BuddyPanelError> {
    if from >= current.len() || to >= current.len() { return Err(BuddyPanelError::InvalidInstance); }
    let mut next = current.to_vec(); let item = next.remove(from); next.insert(to, item); Ok(next)
}

/// Validates a staged fallback queue against the last accepted readback.  The
/// UI calls this before exposing Replace, so free-form or stale instance ids
/// never become a CLI mutation request.
pub fn validate_fallback_selection(readback: &BuddyProviderReadback, ids: &[String]) -> Result<(), BuddyPanelError> {
    validate_fallback_cap(ids)?;
    let named = readback.available_provider_instances.iter().map(|instance| instance.id.as_str()).collect::<BTreeSet<_>>();
    if ids.iter().all(|id| named.contains(id.as_str())) { Ok(()) } else { Err(BuddyPanelError::FallbackNotNamed) }
}

fn validate_role(role: &str) -> Result<(), BuddyPanelError> { read_role(Some(&Value::String(role.to_owned()))).map(|_| ()) }
fn validate_provider(provider: &str) -> Result<(), BuddyPanelError> { read_provider(Some(&Value::String(provider.to_owned()))).map(|_| ()) }
fn validate_identifier(id: &str) -> Result<(), BuddyPanelError> { read_identifier(Some(&Value::String(id.to_owned())), BuddyPanelError::InvalidInstance).map(|_| ()) }
fn validate_preset(name: &str) -> Result<(), BuddyPanelError> { if matches!(name, "local" | "local-reasoning" | "local-abliterated" | "single") { Ok(()) } else { Err(BuddyPanelError::InvalidPreset) } }
fn validate_question(question: &str) -> Result<(), BuddyPanelError> { if question.is_empty() || question.len() > MAX_QUESTION_LEN || question.chars().any(char::is_control) { Err(BuddyPanelError::InvalidQuestion) } else { Ok(()) } }
fn append_model(argv: &mut Vec<String>, model: &Option<String>) -> Result<(), BuddyPanelError> { if let Some(model) = model { if read_model(Some(&Value::String(model.clone())))?.is_none() { return Err(BuddyPanelError::InvalidProvider); } argv.push(format!("--model={model}")); } Ok(()) }
fn validate_fallback(ids: &[String]) -> Result<(), BuddyPanelError> { if ids.is_empty() { return Err(BuddyPanelError::FallbackNotNamed); } validate_fallback_cap(ids) }
fn validate_fallback_cap(ids: &[String]) -> Result<(), BuddyPanelError> { if ids.len() > MAX_DRAFT_FALLBACKS { return Err(BuddyPanelError::TooManyItems); } let mut seen = BTreeSet::new(); for id in ids { validate_identifier(id)?; if !seen.insert(id) { return Err(BuddyPanelError::DuplicateFallback); } } Ok(()) }

/// Parses a small canonical writer receipt without retaining its raw text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuddyOutcomeOperation { Set, Select, Mode, Preset, Test, FallbackReplace, FallbackClear }
impl BuddyOutcomeOperation {
    fn as_str(self) -> &'static str { match self { Self::Set => "set", Self::Select => "select", Self::Mode => "mode", Self::Preset => "preset", Self::Test => "test", Self::FallbackReplace => "fallback_replace", Self::FallbackClear => "fallback_clear" } }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuddyCommandOutcome { pub operation: BuddyOutcomeOperation, pub test_outcome: Option<BuddyTestOutcome> }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuddyTestOutcome { ConstructionOnly, DryRunPreview, LiveCompleted }

/// Accepts a receipt only when the requested canonical writer completed. The
/// caller must then fetch and parse fresh `provider show` state; this receipt
/// alone never changes the visible provider/fallback projection.
pub fn parse_buddy_outcome(raw: &str, expected: BuddyOutcomeOperation) -> Result<BuddyCommandOutcome, BuddyPanelError> {
    let value: Value = serde_json::from_str(raw).map_err(|_| BuddyPanelError::InvalidOutcome)?;
    let object = value.as_object().ok_or(BuddyPanelError::InvalidOutcome)?;
    let receipt = object.get("buddy_gui_receipt").and_then(Value::as_object).ok_or(BuddyPanelError::InvalidOutcome)?;
    if receipt.get("schema_version").and_then(Value::as_u64) != Some(1) || receipt.get("operation").and_then(Value::as_str) != Some(expected.as_str()) { return Err(BuddyPanelError::InvalidOutcome); }
    match expected {
        BuddyOutcomeOperation::Set => { read_role(receipt.get("role"))?; read_provider(receipt.get("provider"))?; read_model(receipt.get("model"))?; read_identifier(receipt.get("mode"), BuddyPanelError::InvalidOutcome)?; }
        BuddyOutcomeOperation::Select => { read_role(receipt.get("role"))?; read_identifier(receipt.get("provider_instance_id"), BuddyPanelError::InvalidInstance)?; read_provider(receipt.get("provider"))?; read_model(receipt.get("model"))?; }
        BuddyOutcomeOperation::Mode => { read_identifier(receipt.get("mode"), BuddyPanelError::InvalidOutcome)?; read_provider(receipt.get("provider"))?; }
        BuddyOutcomeOperation::Preset => { validate_preset(receipt.get("preset").and_then(Value::as_str).ok_or(BuddyPanelError::InvalidOutcome)?)?; read_identifier(receipt.get("mode"), BuddyPanelError::InvalidOutcome)?; receipt.get("changed_roles").and_then(Value::as_array).ok_or(BuddyPanelError::InvalidOutcome)?; }
        BuddyOutcomeOperation::Test => { read_role(receipt.get("role"))?; read_provider(receipt.get("provider"))?; }
        BuddyOutcomeOperation::FallbackReplace | BuddyOutcomeOperation::FallbackClear => { receipt.get("prior_fallback_count").and_then(Value::as_u64).ok_or(BuddyPanelError::InvalidOutcome)?; receipt.get("fallback_count").and_then(Value::as_u64).ok_or(BuddyPanelError::InvalidOutcome)?; receipt.get("max_hops").and_then(Value::as_u64).ok_or(BuddyPanelError::InvalidOutcome)?; let ids = receipt.get("provider_instance_ids").and_then(Value::as_array).ok_or(BuddyPanelError::InvalidOutcome)?; for id in ids { read_identifier(Some(id), BuddyPanelError::InvalidInstance)?; } }
    }
    let test_outcome = match expected { BuddyOutcomeOperation::Test => match receipt.get("outcome").and_then(Value::as_str) { Some("construction_only") => Some(BuddyTestOutcome::ConstructionOnly), Some("dry_run_preview") => Some(BuddyTestOutcome::DryRunPreview), Some("live_completed") => Some(BuddyTestOutcome::LiveCompleted), _ => return Err(BuddyPanelError::InvalidOutcome) }, _ => None };
    Ok(BuddyCommandOutcome { operation: expected, test_outcome })
}

#[cfg(test)]
mod tests {
    use super::*;
    // Exact final backend `buddy_gui` projection fixture; no keys, endpoints, paths, or credential claims.
    const READBACK: &str = r#"{"buddy_gui":{"schema_version":1,"mode":"custom","roles":[{"role":"left","binding_source":"named_instance","provider_instance_id":"route_a","provider":"openai_compat","model":"a-model"},{"role":"right","binding_source":"legacy_inline","provider_instance_id":null,"provider":"claude_cli","model":null},{"role":"cerebellum","binding_source":"named_instance","provider_instance_id":"route_a","provider":"openai_compat","model":"a-model"}],"available_provider_instances":[{"id":"route_a","provider":"openai_compat","model":"a-model"}],"fallback":{"max_hops":7,"selectors":[{"position":0,"binding_source":"named_instance","provider_instance_id":"route_a","provider":"openai_compat","model":"a-model"},{"position":1,"binding_source":"legacy_inline","provider_instance_id":null,"provider":"claude_cli","model":"legacy"}]}}}"#;
    const BACKEND_PROJECTION_FIXTURE: &str = r#"{"schema_version":1,"mode":"custom","roles":[{"role":"left","binding_source":"named_instance","provider_instance_id":"route_a","provider":"openai_compat","model":"a-model"},{"role":"right","binding_source":"named_instance","provider_instance_id":"route_b","provider":"claude_cli","model":"b-model"},{"role":"cerebellum","binding_source":"named_instance","provider_instance_id":"route_a","provider":"openai_compat","model":"a-model"}],"available_provider_instances":[{"id":"route_a","provider":"openai_compat","model":"a-model"},{"id":"route_b","provider":"claude_cli","model":"b-model"}],"fallback":{"max_hops":7,"selectors":[{"position":0,"binding_source":"named_instance","provider_instance_id":"route_b","provider":"claude_cli","model":"b-model"},{"position":1,"binding_source":"named_instance","provider_instance_id":"route_a","provider":"openai_compat","model":"a-model"}]}}"#;
    #[test] fn consumes_exact_backend_projection_fixture() { let raw = format!(r#"{{"buddy_gui":{BACKEND_PROJECTION_FIXTURE}}}"#); let snap = parse_buddy_provider_readback(&raw).unwrap(); assert_eq!(snap.fallback.iter().filter_map(|entry| entry.provider_instance_id.as_deref()).collect::<Vec<_>>(), ["route_b", "route_a"]); }
    #[test] fn backend_projection_is_redacted_and_keeps_legacy_context() { let snap = parse_buddy_provider_readback(READBACK).unwrap(); assert_eq!(snap.mode, "custom"); assert_eq!(snap.fallback[1].provider_instance_id, None); assert_eq!(snap.fallback[1].binding_source, BuddyBindingSource::LegacyInline); }
    #[test] fn malformed_readback_never_replaces_display() { assert!(parse_buddy_provider_readback("not json").is_err()); }
    #[test] fn question_preview_is_dry_run_and_live_needs_confirmation() { let command = BuddyProviderCommand::Test { role: "left".into(), question: Some("hello".into()), dry_run: false }; let preview = preview_buddy_command(&command).unwrap(); assert!(preview.argv.contains(&"--dry-run".into())); assert!(live_buddy_command(&command, None).is_err()); assert!(!live_buddy_command(&command, Some(BuddyLiveConfirmation::confirmed())).unwrap().contains(&"--dry-run".into())); }
    #[test] fn construction_test_and_named_fallback_use_exact_argv() { assert_eq!(preview_buddy_command(&BuddyProviderCommand::Test { role: "left".into(), question: None, dry_run: false }).unwrap().argv, ["neoth", "buddy", "provider", "test", "--role", "left", "--output", "json"]); assert_eq!(preview_buddy_command(&BuddyProviderCommand::FallbackReplace { provider_instance_ids: vec!["a".into(), "b".into()] }).unwrap().argv, ["neoth", "buddy", "fallback", "replace", "--provider-instance-id", "a", "--provider-instance-id", "b", "--output", "json"]); }
    #[test] fn optional_model_and_preset_tuning_have_exact_argv() { assert_eq!(preview_buddy_command(&BuddyProviderCommand::Set { role: "left".into(), provider: "openai_api".into(), model: Some("gpt-4o".into()) }).unwrap().argv, ["neoth", "buddy", "provider", "set", "--role", "left", "--provider", "openai_api", "--model=gpt-4o", "--output", "json"]); assert_eq!(preview_buddy_command(&BuddyProviderCommand::Preset { name: "local-abliterated".into(), vram: Some(4096), count: Some(2) }).unwrap().argv, ["neoth", "buddy", "provider", "preset", "local-abliterated", "--vram", "4096", "--count", "2", "--output", "json"]); }
    #[test] fn exact_argv_covers_show_select_mode_and_clear() { assert_eq!(preview_buddy_command(&BuddyProviderCommand::Show).unwrap().argv, ["neoth", "buddy", "provider", "show", "--output", "json"]); assert_eq!(preview_buddy_command(&BuddyProviderCommand::Select { role: "right".into(), provider_instance_id: "route_a".into() }).unwrap().argv, ["neoth", "buddy", "provider", "select", "--role", "right", "--provider-instance-id", "route_a", "--output", "json"]); assert_eq!(preview_buddy_command(&BuddyProviderCommand::Mode { provider: "local_qwen".into(), model: None }).unwrap().argv, ["neoth", "buddy", "provider", "mode", "--provider", "local_qwen", "--output", "json"]); assert_eq!(preview_buddy_command(&BuddyProviderCommand::FallbackClear).unwrap().argv, ["neoth", "buddy", "fallback", "clear", "--output", "json"]); }
    #[test] fn literal_question_is_not_reinterpreted_as_dry_run_and_empty_replace_is_refused() { let command = BuddyProviderCommand::Test { role: "left".into(), question: Some("--dry-run".into()), dry_run: false }; assert!(preview_buddy_command(&command).unwrap().argv.contains(&"--question=--dry-run".into())); assert!(live_buddy_command(&command, Some(BuddyLiveConfirmation::confirmed())).unwrap().contains(&"--question=--dry-run".into())); assert!(preview_buddy_command(&BuddyProviderCommand::FallbackReplace { provider_instance_ids: vec![] }).is_err()); }
    #[test] fn queue_helpers_preserve_unique_order_and_named_membership() { let queued = fallback_add(&["a".into()], "b", 2).unwrap(); assert_eq!(fallback_move(&queued, 1, 0).unwrap(), ["b", "a"]); assert!(fallback_add(&queued, "a", 2).is_err()); assert_eq!(fallback_remove(&queued, 0).unwrap(), ["b"]); let snap = parse_buddy_provider_readback(READBACK).unwrap(); assert!(validate_fallback_selection(&snap, &["route_a".into()]).is_ok()); assert!(validate_fallback_selection(&snap, &["unknown".into()]).is_err()); }
    #[test] fn outcome_is_typed_and_operation_bound() { let receipt = r#"{"buddy_gui_receipt":{"schema_version":1,"operation":"test","role":"left","provider":"openai_api","outcome":"dry_run_preview"}}"#; assert_eq!(parse_buddy_outcome(receipt, BuddyOutcomeOperation::Test).unwrap().operation, BuddyOutcomeOperation::Test); assert!(parse_buddy_outcome(receipt, BuddyOutcomeOperation::Set).is_err()); }
}
