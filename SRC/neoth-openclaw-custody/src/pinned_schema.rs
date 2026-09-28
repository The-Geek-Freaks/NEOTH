//! Frozen W169 OpenClaw channel schema inventory.
//!
//! The fixture is a hosted, source-derived diagnostic input. This module only
//! validates and looks up its structural paths; it never evaluates upstream
//! JavaScript or invents descendants for open schema subtrees.

use anyhow::{Context as _, Result, bail, ensure};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::sync::OnceLock;

pub const FIXTURE_SHA256: &str = "A7E60AFBB1E0D013100EE8C30F5237307E6552923F34B55A39B2DC1263B0283F";
pub const POLICY_SHA256: &str = "1342AE1183ECB95E429983A5AD31C7A3A4D97D6534CEE7FF111B02D05AEC23D6";
pub const FIXTURE_VERSION: u64 = 1;
pub const OPENCLAW_REPOSITORY: &str = "openclaw/openclaw";
pub const OPENCLAW_METADATA_PATH: &str = "src/config/bundled-channel-config-metadata.generated.ts";
pub const OPENCLAW_COMMIT: &str = "4c667aac8859114bd8f0a589ac6cd1de8bfe1474";
const EXPECTED_ROW_COUNT: usize = 3252;
const EXPECTED_OPAQUE_ROW_COUNT: usize = 22;
const FIXTURE_BYTES: &str = include_str!("fixtures/openclaw_channel_schema_v1.json");
const POLICY_BYTES: &str = include_str!("fixtures/openclaw_channel_schema_migration_policy_v1.json");

const EXPECTED_CHANNELS: &[&str] = &[
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

#[derive(Clone, Copy, Debug)]
pub enum PathPart<'a> {
    Key(&'a str),
    Index,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchemaScope {
    TypedLeaf,
    OpaqueSubtree,
    AccountContainer,
}

#[derive(Clone, Debug)]
pub struct SchemaMatch {
    pub schema_id: String,
    pub path_template: String,
    pub scope: SchemaScope,
    pub disposition: String,
    pub action_id: String,
    pub target_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    channels: Vec<Channel>,
    schema_version: u64,
    source: Source,
    uncovered_blockers: Vec<UncoveredBlocker>,
    #[serde(skip, default)]
    policy: Policy,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    commit: String,
    metadata_path: String,
    repository: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Channel {
    account_template_present: bool,
    aliases: Vec<String>,
    blockers: Vec<ChannelBlocker>,
    channel_id: String,
    default_account_present: bool,
    leaves: Vec<SchemaLeaf>,
    plugin_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelBlocker {
    path: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UncoveredBlocker {
    channel: String,
    path: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaLeaf {
    disposition: Option<String>,
    json_type: String,
    path_template: String,
    scope: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy { policy_version: u64, policy_name: String, source: Source, rows: Vec<PolicyRow>, #[serde(default)] synthetic: Vec<SyntheticPolicy> }
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyRow { channel_id: String, path_template: String, json_type: String, scope: String, disposition: String, action_id: String, #[serde(default)] target_path: Option<String> }
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SyntheticPolicy { kind: String, #[serde(default)] channel_id: Option<String>, #[serde(default)] path_template: Option<String>, #[serde(default)] json_type: Option<String>, disposition: String, action_id: String, #[serde(default)] target_path: Option<String> }

static FIXTURE: OnceLock<Result<Fixture, String>> = OnceLock::new();

pub fn validate_pinned_schema() -> Result<()> {
    fixture().map(|_| ())
}

pub fn lookup(
    channel: &str,
    path: &[PathPart<'_>],
    actual_json_type: &str,
) -> Result<Option<SchemaMatch>> {
    let fixture = fixture()?;
    let Some(channel_schema) = fixture
        .channels
        .iter()
        .find(|item| item.channel_id == channel)
    else {
        return Ok(None);
    };

    if actual_json_type == "secret_ref" {
        if let Some(schema) = secret_ref_match(fixture, channel, channel_schema, path)? {
            return Ok(Some(schema));
        }
    } else {
        let mut candidates = channel_schema
            .leaves
            .iter()
            .filter(|row| row.scope.is_none() && template_matches(row, path, false))
            .filter(|row| json_type_matches(row.json_type.as_str(), actual_json_type));
        if let Some(first) = candidates.next() {
            // The validator guarantees same path/type rows cannot disagree in
            // their outcome. Composition branches are schema provenance, not
            // runtime paths.
            return Ok(Some(schema_match(channel, first, SchemaScope::TypedLeaf, policy_row(fixture, channel, first)?)));
        }
    }

    let opaque = channel_schema.leaves.iter().find(|row| {
        row.scope.as_deref() == Some("opaque_subtree") && template_matches(row, path, true)
    });
    Ok(opaque.map(|row| schema_match(channel, row, SchemaScope::OpaqueSubtree, policy_row(fixture, channel, row).expect("validated policy row"))))
}

/// Whether a container matching an opaque subtree has an explicitly typed
/// descendant in the pinned fixture. Callers use this to traverse known nested
/// fields while still blocking unknown dynamic map children at their own path.
pub fn has_typed_descendant(channel: &str, path: &[PathPart<'_>]) -> Result<bool> {
    let fixture = fixture()?;
    let Some(channel_schema) = fixture
        .channels
        .iter()
        .find(|item| item.channel_id == channel)
    else {
        return Ok(false);
    };
    Ok(channel_schema
        .leaves
        .iter()
        .any(|row| row.scope.is_none() && template_has_prefix(row, path)))
}

fn secret_ref_match(
    fixture: &Fixture,
    channel: &str,
    channel_schema: &Channel,
    path: &[PathPart<'_>],
) -> Result<Option<SchemaMatch>> {
    for id_row in channel_schema.leaves.iter().filter(|row| {
        row.scope.is_none()
            && row.json_type == "string"
            && is_object_composition_member(row.path_template.as_str())
            && row.path_template.ends_with(".id")
    }) {
        let parent = id_row.path_template.strip_suffix(".id")?;
        let mut member_path = path.to_vec();
        member_path.push(PathPart::Key("id"));
        if !template_matches(id_row, &member_path, false) {
            continue;
        }
        if ["source", "provider"].iter().all(|member| {
            let mut member_path = path.to_vec();
            member_path.push(PathPart::Key(member));
            let expected_template = format!("{parent}.{member}");
            channel_schema.leaves.iter().any(|row| {
                row.scope.is_none()
                    && row.json_type == "string"
                    && row.path_template.as_str() == expected_template.as_str()
                    && template_matches(row, &member_path, false)
            })
        }) {
            let synthetic = secret_ref_family_policy(fixture, channel, parent)?;
            return Ok(Some(SchemaMatch {
                schema_id: format!("w169:{channel}:{parent}:secret_ref"),
                path_template: parent.to_string(),
                scope: SchemaScope::TypedLeaf,
                // A valid SecretRef never imports its inline scalar value.
                // Keep the composed family's exact target provenance, but bind
                // this synthetic runtime shape to the credential-flow policy.
                disposition: synthetic.disposition.clone(),
                action_id: synthetic.action_id.clone(),
                target_path: synthetic.target_path.clone(),
            }));
        }
    }
    Ok(None)
}

/// A SecretRef is admissible only for an exact pinned object-composition
/// family.  The numeric `anyOf` branch is schema provenance, not a stable
/// semantic discriminator: Google Chat's current service-account family is
/// `anyOf:2`, while other supported families use other ordinals.
fn is_object_composition_member(template: &str) -> bool {
    template
        .strip_suffix(".id")
        .and_then(|parent| parent.rsplit('.').next())
        .is_some_and(|component| component.contains("{anyOf:") && component.contains("{oneOf:"))
}

/// Account objects are structural records, not values copied into a target.
/// The upstream fixture records account-template presence at the channel level,
/// so this binding remains traceable even though an account object itself has
/// no primitive `json_type` row.
pub fn account_container(channel: &str) -> Result<Option<SchemaMatch>> {
    let fixture = fixture()?;
    let kind = if crate::alias_target(channel).is_some() {
        "account_container"
    } else {
        "account_container_unmapped"
    };
    let synthetic = synthetic_policy(fixture, kind)?;
    Ok(fixture
        .channels
        .iter()
        .find(|item| item.channel_id == channel && item.account_template_present)
        .map(|_| SchemaMatch {
            schema_id: format!("w169:{channel}:accounts.{{key}}:account_container"),
            path_template: "accounts.{key}".to_string(),
            scope: SchemaScope::AccountContainer,
            disposition: synthetic.disposition.clone(),
            action_id: synthetic.action_id.clone(),
            target_path: None,
        }))
}

pub fn whatsapp_auth_dir_legacy() -> Result<SchemaMatch> {
    let fixture = fixture()?;
    let policy = synthetic_policy(fixture, "whatsapp_auth_dir_string")?;
    Ok(SchemaMatch { schema_id: "w1835:whatsapp:authDir:legacy_string".to_string(), path_template: "authDir".to_string(), scope: SchemaScope::TypedLeaf, disposition: policy.disposition.clone(), action_id: policy.action_id.clone(), target_path: None })
}

fn fixture() -> Result<&'static Fixture> {
    FIXTURE
        .get_or_init(|| load_fixture().map_err(|error| format!("{error:#}")))
        .as_ref()
        .map_err(|error| anyhow::anyhow!("invalid pinned W169 schema fixture: {error}"))
}

fn load_fixture() -> Result<Fixture> {
    let actual = format!("{:X}", Sha256::digest(FIXTURE_BYTES.as_bytes()));
    ensure!(
        actual == FIXTURE_SHA256,
        "W169 schema fixture digest mismatch"
    );
    let mut fixture: Fixture =
        serde_json::from_str(FIXTURE_BYTES).context("parse pinned W169 schema fixture")?;
    let policy_actual = format!("{:X}", Sha256::digest(POLICY_BYTES.as_bytes()));
    ensure!(policy_actual == POLICY_SHA256, "W1835 migration policy digest mismatch");
    let policy: Policy = serde_json::from_str(POLICY_BYTES).context("parse W1835 migration policy")?;
    ensure!(policy.policy_version == 1 && policy.policy_name == "neoth-openclaw-channel-schema-migration-policy-v1", "unexpected W1835 policy version");
    ensure!(policy.source.repository == fixture.source.repository && policy.source.commit == fixture.source.commit && policy.source.metadata_path == fixture.source.metadata_path, "W1835 policy source pin mismatch");
    fixture.policy = policy;
    validate_synthetic_policy(&fixture)?;
    ensure!(
        fixture.schema_version == FIXTURE_VERSION,
        "unexpected W169 schema fixture version"
    );
    ensure!(
        fixture.source.repository == OPENCLAW_REPOSITORY,
        "unexpected W169 source repository"
    );
    ensure!(
        fixture.source.commit == OPENCLAW_COMMIT,
        "unexpected W169 source commit"
    );
    ensure!(
        fixture.source.metadata_path == OPENCLAW_METADATA_PATH,
        "unexpected W169 metadata path"
    );
    for blocker in &fixture.uncovered_blockers {
        let _ = (&blocker.channel, &blocker.path, &blocker.reason);
    }
    ensure!(
        fixture.uncovered_blockers.is_empty(),
        "W169 schema fixture has uncovered blockers"
    );

    let expected: BTreeSet<_> = EXPECTED_CHANNELS.iter().copied().collect();
    let actual_channels: BTreeSet<_> = fixture
        .channels
        .iter()
        .map(|item| item.channel_id.as_str())
        .collect();
    ensure!(
        actual_channels == expected,
        "W169 schema fixture channel inventory drift"
    );
    ensure!(
        fixture.channels.len() == EXPECTED_CHANNELS.len(),
        "duplicate W169 channel IDs"
    );

    let mut identities = BTreeSet::new();
    let mut rows = 0usize;
    let mut opaque_rows = 0usize;
    for channel in &fixture.channels {
        let _ = (
            &channel.aliases,
            channel.default_account_present,
            &channel.plugin_id,
        );
        if let Some(blocker) = channel.blockers.first() {
            let _ = (&blocker.path, &blocker.reason);
            bail!("W169 fixture retains legacy channel blocker outside normalized rows");
        }
        for row in &channel.leaves {
            rows += 1;
            validate_template(row.path_template.as_str())?;
            let identity = format!(
                "{}\u{1f}{}\u{1f}{}",
                channel.channel_id, row.path_template, row.json_type
            );
            ensure!(
                identities.insert(identity),
                "duplicate W169 schema row identity"
            );
            match row.scope.as_deref() {
                None => {
                    ensure!(
                        row.json_type != "any",
                        "typed W169 row cannot have json_type any"
                    );
                }
                Some("opaque_subtree") => {
                    opaque_rows += 1;
                    ensure!(
                        row.json_type == "any",
                        "opaque W169 row must have json_type any"
                    );
                    ensure!(
                        row.disposition.as_deref() == Some("blocked_requires_explicit_leaf_mapping"),
                        "opaque W169 row disposition drift"
                    );
                }
                Some(other) => bail!("unknown W169 schema scope `{other}`"),
            }
            let policy = policy_row(&fixture, channel.channel_id.as_str(), row)?;
            ensure!(valid_policy_outcome(&policy.disposition, &policy.action_id, policy.target_path.as_deref()), "invalid W1835 policy outcome");
        }
        if channel.account_template_present {
            ensure!(
                channel
                    .leaves
                    .iter()
                    .any(|row| row.path_template.starts_with("accounts.{key}")),
                "account-template channel lacks accounts.{{key}} schema row"
            );
        }
    }
    ensure!(rows == EXPECTED_ROW_COUNT, "W169 schema row count drift");
    ensure!(fixture.policy.rows.len() == rows, "W1835 policy has extra or missing exact rows");
    ensure!(
        opaque_rows == EXPECTED_OPAQUE_ROW_COUNT,
        "W169 opaque schema row count drift"
    );
    Ok(fixture)
}

fn validate_template(template: &str) -> Result<()> {
    ensure!(
        !template.is_empty() && !template.starts_with('.') && !template.ends_with('.'),
        "invalid empty W169 path template"
    );
    for component in template.split('.') {
        ensure!(!component.is_empty(), "invalid empty W169 path component");
        let stripped = strip_composition(component);
        ensure!(
            !stripped.is_empty() || component.contains("{anyOf:") || component.contains("{oneOf:"),
            "invalid W169 path component"
        );
        ensure!(
            stripped == "{key}"
                || stripped == "{key}[]"
                || (!stripped.contains('{') && !stripped.contains('}')),
            "invalid W169 path placeholder"
        );
    }
    Ok(())
}

fn policy_row<'a>(fixture: &'a Fixture, channel: &str, row: &SchemaLeaf) -> Result<&'a PolicyRow> {
    let scope = row.scope.as_deref().unwrap_or("typed_leaf");
    let matches: Vec<_> = fixture.policy.rows.iter().filter(|policy| policy.channel_id == channel && policy.path_template == row.path_template && policy.json_type == row.json_type && policy.scope == scope).collect();
    ensure!(matches.len() == 1, "W1835 policy exact join missing or duplicate");
    Ok(matches[0])
}

fn valid_policy_outcome(disposition: &str, action: &str, target: Option<&str>) -> bool {
    let needs_target = matches!(disposition, "mapped" | "needs_secret");
    let pair = matches!((disposition, action),
        ("mapped", "direct_credential_mapping") | ("needs_secret", "neoth_credential_flow") |
        ("needs_relink", "relink_required") | ("needs_runtime", "runtime_prerequisite_required") |
        ("unsupported", "requires_target_contract" | "requires_neoth_adapter" | "requires_account_scoped_runtime") |
        ("unknown", "blocked_requires_explicit_leaf_mapping" | "blocked_requires_explicit_account_mapping"));
    pair && if needs_target { target.is_some_and(|value| !value.is_empty()) } else { target.is_none() }
}

fn synthetic_policy<'a>(fixture: &'a Fixture, kind: &str) -> Result<&'a SyntheticPolicy> {
    let matches: Vec<_> = fixture.policy.synthetic.iter().filter(|item| item.kind == kind).collect();
    ensure!(matches.len() == 1, "missing or duplicate W1835 synthetic policy {kind}");
    Ok(matches[0])
}

fn secret_ref_family_policy<'a>(
    fixture: &'a Fixture,
    channel: &str,
    path_template: &str,
) -> Result<&'a SyntheticPolicy> {
    let matches: Vec<_> = fixture
        .policy
        .synthetic
        .iter()
        .filter(|item| {
            item.kind == "secret_ref_family"
                && item.channel_id.as_deref() == Some(channel)
                && item.path_template.as_deref() == Some(path_template)
        })
        .collect();
    ensure!(
        matches.len() == 1,
        "missing or duplicate W1835 SecretRef family policy {channel}:{path_template}"
    );
    Ok(matches[0])
}

fn validate_synthetic_policy(fixture: &Fixture) -> Result<()> {
    let unmapped = synthetic_policy(fixture, "account_container_unmapped")?;
    ensure!(
        unmapped.channel_id.is_none()
            && unmapped.path_template.is_none()
            && unmapped.json_type.is_none()
            && unmapped.target_path.is_none()
            && unmapped.disposition == "unknown"
            && unmapped.action_id == "blocked_requires_explicit_account_mapping",
        "invalid W1835 unmapped account-container policy"
    );
    let account = synthetic_policy(fixture, "account_container")?;
    ensure!(
        account.channel_id.is_none()
            && account.path_template.is_none()
            && account.json_type.is_none()
            && valid_policy_outcome(
                &account.disposition,
                &account.action_id,
                account.target_path.as_deref(),
            )
            && account.disposition == "unsupported"
            && account.action_id == "requires_account_scoped_runtime",
        "invalid W1835 account-container policy"
    );
    let legacy = synthetic_policy(fixture, "whatsapp_auth_dir_string")?;
    ensure!(
        legacy.channel_id.as_deref() == Some("whatsapp")
            && legacy.path_template.as_deref() == Some("authDir")
            && legacy.json_type.as_deref() == Some("string")
            && valid_policy_outcome(
                &legacy.disposition,
                &legacy.action_id,
                legacy.target_path.as_deref(),
            )
            && legacy.disposition == "needs_relink"
            && legacy.action_id == "relink_required",
        "invalid W1835 authDir legacy policy"
    );

    let mut expected = BTreeSet::new();
    for channel in &fixture.channels {
        for id_row in channel.leaves.iter().filter(|row| {
            row.scope.is_none()
                && row.json_type == "string"
                && row.path_template.ends_with(".id")
                && is_object_composition_member(row.path_template.as_str())
        }) {
            let parent = id_row
                .path_template
                .strip_suffix(".id")
                .context("W1835 SecretRef id template is malformed")?;
            let has_trio = ["source", "provider"].iter().all(|member| {
                let expected_template = format!("{parent}.{member}");
                channel.leaves.iter().any(|row| {
                    row.scope.is_none()
                        && row.json_type == "string"
                        && row.path_template == expected_template
                })
            });
            if has_trio {
                expected.insert((channel.channel_id.clone(), parent.to_string()));
            }
        }
    }

    let mut actual = BTreeSet::new();
    for item in fixture
        .policy
        .synthetic
        .iter()
        .filter(|item| item.kind == "secret_ref_family")
    {
        let channel = item
            .channel_id
            .as_deref()
            .context("W1835 SecretRef family missing channel")?;
        let path_template = item
            .path_template
            .as_deref()
            .context("W1835 SecretRef family missing path")?;
        ensure!(
            item.json_type.is_none()
                && valid_policy_outcome(
                    &item.disposition,
                    &item.action_id,
                    item.target_path.as_deref(),
                )
                && is_object_composition_member(&format!("{path_template}.id")),
            "invalid W1835 SecretRef family policy {channel}:{path_template}"
        );
        let identity = (channel.to_string(), path_template.to_string());
        ensure!(
            actual.insert(identity.clone()),
            "duplicate W1835 SecretRef family policy {channel}:{path_template}"
        );
        ensure!(
            expected.contains(&identity),
            "extra W1835 SecretRef family policy"
        );
    }
    ensure!(
        actual == expected,
        "missing W1835 SecretRef family policy"
    );
    ensure!(
        fixture.policy.synthetic.len() == expected.len() + 3,
        "extra W1835 synthetic policy"
    );
    Ok(())
}

fn schema_match(channel: &str, row: &SchemaLeaf, scope: SchemaScope, policy: &PolicyRow) -> SchemaMatch {
    SchemaMatch {
        schema_id: format!("w169:{channel}:{}:{}", row.path_template, row.json_type),
        path_template: row.path_template.clone(),
        scope,
        disposition: policy.disposition.clone(),
        action_id: policy.action_id.clone(),
        target_path: policy.target_path.clone(),
    }
}

fn template_parts(row: &SchemaLeaf) -> Vec<TemplatePart> {
    let mut expected = Vec::new();
    for component in row.path_template.split('.') {
        let component = strip_composition(component);
        if component.is_empty() {
            continue;
        }
        if let Some(base) = component.strip_suffix("[]") {
            expected.push(TemplatePart::Key(base.to_string()));
            expected.push(TemplatePart::Index);
        } else {
            expected.push(TemplatePart::Key(component));
        }
    }
    expected
}

fn template_matches(row: &SchemaLeaf, path: &[PathPart<'_>], prefix: bool) -> bool {
    let expected = template_parts(row);
    if prefix {
        if path.len() < expected.len() {
            return false;
        }
    } else if path.len() != expected.len() {
        return false;
    }
    expected
        .iter()
        .zip(path)
        .all(|(expected, actual)| template_part_matches(expected, actual))
}

fn template_has_prefix(row: &SchemaLeaf, path: &[PathPart<'_>]) -> bool {
    let expected = template_parts(row);
    path.len() < expected.len()
        && expected
            .iter()
            .zip(path)
            .all(|(expected, actual)| template_part_matches(expected, actual))
}

fn template_part_matches(expected: &TemplatePart, actual: &PathPart<'_>) -> bool {
    match (expected, actual) {
        (TemplatePart::Index, PathPart::Index) => true,
        (TemplatePart::Key(expected), PathPart::Key(_)) if expected == "{key}" => true,
        (TemplatePart::Key(expected), PathPart::Key(actual)) => expected == actual,
        _ => false,
    }
}

enum TemplatePart {
    Key(String),
    Index,
}

fn strip_composition(component: &str) -> String {
    let mut remaining = component;
    let mut output = String::new();
    while let Some(start) = remaining
        .find("{anyOf:")
        .or_else(|| remaining.find("{oneOf:"))
    {
        output.push_str(&remaining[..start]);
        let Some(end) = remaining[start..].find('}') else {
            output.push_str(&remaining[start..]);
            return output;
        };
        remaining = &remaining[start + end + 1..];
    }
    output.push_str(remaining);
    output
}

fn json_type_matches(expected: &str, actual: &str) -> bool {
    expected == actual || (expected == "number" && actual == "integer")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    enum SamplePart {
        Key(String),
        Index,
    }

    fn sample_parts(template: &str) -> Vec<SamplePart> {
        let mut output = Vec::new();
        for component in template.split('.') {
            let component = strip_composition(component);
            if component.is_empty() {
                continue;
            }
            if let Some(base) = component.strip_suffix("[]") {
                output.push(SamplePart::Key(sample_key(base)));
                output.push(SamplePart::Index);
            } else {
                output.push(SamplePart::Key(sample_key(component.as_str())));
            }
        }
        output
    }

    fn sample_key(value: &str) -> String {
        if value == "{key}" {
            "fixture_key".to_string()
        } else {
            value.to_string()
        }
    }

    fn ledger_path(channel: &str, template: &str) -> Vec<crate::PathPart> {
        let mut path = vec![
            crate::PathPart::Key("channels".to_string()),
            crate::PathPart::Key(channel.to_string()),
        ];
        path.extend(sample_parts(template).into_iter().map(|part| match part {
            SamplePart::Key(key) => crate::PathPart::Key(key),
            SamplePart::Index => crate::PathPart::Index(0),
        }));
        path
    }

    #[test]
    fn every_frozen_policy_row_agrees_with_the_real_runtime_ledger() {
        let fixture = fixture().unwrap();
        let mut checked = 0;
        for channel in &fixture.channels {
            for row in &channel.leaves {
                let value = match row.json_type.as_str() {
                    "string" => serde_json::json!("fixture-value"),
                    "integer" => serde_json::json!(1),
                    "number" => serde_json::json!(1.5),
                    "boolean" | "any" => serde_json::json!(true),
                    "null" => serde_json::Value::Null,
                    other => panic!("unhandled pinned type {other}"),
                };
                let path = ledger_path(&channel.channel_id, &row.path_template);
                let entry = crate::classify_leaf(&value, &path, false, false)
                    .unwrap_or_else(|error| panic!("{}:{}: {error:#}", channel.channel_id, row.path_template));
                let policy = policy_row(fixture, &channel.channel_id, row).unwrap();
                assert_eq!(entry.disposition.as_str(), policy.disposition, "{}:{}", channel.channel_id, row.path_template);
                assert_eq!(entry.target_path, policy.target_path);
                assert_eq!(entry.schema_binding.unwrap().action_id, policy.action_id);
                checked += 1;
            }
        }
        assert_eq!(checked, EXPECTED_ROW_COUNT);
    }

    #[test]
    fn every_secret_ref_family_and_account_container_agrees_with_runtime() {
        let fixture = fixture().unwrap();
        let value = serde_json::json!({"source": "env", "provider": "default", "id": "PRIVATE_FIXTURE"});
        let mut checked = 0;
        for policy in fixture.policy.synthetic.iter().filter(|item| item.kind == "secret_ref_family") {
            let channel = policy.channel_id.as_deref().unwrap();
            let template = policy.path_template.as_deref().unwrap();
            let entry = crate::classify_leaf(&value, &ledger_path(channel, template), true, false)
                .unwrap_or_else(|error| panic!("{channel}:{template}: {error:#}"));
            assert_eq!(entry.disposition.as_str(), policy.disposition);
            assert_eq!(entry.target_path, policy.target_path);
            assert!(entry.sensitive && entry.effective_value_sha256.is_none());
            assert_eq!(entry.schema_binding.as_ref().unwrap().action_id, policy.action_id);
            assert!(!serde_json::to_string(&entry).unwrap().contains("PRIVATE_FIXTURE"));
            checked += 1;
        }
        assert_eq!(checked, 150);
        for channel in fixture.channels.iter().filter(|item| item.account_template_present) {
            let entry = crate::classify_account_container(&ledger_path(&channel.channel_id, "accounts.{key}")).unwrap();
            let kind = if crate::alias_target(&channel.channel_id).is_some() { "account_container" } else { "account_container_unmapped" };
            let policy = synthetic_policy(fixture, kind).unwrap();
            assert_eq!(entry.disposition.as_str(), policy.disposition);
            assert_eq!(entry.schema_binding.unwrap().action_id, policy.action_id);
        }
    }

    #[test]
    fn synthetic_policy_rejects_missing_extra_duplicate_and_incompatible_records() {
        for mutation in 0..4 {
            let mut fixture: Fixture = serde_json::from_str(FIXTURE_BYTES).unwrap();
            let mut policy: serde_json::Value = serde_json::from_str(POLICY_BYTES).unwrap();
            let records = policy["synthetic"].as_array_mut().unwrap();
            let index = records.iter().position(|row| row["kind"] == "secret_ref_family").unwrap();
            match mutation {
                0 => { records.remove(index); }
                1 => { let extra = records[index].clone(); records.push(extra); }
                2 => { records[index]["path_template"] = serde_json::json!("invented{anyOf:1}{oneOf:0}"); }
                3 => { records[index]["action_id"] = serde_json::json!("relink_required"); }
                _ => unreachable!(),
            }
            fixture.policy = serde_json::from_value(policy).unwrap();
            assert!(validate_synthetic_policy(&fixture).is_err(), "mutation {mutation}");
        }
    }

    #[test]
    fn hosted_fixture_has_the_frozen_inventory_and_opaque_boundary() {
        validate_pinned_schema().unwrap();
        let typed = lookup("telegram", &[PathPart::Key("enabled")], "boolean")
            .unwrap()
            .unwrap();
        assert_eq!(typed.scope, SchemaScope::TypedLeaf);
        assert_eq!(typed.path_template, "enabled");

        let opaque = lookup(
            "matrix",
            &[
                PathPart::Key("accounts"),
                PathPart::Key("work"),
                PathPart::Key("futureOption"),
            ],
            "boolean",
        )
        .unwrap()
        .unwrap();
        assert_eq!(opaque.scope, SchemaScope::OpaqueSubtree);
        assert_eq!(opaque.path_template, "accounts.{key}");
    }

    #[test]
    fn every_frozen_row_resolves_or_blocks_at_its_exact_structural_path() {
        let fixture = fixture().unwrap();
        let mut rows = 0usize;
        let mut opaque = 0usize;
        let mut saw_map = false;
        let mut saw_array = false;
        let mut saw_composition = false;
        for channel in &fixture.channels {
            for row in &channel.leaves {
                rows += 1;
                saw_map |= row.path_template.contains("{key}");
                saw_array |= row.path_template.contains("[]");
                saw_composition |=
                    row.path_template.contains("{anyOf:") || row.path_template.contains("{oneOf:");
                let owned = sample_parts(row.path_template.as_str());
                let parts: Vec<_> = owned
                    .iter()
                    .map(|part| match part {
                        SamplePart::Key(key) => PathPart::Key(key.as_str()),
                        SamplePart::Index => PathPart::Index,
                    })
                    .collect();
                let observed = if row.scope.as_deref() == Some("opaque_subtree") {
                    "boolean"
                } else {
                    row.json_type.as_str()
                };
                let matched = lookup(channel.channel_id.as_str(), &parts, observed)
                    .unwrap()
                    .unwrap_or_else(|| {
                        panic!(
                            "fixture row did not resolve: {}:{}",
                            channel.channel_id, row.path_template
                        )
                    });
                match row.scope.as_deref() {
                    Some("opaque_subtree") => {
                        opaque += 1;
                        assert_eq!(matched.scope, SchemaScope::OpaqueSubtree);
                        assert_eq!(
                            row.disposition.as_deref().unwrap(),
                            "blocked_requires_explicit_leaf_mapping"
                        );
                    }
                    None => {
                        assert_eq!(matched.scope, SchemaScope::TypedLeaf);
                        assert!(policy_row(fixture, channel.channel_id.as_str(), row).is_ok());
                    }
                    Some(other) => panic!("unexpected fixture scope {other}"),
                }
            }
        }
        assert_eq!(rows, EXPECTED_ROW_COUNT);
        assert_eq!(opaque, EXPECTED_OPAQUE_ROW_COUNT);
        assert!(saw_map && saw_array && saw_composition);
    }

    #[test]
    fn every_frozen_row_has_one_closed_w1835_policy_outcome() {
        let fixture = fixture().unwrap();
        let mut identities = BTreeSet::new();
        let mut rows = 0usize;
        for channel in &fixture.channels {
            for row in &channel.leaves {
                rows += 1;
                assert!(identities.insert(format!("{}\u{1f}{}\u{1f}{}", channel.channel_id, row.path_template, row.json_type)));
                let policy = policy_row(fixture, channel.channel_id.as_str(), row).unwrap();
                assert!(matches!(policy.disposition.as_str(), "mapped" | "needs_secret" | "needs_relink" | "needs_runtime" | "unsupported" | "unknown"));
                assert!(!policy.action_id.is_empty());
            }
        }
        assert_eq!(rows, EXPECTED_ROW_COUNT);
    }

    #[test]
    fn policy_outcome_contract_rejects_incoherent_pairs_and_empty_targets() {
        assert!(valid_policy_outcome("mapped", "direct_credential_mapping", Some("credentials.telegram_token")));
        assert!(valid_policy_outcome("unsupported", "requires_neoth_adapter", None));
        assert!(!valid_policy_outcome("mapped", "requires_neoth_adapter", Some("credentials.x")));
        assert!(!valid_policy_outcome("needs_secret", "neoth_credential_flow", Some("")));
        assert!(!valid_policy_outcome("unknown", "blocked_requires_explicit_leaf_mapping", Some("x")));
        assert!(!valid_policy_outcome("unsupported", "requires_neoth_adapter", Some("")));
    }

    #[test]
    fn validated_policy_has_required_synthetic_contracts() {
        let fixture = fixture().unwrap();
        assert_eq!(synthetic_policy(fixture, "account_container").unwrap().action_id, "requires_account_scoped_runtime");
        assert_eq!(synthetic_policy(fixture, "whatsapp_auth_dir_string").unwrap().disposition, "needs_relink");
        let families: BTreeSet<_> = fixture.policy.synthetic.iter().filter(|item| item.kind == "secret_ref_family").map(|item| (item.channel_id.as_deref().unwrap(), item.path_template.as_deref().unwrap())).collect();
        assert_eq!(families.len(), 150);
        assert_eq!(families.len(), fixture.policy.synthetic.iter().filter(|item| item.kind == "secret_ref_family").count());
        validate_synthetic_policy(fixture).unwrap();
    }

    #[test]
    fn secret_refs_require_a_fixture_backed_object_composition_family() {
        assert!(
            lookup("telegram", &[PathPart::Key("botToken")], "secret_ref")
                .unwrap()
                .is_some()
        );
        assert!(
            lookup("telegram", &[PathPart::Key("proxy")], "secret_ref")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn googlechat_service_account_secret_ref_accepts_its_pinned_anyof_two_family() {
        let matched = lookup(
            "googlechat",
            &[
                PathPart::Key("accounts"),
                PathPart::Key("work"),
                PathPart::Key("serviceAccount"),
            ],
            "secret_ref",
        )
        .unwrap()
        .unwrap();
        assert_eq!(matched.scope, SchemaScope::TypedLeaf);
        assert!(
            matched
                .path_template
                .starts_with("accounts.{key}.serviceAccount{anyOf:2}{oneOf:")
        );

        assert!(
            lookup(
                "googlechat",
                &[
                    PathPart::Key("accounts"),
                    PathPart::Key("work"),
                    PathPart::Key("unrelatedObject"),
                ],
                "secret_ref",
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn explicit_typed_leaves_take_precedence_over_opaque_map_prefixes() {
        let typed = lookup(
            "qqbot",
            &[
                PathPart::Key("accounts"),
                PathPart::Key("work"),
                PathPart::Key("audioFormatPolicy"),
                PathPart::Key("transcodeEnabled"),
            ],
            "boolean",
        )
        .unwrap()
        .unwrap();
        assert_eq!(typed.scope, SchemaScope::TypedLeaf);
        assert_eq!(
            typed.path_template,
            "accounts.{key}.audioFormatPolicy.transcodeEnabled"
        );
        assert!(
            has_typed_descendant(
                "qqbot",
                &[
                    PathPart::Key("accounts"),
                    PathPart::Key("work"),
                    PathPart::Key("audioFormatPolicy"),
                ],
            )
            .unwrap()
        );

        let opaque = lookup(
            "qqbot",
            &[
                PathPart::Key("accounts"),
                PathPart::Key("work"),
                PathPart::Key("futureOption"),
            ],
            "boolean",
        )
        .unwrap()
        .unwrap();
        assert_eq!(opaque.scope, SchemaScope::OpaqueSubtree);
        assert_eq!(opaque.path_template, "accounts.{key}.{key}");
        assert!(
            !has_typed_descendant(
                "qqbot",
                &[
                    PathPart::Key("accounts"),
                    PathPart::Key("work"),
                    PathPart::Key("futureOption"),
                ],
            )
            .unwrap()
        );
    }
}
