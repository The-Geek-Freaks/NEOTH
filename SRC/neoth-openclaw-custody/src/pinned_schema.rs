//! Frozen W169 OpenClaw channel schema inventory.
//!
//! The fixture is a hosted, source-derived diagnostic input. This module only
//! validates and looks up its structural paths; it never evaluates upstream
//! JavaScript or invents descendants for open schema subtrees.

use anyhow::{bail, ensure, Context as _, Result};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::sync::OnceLock;

pub const FIXTURE_SHA256: &str = "A7E60AFBB1E0D013100EE8C30F5237307E6552923F34B55A39B2DC1263B0283F";
pub const FIXTURE_VERSION: u64 = 1;
pub const OPENCLAW_REPOSITORY: &str = "openclaw/openclaw";
pub const OPENCLAW_METADATA_PATH: &str = "src/config/bundled-channel-config-metadata.generated.ts";
pub const OPENCLAW_COMMIT: &str = "4c667aac8859114bd8f0a589ac6cd1de8bfe1474";
const EXPECTED_ROW_COUNT: usize = 3252;
const EXPECTED_OPAQUE_ROW_COUNT: usize = 22;
const FIXTURE_BYTES: &str = include_str!("fixtures/openclaw_channel_schema_v1.json");

const EXPECTED_CHANNELS: &[&str] = &[
    "clickclack", "discord", "feishu", "googlechat", "imessage", "irc", "line", "matrix",
    "mattermost", "msteams", "nextcloud-talk", "nostr", "qa-channel", "qqbot", "raft",
    "reef", "signal", "slack", "sms", "synology-chat", "telegram", "tlon", "twitch",
    "whatsapp", "zalo", "zalouser",
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
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    channels: Vec<Channel>,
    schema_version: u64,
    source: Source,
    uncovered_blockers: Vec<UncoveredBlocker>,
}

#[derive(Debug, Deserialize)]
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

static FIXTURE: OnceLock<Result<Fixture, String>> = OnceLock::new();

pub fn validate_pinned_schema() -> Result<()> {
    fixture().map(|_| ())
}

pub fn lookup(channel: &str, path: &[PathPart<'_>], actual_json_type: &str) -> Result<Option<SchemaMatch>> {
    let fixture = fixture()?;
    let Some(channel_schema) = fixture.channels.iter().find(|item| item.channel_id == channel) else {
        return Ok(None);
    };

    let opaque = channel_schema
        .leaves
        .iter()
        .find(|row| row.scope.as_deref() == Some("opaque_subtree") && template_matches(row, path, true));
    if let Some(row) = opaque {
        return Ok(Some(schema_match(channel, row, SchemaScope::OpaqueSubtree)));
    }

    if actual_json_type == "secret_ref" {
        return Ok(secret_ref_match(channel, channel_schema, path));
    }

    let mut candidates = channel_schema
        .leaves
        .iter()
        .filter(|row| row.scope.is_none() && template_matches(row, path, false))
        .filter(|row| json_type_matches(row.json_type.as_str(), actual_json_type));
    let Some(first) = candidates.next() else {
        return Ok(None);
    };
    // The validator guarantees same path/type rows cannot disagree in their
    // outcome. Composition branches are schema provenance, not runtime paths.
    Ok(Some(schema_match(channel, first, SchemaScope::TypedLeaf)))
}

fn secret_ref_match(
    channel: &str,
    channel_schema: &Channel,
    path: &[PathPart<'_>],
) -> Option<SchemaMatch> {
    for id_row in channel_schema.leaves.iter().filter(|row| {
        row.scope.is_none()
            && row.json_type == "string"
            && row.path_template.contains("{anyOf:1}{oneOf:")
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
            member_path.push(PathPart::Key(*member));
            let expected_template = format!("{parent}.{member}");
            channel_schema.leaves.iter().any(|row| {
                row.scope.is_none()
                    && row.json_type == "string"
                    && row.path_template.as_str() == expected_template.as_str()
                    && template_matches(row, &member_path, false)
            })
        }) {
            return Some(SchemaMatch {
                schema_id: format!("w169:{channel}:{parent}:secret_ref"),
                path_template: parent.to_string(),
                scope: SchemaScope::TypedLeaf,
            });
        }
    }
    None
}

/// Account objects are structural records, not values copied into a target.
/// The upstream fixture records account-template presence at the channel level,
/// so this binding remains traceable even though an account object itself has
/// no primitive `json_type` row.
pub fn account_container(channel: &str) -> Result<Option<SchemaMatch>> {
    let fixture = fixture()?;
    Ok(fixture
        .channels
        .iter()
        .find(|item| item.channel_id == channel && item.account_template_present)
        .map(|_| SchemaMatch {
            schema_id: format!("w169:{channel}:accounts.{{key}}:account_container"),
            path_template: "accounts.{key}".to_string(),
            scope: SchemaScope::AccountContainer,
        }))
}

fn fixture() -> Result<&'static Fixture> {
    FIXTURE
        .get_or_init(|| load_fixture().map_err(|error| format!("{error:#}")))
        .as_ref()
        .map_err(|error| anyhow::anyhow!("invalid pinned W169 schema fixture: {error}"))
}

fn load_fixture() -> Result<Fixture> {
    let actual = format!("{:X}", Sha256::digest(FIXTURE_BYTES.as_bytes()));
    ensure!(actual == FIXTURE_SHA256, "W169 schema fixture digest mismatch");
    let fixture: Fixture = serde_json::from_str(FIXTURE_BYTES).context("parse pinned W169 schema fixture")?;
    ensure!(fixture.schema_version == FIXTURE_VERSION, "unexpected W169 schema fixture version");
    ensure!(fixture.source.repository == OPENCLAW_REPOSITORY, "unexpected W169 source repository");
    ensure!(fixture.source.commit == OPENCLAW_COMMIT, "unexpected W169 source commit");
    ensure!(fixture.source.metadata_path == OPENCLAW_METADATA_PATH, "unexpected W169 metadata path");
    for blocker in &fixture.uncovered_blockers {
        let _ = (&blocker.channel, &blocker.path, &blocker.reason);
    }
    ensure!(fixture.uncovered_blockers.is_empty(), "W169 schema fixture has uncovered blockers");

    let expected: BTreeSet<_> = EXPECTED_CHANNELS.iter().copied().collect();
    let actual_channels: BTreeSet<_> = fixture.channels.iter().map(|item| item.channel_id.as_str()).collect();
    ensure!(actual_channels == expected, "W169 schema fixture channel inventory drift");
    ensure!(fixture.channels.len() == EXPECTED_CHANNELS.len(), "duplicate W169 channel IDs");

    let mut identities = BTreeSet::new();
    let mut rows = 0usize;
    let mut opaque_rows = 0usize;
    for channel in &fixture.channels {
        let _ = (&channel.aliases, channel.default_account_present, &channel.plugin_id);
        if let Some(blocker) = channel.blockers.first() {
            let _ = (&blocker.path, &blocker.reason);
            bail!("W169 fixture retains legacy channel blocker outside normalized rows");
        }
        for row in &channel.leaves {
            rows += 1;
            validate_template(row.path_template.as_str())?;
            let identity = format!("{}\u{1f}{}\u{1f}{}", channel.channel_id, row.path_template, row.json_type);
            ensure!(identities.insert(identity), "duplicate W169 schema row identity");
            match row.scope.as_deref() {
                None => {
                    ensure!(row.disposition.is_none(), "typed W169 row unexpectedly carries a disposition");
                    ensure!(row.json_type != "any", "typed W169 row cannot have json_type any");
                }
                Some("opaque_subtree") => {
                    opaque_rows += 1;
                    ensure!(row.json_type == "any", "opaque W169 row must have json_type any");
                    ensure!(row.disposition.as_deref() == Some("blocked_requires_explicit_leaf_mapping"), "opaque W169 row disposition drift");
                }
                Some(other) => bail!("unknown W169 schema scope `{other}`"),
            }
        }
        if channel.account_template_present {
            ensure!(channel.leaves.iter().any(|row| row.path_template.starts_with("accounts.{key}")), "account-template channel lacks accounts.{{key}} schema row");
        }
    }
    ensure!(rows == EXPECTED_ROW_COUNT, "W169 schema row count drift");
    ensure!(opaque_rows == EXPECTED_OPAQUE_ROW_COUNT, "W169 opaque schema row count drift");
    Ok(fixture)
}

fn validate_template(template: &str) -> Result<()> {
    ensure!(!template.is_empty() && !template.starts_with('.') && !template.ends_with('.'), "invalid empty W169 path template");
    for component in template.split('.') {
        ensure!(!component.is_empty(), "invalid empty W169 path component");
        let stripped = strip_composition(component);
        ensure!(!stripped.is_empty() || component.contains("{anyOf:") || component.contains("{oneOf:"), "invalid W169 path component");
        ensure!(
            stripped == "{key}"
                || stripped == "{key}[]"
                || (!stripped.contains('{') && !stripped.contains('}')),
            "invalid W169 path placeholder"
        );
    }
    Ok(())
}

fn schema_match(channel: &str, row: &SchemaLeaf, scope: SchemaScope) -> SchemaMatch {
    SchemaMatch {
        schema_id: format!("w169:{channel}:{}:{}", row.path_template, row.json_type),
        path_template: row.path_template.clone(),
        scope,
    }
}

fn template_matches(row: &SchemaLeaf, path: &[PathPart<'_>], prefix: bool) -> bool {
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
    if prefix {
        if path.len() < expected.len() {
            return false;
        }
    } else if path.len() != expected.len() {
        return false;
    }
    expected.iter().zip(path).all(|(expected, actual)| match (expected, actual) {
        (TemplatePart::Index, PathPart::Index) => true,
        (TemplatePart::Key(expected), PathPart::Key(_)) if expected == "{key}" => true,
        (TemplatePart::Key(expected), PathPart::Key(actual)) => expected == actual,
        _ => false,
    })
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
                saw_composition |= row.path_template.contains("{anyOf:")
                    || row.path_template.contains("{oneOf:");
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
                    .unwrap_or_else(|| panic!("fixture row did not resolve: {}:{}", channel.channel_id, row.path_template));
                match row.scope.as_deref() {
                    Some("opaque_subtree") => {
                        opaque += 1;
                        assert_eq!(matched.scope, SchemaScope::OpaqueSubtree);
                        assert_eq!(row.disposition.as_deref(), Some("blocked_requires_explicit_leaf_mapping"));
                    }
                    None => {
                        assert_eq!(matched.scope, SchemaScope::TypedLeaf);
                        assert!(row.disposition.is_none());
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
    fn secret_refs_require_a_fixture_backed_object_composition_family() {
        assert!(lookup("telegram", &[PathPart::Key("botToken")], "secret_ref")
            .unwrap()
            .is_some());
        assert!(lookup("telegram", &[PathPart::Key("proxy")], "secret_ref")
            .unwrap()
            .is_none());
    }
}
