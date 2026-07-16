//! Canonical typed capability catalog foundation.
//!
//! This module deliberately contains no per-surface registry. CLI, GUI, Buddy,
//! Doctor, wizard and migration adapters consume the same validated
//! [`CapabilityCatalog`]. The checked-in/release JSON loader lands on this
//! type; it must not grow a second set of feature names elsewhere.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

const MAX_ID_LEN: usize = 128;
const MAX_DISPLAY_NAME_LEN: usize = 160;
const MAX_PUBLIC_TEXT_LEN: usize = 1_024;
const MAX_CAPABILITIES: usize = 4_096;
const MAX_DEPENDENCIES_PER_CAPABILITY: usize = 128;
const MAX_DEPENDENCY_DEPTH: usize = 128;
const MAX_TARGETS_PER_CAPABILITY: usize = 128;

/// Stable public capability identifier.
///
/// IDs are additive migration contracts. They are lowercase ASCII and cannot
/// contain path separators, whitespace, credential material, or shell syntax.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapabilityId(String);

impl CapabilityId {
    pub fn parse(value: impl Into<String>) -> Result<Self, CatalogError> {
        let value = value.into();
        validate_identifier(&value, "capability id")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for CapabilityId {
    type Err = CatalogError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for CapabilityId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CapabilityId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// Target selector used by the release-lock generator.
///
/// Keeping the target as a validated newtype permits exact Rust triples and
/// additive platform variants without silently accepting arbitrary prose.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TargetSelector(String);

impl TargetSelector {
    pub fn parse(value: impl Into<String>) -> Result<Self, CatalogError> {
        let value = value.into();
        validate_identifier(&value, "target selector")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TargetSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for TargetSelector {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for TargetSelector {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityCategory {
    Application,
    Channel,
    Device,
    Migration,
    Model,
    Plugin,
    Preset,
    Provider,
    Release,
    Runtime,
    Sidecar,
    Skill,
    Transport,
    Workflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportTier {
    Core,
    Managed,
    Optional,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySurface {
    Buddy,
    Cli,
    Doctor,
    FirstUse,
    Gui,
    Migration,
    Wizard,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnavailableReason {
    pub code: String,
    pub message: String,
}

impl UnavailableReason {
    fn validate(&self, capability: &CapabilityId) -> Result<(), CatalogError> {
        validate_identifier(&self.code, "unavailable reason code")?;
        validate_public_text(&self.message, "unavailable reason")?;
        if self.message.is_empty() {
            return Err(CatalogError::InvalidDescriptor {
                id: capability.clone(),
                reason: "unavailable reason message is empty".into(),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum TargetAvailability {
    Supported,
    Unavailable { reason: UnavailableReason },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetSupport {
    pub target: TargetSelector,
    pub availability: TargetAvailability,
}

/// Shared descriptor consumed by every public surface and lifecycle adapter.
///
/// Artifact/source/config ownership fields are intentionally added by the
/// release catalog wave. This foundation establishes the stable identity,
/// dependency, target, lifecycle and surface contract they extend.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityDescriptor {
    pub id: CapabilityId,
    pub display_name: String,
    pub category: CapabilityCategory,
    pub support_tier: SupportTier,
    #[serde(default)]
    pub dependencies: Vec<CapabilityId>,
    pub targets: Vec<TargetSupport>,
    pub lifecycle_adapter: Option<String>,
    pub probe: Option<String>,
    pub surfaces: BTreeSet<CapabilitySurface>,
}

impl CapabilityDescriptor {
    pub fn validate(&self) -> Result<(), CatalogError> {
        validate_public_text(&self.display_name, "display name")?;
        if self.display_name.is_empty() || self.display_name.len() > MAX_DISPLAY_NAME_LEN {
            return Err(CatalogError::InvalidDescriptor {
                id: self.id.clone(),
                reason: format!("display name must contain 1..={MAX_DISPLAY_NAME_LEN} bytes"),
            });
        }
        if self.dependencies.len() > MAX_DEPENDENCIES_PER_CAPABILITY {
            return Err(CatalogError::InvalidDescriptor {
                id: self.id.clone(),
                reason: format!("dependency count exceeds {MAX_DEPENDENCIES_PER_CAPABILITY}"),
            });
        }
        validate_sorted_unique(&self.dependencies, "dependencies", &self.id)?;
        if self
            .dependencies
            .iter()
            .any(|dependency| dependency == &self.id)
        {
            return Err(CatalogError::InvalidDescriptor {
                id: self.id.clone(),
                reason: "capability cannot depend on itself".into(),
            });
        }
        if self.targets.is_empty() {
            return Err(CatalogError::InvalidDescriptor {
                id: self.id.clone(),
                reason: "at least one target declaration is required".into(),
            });
        }
        if self.targets.len() > MAX_TARGETS_PER_CAPABILITY {
            return Err(CatalogError::InvalidDescriptor {
                id: self.id.clone(),
                reason: format!("target count exceeds {MAX_TARGETS_PER_CAPABILITY}"),
            });
        }
        for pair in self.targets.windows(2) {
            if pair[0].target >= pair[1].target {
                return Err(CatalogError::InvalidDescriptor {
                    id: self.id.clone(),
                    reason: "targets must be sorted and unique".into(),
                });
            }
        }

        let has_supported_target = self
            .targets
            .iter()
            .any(|target| matches!(target.availability, TargetAvailability::Supported));
        for target in &self.targets {
            if let TargetAvailability::Unavailable { reason } = &target.availability {
                reason.validate(&self.id)?;
            }
        }
        if has_supported_target {
            let adapter = self.lifecycle_adapter.as_deref().ok_or_else(|| {
                CatalogError::InvalidDescriptor {
                    id: self.id.clone(),
                    reason: "a supported target requires a lifecycle adapter".into(),
                }
            })?;
            let probe = self
                .probe
                .as_deref()
                .ok_or_else(|| CatalogError::InvalidDescriptor {
                    id: self.id.clone(),
                    reason: "a supported target requires an authenticated probe id".into(),
                })?;
            validate_identifier(adapter, "lifecycle adapter id")?;
            validate_identifier(probe, "probe id")?;
        } else if self.lifecycle_adapter.is_some() || self.probe.is_some() {
            return Err(CatalogError::InvalidDescriptor {
                id: self.id.clone(),
                reason: "fully unavailable capability must not advertise runnable adapters".into(),
            });
        }
        if self.surfaces.is_empty() {
            return Err(CatalogError::InvalidDescriptor {
                id: self.id.clone(),
                reason: "at least one public surface is required".into(),
            });
        }
        Ok(())
    }
}

/// Validated, deterministic catalog. Entries are stored exactly once by id.
#[derive(Clone, Debug)]
pub struct CapabilityCatalog {
    ordered: Vec<CapabilityDescriptor>,
    by_id: BTreeMap<CapabilityId, usize>,
}

impl CapabilityCatalog {
    /// Build a catalog from canonical, id-sorted descriptors.
    ///
    /// Rejecting unsorted input makes checked-in JSON diffs deterministic and
    /// prevents a loader from silently normalising a non-canonical release.
    pub fn new(ordered: Vec<CapabilityDescriptor>) -> Result<Self, CatalogError> {
        if ordered.is_empty() {
            return Err(CatalogError::EmptyCatalog);
        }
        if ordered.len() > MAX_CAPABILITIES {
            return Err(CatalogError::CatalogTooLarge {
                count: ordered.len(),
                maximum: MAX_CAPABILITIES,
            });
        }
        let mut by_id = BTreeMap::new();
        for (index, descriptor) in ordered.iter().enumerate() {
            descriptor.validate()?;
            if index > 0 && ordered[index - 1].id >= descriptor.id {
                if ordered[index - 1].id == descriptor.id {
                    return Err(CatalogError::DuplicateId(descriptor.id.clone()));
                }
                return Err(CatalogError::UnsortedEntries);
            }
            if by_id.insert(descriptor.id.clone(), index).is_some() {
                return Err(CatalogError::DuplicateId(descriptor.id.clone()));
            }
        }
        for descriptor in &ordered {
            for dependency in &descriptor.dependencies {
                if !by_id.contains_key(dependency) {
                    return Err(CatalogError::UnknownDependency {
                        id: descriptor.id.clone(),
                        dependency: dependency.clone(),
                    });
                }
            }
        }
        validate_acyclic(&ordered, &by_id)?;
        Ok(Self { ordered, by_id })
    }

    pub fn get(&self, id: &CapabilityId) -> Option<&CapabilityDescriptor> {
        self.by_id.get(id).map(|index| &self.ordered[*index])
    }

    pub fn contains(&self, id: &CapabilityId) -> bool {
        self.by_id.contains_key(id)
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &CapabilityDescriptor> {
        self.ordered.iter()
    }

    pub fn len(&self) -> usize {
        self.ordered.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ordered.is_empty()
    }

    /// Dependencies in deterministic post-order, ending with `id` itself.
    pub fn dependency_order(&self, id: &CapabilityId) -> Result<Vec<CapabilityId>, CatalogError> {
        if !self.contains(id) {
            return Err(CatalogError::UnknownCapability(id.clone()));
        }
        fn visit(
            catalog: &CapabilityCatalog,
            id: &CapabilityId,
            seen: &mut BTreeSet<CapabilityId>,
            out: &mut Vec<CapabilityId>,
        ) {
            if !seen.insert(id.clone()) {
                return;
            }
            let descriptor = catalog
                .get(id)
                .expect("validated catalog dependency must exist");
            for dependency in &descriptor.dependencies {
                visit(catalog, dependency, seen, out);
            }
            out.push(id.clone());
        }
        let mut seen = BTreeSet::new();
        let mut order = Vec::new();
        visit(self, id, &mut seen, &mut order);
        Ok(order)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CatalogError {
    #[error("capability catalog is empty")]
    EmptyCatalog,
    #[error("capability catalog entries are not strictly sorted by id")]
    UnsortedEntries,
    #[error("capability catalog has {count} entries; maximum is {maximum}")]
    CatalogTooLarge { count: usize, maximum: usize },
    #[error("duplicate capability id `{0}`")]
    DuplicateId(CapabilityId),
    #[error("unknown capability `{0}`")]
    UnknownCapability(CapabilityId),
    #[error("capability `{id}` depends on missing capability `{dependency}`")]
    UnknownDependency {
        id: CapabilityId,
        dependency: CapabilityId,
    },
    #[error("capability dependency cycle detected at `{0}`")]
    DependencyCycle(CapabilityId),
    #[error("capability dependency depth at `{id}` exceeds maximum {maximum}")]
    DependencyDepthExceeded { id: CapabilityId, maximum: usize },
    #[error("invalid {field}: {reason}")]
    InvalidValue { field: &'static str, reason: String },
    #[error("invalid capability descriptor `{id}`: {reason}")]
    InvalidDescriptor { id: CapabilityId, reason: String },
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), CatalogError> {
    if value.is_empty() || value.len() > MAX_ID_LEN {
        return Err(CatalogError::InvalidValue {
            field,
            reason: format!("must contain 1..={MAX_ID_LEN} bytes"),
        });
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return Err(CatalogError::InvalidValue {
            field,
            reason: "must start with a lowercase ASCII letter or digit".into(),
        });
    }
    if bytes.iter().any(|byte| {
        !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(*byte, b'-' | b'_' | b'.'))
    }) {
        return Err(CatalogError::InvalidValue {
            field,
            reason: "may contain only lowercase ASCII letters, digits, '.', '_' and '-'".into(),
        });
    }
    if matches!(bytes.last(), Some(b'-' | b'_' | b'.')) {
        return Err(CatalogError::InvalidValue {
            field,
            reason: "must not end with punctuation".into(),
        });
    }
    if crate::security::redact::redact_if_secret(value).1 {
        return Err(CatalogError::InvalidValue {
            field,
            reason: "contains a credential-looking literal".into(),
        });
    }
    Ok(())
}

fn validate_public_text(value: &str, field: &'static str) -> Result<(), CatalogError> {
    if value.len() > MAX_PUBLIC_TEXT_LEN {
        return Err(CatalogError::InvalidValue {
            field,
            reason: format!("exceeds {MAX_PUBLIC_TEXT_LEN} bytes"),
        });
    }
    if value
        .chars()
        .any(|character| character == '\0' || character.is_control())
    {
        return Err(CatalogError::InvalidValue {
            field,
            reason: "contains control characters".into(),
        });
    }
    if crate::security::redact::redact_if_secret(value).1 {
        return Err(CatalogError::InvalidValue {
            field,
            reason: "contains a credential-looking literal".into(),
        });
    }
    Ok(())
}

fn validate_sorted_unique<T: Ord>(
    values: &[T],
    field: &'static str,
    id: &CapabilityId,
) -> Result<(), CatalogError> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(CatalogError::InvalidDescriptor {
            id: id.clone(),
            reason: format!("{field} must be sorted and unique"),
        });
    }
    Ok(())
}

fn validate_acyclic(
    ordered: &[CapabilityDescriptor],
    by_id: &BTreeMap<CapabilityId, usize>,
) -> Result<(), CatalogError> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mark {
        Visiting,
        Done,
    }
    fn visit(
        id: &CapabilityId,
        path_depth: usize,
        ordered: &[CapabilityDescriptor],
        by_id: &BTreeMap<CapabilityId, usize>,
        marks: &mut BTreeMap<CapabilityId, Mark>,
        remaining_depths: &mut BTreeMap<CapabilityId, usize>,
    ) -> Result<usize, CatalogError> {
        if path_depth > MAX_DEPENDENCY_DEPTH {
            return Err(CatalogError::DependencyDepthExceeded {
                id: id.clone(),
                maximum: MAX_DEPENDENCY_DEPTH,
            });
        }
        match marks.get(id) {
            Some(Mark::Visiting) => return Err(CatalogError::DependencyCycle(id.clone())),
            Some(Mark::Done) => {
                let remaining = *remaining_depths
                    .get(id)
                    .expect("completed dependency must have a cached depth");
                if path_depth + remaining > MAX_DEPENDENCY_DEPTH {
                    return Err(CatalogError::DependencyDepthExceeded {
                        id: id.clone(),
                        maximum: MAX_DEPENDENCY_DEPTH,
                    });
                }
                return Ok(remaining);
            }
            None => {}
        }
        marks.insert(id.clone(), Mark::Visiting);
        let descriptor = &ordered[*by_id
            .get(id)
            .expect("validated dependency lookup must exist")];
        let mut remaining_depth = 0;
        for dependency in &descriptor.dependencies {
            let dependency_depth = visit(
                dependency,
                path_depth + 1,
                ordered,
                by_id,
                marks,
                remaining_depths,
            )?;
            remaining_depth = remaining_depth.max(dependency_depth + 1);
        }
        marks.insert(id.clone(), Mark::Done);
        remaining_depths.insert(id.clone(), remaining_depth);
        Ok(remaining_depth)
    }

    let mut marks = BTreeMap::new();
    let mut remaining_depths = BTreeMap::new();
    for descriptor in ordered {
        visit(
            &descriptor.id,
            0,
            ordered,
            by_id,
            &mut marks,
            &mut remaining_depths,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(id: &str, dependencies: &[&str]) -> CapabilityDescriptor {
        CapabilityDescriptor {
            id: CapabilityId::parse(id).unwrap(),
            display_name: id.replace('-', " "),
            category: CapabilityCategory::Runtime,
            support_tier: SupportTier::Managed,
            dependencies: dependencies
                .iter()
                .map(|value| CapabilityId::parse(*value).unwrap())
                .collect(),
            targets: vec![TargetSupport {
                target: TargetSelector::parse("x86_64-pc-windows-msvc").unwrap(),
                availability: TargetAvailability::Supported,
            }],
            lifecycle_adapter: Some("fixture-adapter".into()),
            probe: Some("fixture-authenticated-probe".into()),
            surfaces: BTreeSet::from([
                CapabilitySurface::Cli,
                CapabilitySurface::Doctor,
                CapabilitySurface::Gui,
            ]),
        }
    }

    #[test]
    fn catalog_is_sorted_typed_and_dependency_ordered() {
        let catalog = CapabilityCatalog::new(vec![
            descriptor("managed-node", &[]),
            descriptor("whatsapp-bridge", &["managed-node"]),
        ])
        .unwrap();
        let requested = CapabilityId::parse("whatsapp-bridge").unwrap();
        assert_eq!(
            catalog.dependency_order(&requested).unwrap(),
            vec![CapabilityId::parse("managed-node").unwrap(), requested,]
        );
    }

    #[test]
    fn catalog_rejects_unknown_dependencies_cycles_and_drift() {
        let missing = CapabilityCatalog::new(vec![descriptor("bridge", &["runtime"])]);
        assert!(matches!(
            missing,
            Err(CatalogError::UnknownDependency { .. })
        ));

        let cycle = CapabilityCatalog::new(vec![descriptor("a", &["b"]), descriptor("b", &["a"])]);
        assert!(matches!(cycle, Err(CatalogError::DependencyCycle(_))));

        let unsorted = CapabilityCatalog::new(vec![descriptor("z", &[]), descriptor("a", &[])]);
        assert_eq!(unsorted.unwrap_err(), CatalogError::UnsortedEntries);
    }

    #[test]
    fn supported_target_requires_adapter_probe_and_surface() {
        let mut value = descriptor("model", &[]);
        value.probe = None;
        assert!(matches!(
            value.validate(),
            Err(CatalogError::InvalidDescriptor { .. })
        ));
        value.probe = Some("probe".into());
        value.surfaces.clear();
        assert!(matches!(
            value.validate(),
            Err(CatalogError::InvalidDescriptor { .. })
        ));
    }

    #[test]
    fn unavailable_target_requires_typed_reason_and_no_runnable_adapter() {
        let mut value = descriptor("ios-only", &[]);
        value.targets[0].availability = TargetAvailability::Unavailable {
            reason: UnavailableReason {
                code: "unsupported-target".into(),
                message: "No reviewed artifact exists for this target.".into(),
            },
        };
        value.lifecycle_adapter = None;
        value.probe = None;
        value.validate().unwrap();

        value.lifecycle_adapter = Some("must-not-run".into());
        assert!(value.validate().is_err());
    }

    #[test]
    fn ids_and_public_text_fail_closed() {
        assert!(CapabilityId::parse("../escape").is_err());
        assert!(CapabilityId::parse("Uppercase").is_err());
        let mut value = descriptor("safe", &[]);
        value.display_name = "API_TOKEN=not-public-value".into();
        assert!(value.validate().is_err());

        value.display_name = format!("sk-{}", "A".repeat(32));
        assert!(value.validate().is_err());
        value.display_name = format!("Bearer {}", "b".repeat(32));
        assert!(value.validate().is_err());
    }

    #[test]
    fn catalog_and_descriptor_work_are_bounded_before_dag_walk() {
        let mut value = descriptor("bounded", &[]);
        value.dependencies = (0..=MAX_DEPENDENCIES_PER_CAPABILITY)
            .map(|index| CapabilityId::parse(format!("dependency-{index:03}")))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(matches!(
            value.validate(),
            Err(CatalogError::InvalidDescriptor { .. })
        ));

        let oversized = (0..=MAX_CAPABILITIES)
            .map(|index| descriptor(&format!("capability-{index:04}"), &[]))
            .collect();
        assert!(matches!(
            CapabilityCatalog::new(oversized),
            Err(CatalogError::CatalogTooLarge { .. })
        ));

        let too_deep = (0..=MAX_DEPENDENCY_DEPTH + 1)
            .map(|index| {
                let id = format!("depth-{index:03}");
                let dependency =
                    (index <= MAX_DEPENDENCY_DEPTH).then(|| format!("depth-{:03}", index + 1));
                descriptor(&id, &dependency.as_deref().into_iter().collect::<Vec<_>>())
            })
            .collect();
        assert!(matches!(
            CapabilityCatalog::new(too_deep),
            Err(CatalogError::DependencyDepthExceeded { .. })
        ));
    }
}
