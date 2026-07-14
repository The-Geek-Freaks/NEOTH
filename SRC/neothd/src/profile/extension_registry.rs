//! Operator-curated profile extension registry — `SPEC_profile_claim_guard.md`
//! M2. Backs the H1-aligned anti-`other: Vec<String>` rule: the
//! extractor must not be allowed to invent novel top-level categories
//! without operator opt-in.
//!
//! The base taxonomy (`identity`, `preferences`, `relationships`,
//! `skills`, `goals`, `health`, `schedule`, `emotional_baseline`,
//! `operator_preferences`) is always allowed. Operators register
//! additional top-level categories in `~/.neoth/profile_extensions.toml`:
//!
//! ```toml
//! [extensions]
//! pets    = "Vec<Pet>"
//! hobbies = "Vec<Hobby>"
//! ```
//!
//! The `type_sig` value is informational v0.1 — stage 5 only checks
//! that the category name is present. Future strict-schema typing
//! can consume the type signature when ProfileApply learns to
//! validate per-category payloads.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::config::FreedomConfig;

/// The base taxonomy the spec mandates. Always allowed regardless of
/// what's in the operator's extensions file. Order matches the spec
/// for documentation clarity.
pub const BASE_CATEGORIES: &[&str] = &[
    "identity",
    "preferences",
    "relationships",
    "skills",
    "goals",
    "health",
    "schedule",
    "emotional_baseline",
    "operator_preferences",
];

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ExtensionsFile {
    /// Map from category name to operator-curated type signature.
    /// The string is informational today; future strict-schema work
    /// will parse it.
    extensions: HashMap<String, String>,
}

/// Operator-curated registry of additional profile categories. Backs
/// the stage-5 H1 check that rejects claims against novel `field`
/// dot-paths whose top segment is neither a base category nor a
/// registered extension.
#[derive(Debug, Default, Clone)]
pub struct TypedExtensionRegistry {
    registered: HashMap<String, String>,
}

impl TypedExtensionRegistry {
    /// Default path: `<neoth_home>/profile_extensions.toml`.
    pub fn default_path() -> PathBuf {
        FreedomConfig::default_neoth_home().join("profile_extensions.toml")
    }

    /// Missing file → empty registry (only base categories allowed).
    /// Bad TOML → loud error so the operator fixes the typo rather
    /// than silently losing protection.
    pub fn load_from(path: &Path) -> Result<Self> {
        let body = match std::fs::read_to_string(path) {
            Ok(body) => body,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("read profile_extensions at {}", path.display()));
            }
        };
        let parsed: ExtensionsFile =
            toml::from_str(&body).with_context(|| format!("parse TOML at {}", path.display()))?;
        Ok(Self {
            registered: parsed.extensions,
        })
    }

    /// Convenience: load from the default path.
    pub fn load() -> Result<Self> {
        Self::load_from(&Self::default_path())
    }

    /// True iff `category` is in the base taxonomy or the operator
    /// registered it via `profile_extensions.toml`.
    pub fn is_known(&self, category: &str) -> bool {
        BASE_CATEGORIES.contains(&category) || self.registered.contains_key(category)
    }

    /// Extract the top-level category from a dot-path field
    /// (`identity.name` → `identity`). Returns the original string when
    /// no `.` is present.
    pub fn category_of(field: &str) -> &str {
        field.split('.').next().unwrap_or(field)
    }

    /// Number of operator-registered (non-base) categories. Telemetry-
    /// only; mostly useful for `neoth profile show`-style introspection.
    pub fn registered_count(&self) -> usize {
        self.registered.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn base_categories_are_always_known() {
        let reg = TypedExtensionRegistry::default();
        for c in BASE_CATEGORIES {
            assert!(reg.is_known(c), "base category {c} must be known");
        }
    }

    #[test]
    fn unknown_category_not_known_without_registration() {
        let reg = TypedExtensionRegistry::default();
        assert!(!reg.is_known("pets"));
    }

    #[test]
    fn category_of_returns_top_segment() {
        assert_eq!(
            TypedExtensionRegistry::category_of("identity.name"),
            "identity"
        );
        assert_eq!(
            TypedExtensionRegistry::category_of("skills.rust.years"),
            "skills"
        );
        assert_eq!(TypedExtensionRegistry::category_of("flat"), "flat");
    }

    #[test]
    fn missing_file_returns_empty_registry() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("profile_extensions.toml");
        let reg = TypedExtensionRegistry::load_from(&path).unwrap();
        assert!(!reg.is_known("pets"));
        assert_eq!(reg.registered_count(), 0);
    }

    #[test]
    fn well_formed_toml_loads_extensions() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("profile_extensions.toml");
        std::fs::write(
            &path,
            r#"
[extensions]
pets    = "Vec<Pet>"
hobbies = "Vec<Hobby>"
"#,
        )
        .unwrap();
        let reg = TypedExtensionRegistry::load_from(&path).unwrap();
        assert!(reg.is_known("pets"));
        assert!(reg.is_known("hobbies"));
        // Base categories still known.
        assert!(reg.is_known("identity"));
        assert_eq!(reg.registered_count(), 2);
    }

    #[test]
    fn malformed_toml_returns_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("profile_extensions.toml");
        std::fs::write(&path, "[extensions\npets = \"Vec<Pet>\"").unwrap();
        let err = TypedExtensionRegistry::load_from(&path).unwrap_err();
        assert!(err.to_string().contains("parse TOML"));
    }

    #[test]
    fn existing_unreadable_path_returns_error_instead_of_empty_registry() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("profile_extensions.toml");
        std::fs::create_dir(&path).unwrap();
        let err = TypedExtensionRegistry::load_from(&path).unwrap_err();
        let detail = format!("{err:#}");
        assert!(detail.contains("read profile_extensions"));
        assert!(detail.contains("profile_extensions.toml"));
    }

    #[test]
    fn registered_count_excludes_base_categories() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("profile_extensions.toml");
        std::fs::write(&path, "[extensions]\npets = \"Vec<Pet>\"\n").unwrap();
        let reg = TypedExtensionRegistry::load_from(&path).unwrap();
        assert_eq!(reg.registered_count(), 1);
    }
}
