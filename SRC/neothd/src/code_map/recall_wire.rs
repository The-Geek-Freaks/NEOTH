//! Stable machine contract for repository-local recall consumers.
//!
//! CLI, MCP, GUI, Buddy and automation all serialize/parse this type. Keeping
//! the envelope here prevents each surface from inventing a subtly different
//! empty-result or generation shape.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::path::Path;

use super::recall::RecallReceipt;

pub const RECALL_WIRE_SCHEMA: &str = "neoth.code_map.recall.v1";

/// Bounded non-prompt-specific reason shared by automatic Chat/Channel recall
/// and the existing lifecycle presentation surfaces.  It intentionally carries
/// no SQLite error, path outside the selected root, prompt, or source text.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryContextUnavailable {
    MissingStore,
    UnmappedRoot,
    StaleSnapshot,
    UnreadableStore,
    WorkerUnavailable,
}

impl RepositoryContextUnavailable {
    pub const fn code(self) -> &'static str {
        match self {
            Self::MissingStore => "missing_store",
            Self::UnmappedRoot => "unmapped_root",
            Self::StaleSnapshot => "stale_snapshot",
            Self::UnreadableStore => "unreadable_store",
            Self::WorkerUnavailable => "worker_unavailable",
        }
    }
}

/// Read-only automatic-context eligibility for one explicit repository root.
/// `Eligible` only says a following turn may attempt prompt-specific recall;
/// it never predicts a nonempty selection or a provider result.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AutomaticContextReadiness {
    Disabled,
    Unavailable {
        reason: RepositoryContextUnavailable,
    },
    Eligible {
        canonical_root: String,
        root_identity: String,
        index_generation: i64,
        graph_generation: i64,
        max_files: u64,
    },
}

/// Classify only the accepted automatic-context control and the same
/// root/generation/completeness/freshness preflight that guards W55 recall.
/// Disabled returns before root or SQLite inspection. This path opens an
/// existing database read-only; it never creates, migrates, or refreshes one.
pub fn inspect_automatic_context_readiness(
    config: &crate::config::FreedomConfig,
    database_path: &Path,
    root: &Path,
) -> AutomaticContextReadiness {
    let max_files = config.code_map.auto_context_max_files;
    if max_files == 0 {
        return AutomaticContextReadiness::Disabled;
    }
    match database_path.try_exists() {
        Ok(false) => {
            return AutomaticContextReadiness::Unavailable {
                reason: RepositoryContextUnavailable::MissingStore,
            };
        }
        Err(_) => {
            return AutomaticContextReadiness::Unavailable {
                reason: RepositoryContextUnavailable::UnreadableStore,
            };
        }
        Ok(true) => {}
    }
    let conn = match crate::code_map::persist::open_read_only(database_path) {
        Ok(conn) => conn,
        Err(_) => {
            return AutomaticContextReadiness::Unavailable {
                reason: RepositoryContextUnavailable::UnreadableStore,
            };
        }
    };
    match crate::code_map::recall::automatic_context_preflight(&conn, root) {
        Ok(Some((snapshot, false))) => AutomaticContextReadiness::Eligible {
            canonical_root: snapshot.root.display().to_owned(),
            root_identity: snapshot.root.identity().as_str().to_owned(),
            index_generation: snapshot.index_generation,
            graph_generation: snapshot.graph_generation,
            max_files: u64::from(max_files),
        },
        Ok(None) => AutomaticContextReadiness::Unavailable {
            reason: RepositoryContextUnavailable::UnmappedRoot,
        },
        Ok(Some((_snapshot, true))) => AutomaticContextReadiness::Unavailable {
            reason: RepositoryContextUnavailable::StaleSnapshot,
        },
        Err(_) => AutomaticContextReadiness::Unavailable {
            // Existing but unqueryable stores (including schema damage) stay
            // distinct from a valid map that merely needs a rebuild.
            reason: RepositoryContextUnavailable::UnreadableStore,
        },
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecallWireStatus {
    Ok,
    Unmapped,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecallWireHit {
    pub root: String,
    pub path: String,
    pub identifier_hits: u32,
    pub matched_symbols: Vec<String>,
    pub path_keyword_overlap: u32,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecallWireReceipt {
    pub root: String,
    pub root_identity: String,
    pub index_generation: i64,
    pub graph_generation: i64,
    /// `None` means the caller deliberately skipped the filesystem freshness
    /// scan. Consumers must not render that as "fresh".
    pub stale: Option<bool>,
    pub truncated: bool,
    pub hits: Vec<RecallWireHit>,
}

impl From<&RecallReceipt> for RecallWireReceipt {
    fn from(receipt: &RecallReceipt) -> Self {
        Self {
            root: receipt.snapshot.root.display().to_owned(),
            root_identity: receipt.snapshot.root.identity().as_str().to_owned(),
            index_generation: receipt.snapshot.index_generation,
            graph_generation: receipt.snapshot.graph_generation,
            stale: receipt.stale,
            truncated: receipt.truncated,
            hits: receipt
                .ranked_files
                .iter()
                .map(|hit| RecallWireHit {
                    root: hit.root.clone(),
                    path: hit.path.clone(),
                    identifier_hits: hit.identifier_hits,
                    matched_symbols: hit.matched_symbols.clone(),
                    path_keyword_overlap: hit.path_keyword_overlap,
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecallWireEnvelope {
    pub schema: String,
    pub status: RecallWireStatus,
    pub prompt: String,
    pub max: u64,
    pub receipt: Option<RecallWireReceipt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl RecallWireEnvelope {
    pub fn success(prompt: impl Into<String>, max: usize, receipt: &RecallReceipt) -> Result<Self> {
        let envelope = Self {
            schema: RECALL_WIRE_SCHEMA.to_owned(),
            status: RecallWireStatus::Ok,
            prompt: prompt.into(),
            max: u64::try_from(max).map_err(anyhow::Error::from)?,
            receipt: Some(receipt.into()),
            note: None,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn empty(
        status: RecallWireStatus,
        prompt: impl Into<String>,
        max: usize,
        note: impl Into<String>,
    ) -> Result<Self> {
        if status == RecallWireStatus::Ok {
            bail!("empty recall envelope cannot use ok status");
        }
        let envelope = Self {
            schema: RECALL_WIRE_SCHEMA.to_owned(),
            status,
            prompt: prompt.into(),
            max: u64::try_from(max).map_err(anyhow::Error::from)?,
            receipt: None,
            note: Some(note.into()),
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn parse_json(input: &str) -> Result<Self> {
        let envelope: Self = serde_json::from_str(input)?;
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != RECALL_WIRE_SCHEMA {
            bail!(
                "unsupported recall schema {:?}; expected {RECALL_WIRE_SCHEMA}",
                self.schema
            );
        }
        if self.prompt.trim().is_empty() || self.max == 0 {
            bail!("recall envelope has an invalid prompt or max");
        }
        match (self.status, self.receipt.as_ref()) {
            (RecallWireStatus::Ok, Some(receipt)) => {
                if receipt.root.trim().is_empty() || receipt.root_identity.trim().is_empty() {
                    bail!("recall receipt has an invalid root identity");
                }
                if receipt.index_generation <= 0 || receipt.graph_generation <= 0 {
                    bail!("recall receipt requires positive index and graph generations");
                }
                if receipt.index_generation != receipt.graph_generation {
                    bail!("recall receipt mixes different index and graph generations");
                }
                for hit in &receipt.hits {
                    if hit.root != receipt.root || hit.path.trim().is_empty() {
                        bail!("recall hit is not bound to the receipt root");
                    }
                }
            }
            (RecallWireStatus::Ok, None) => bail!("ok recall envelope is missing its receipt"),
            (RecallWireStatus::Unmapped | RecallWireStatus::Unavailable, Some(_)) => {
                bail!("non-ok recall envelope must not carry a receipt")
            }
            (RecallWireStatus::Unmapped | RecallWireStatus::Unavailable, None) => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_config() -> crate::config::FreedomConfig {
        let mut config = crate::config::FreedomConfig::default();
        config.code_map.auto_context_max_files = 3;
        config
    }

    fn persist_complete_map(repository: &Path, database: &Path) {
        let map = crate::code_map::walker::RepoMapBuilder::new(repository)
            .scan()
            .unwrap();
        let mut conn = crate::code_map::persist::open(database).unwrap();
        crate::code_map::persist::persist_map_and_edges(&mut conn, &map, &[]).unwrap();
    }

    #[test]
    fn disabled_automatic_context_never_opens_or_creates_an_absent_store() {
        let home = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        let database = home.path().join("code_map.db");
        let config = crate::config::FreedomConfig::default();

        let readiness = inspect_automatic_context_readiness(&config, &database, repository.path());

        assert_eq!(readiness, AutomaticContextReadiness::Disabled);
        assert!(
            !database.exists(),
            "disabled status must not create the store"
        );
    }

    #[test]
    fn enabled_automatic_context_reports_missing_store_with_a_bounded_reason() {
        let home = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        let database = home.path().join("code_map.db");
        let config = enabled_config();

        let readiness = inspect_automatic_context_readiness(&config, &database, repository.path());

        assert_eq!(
            readiness,
            AutomaticContextReadiness::Unavailable {
                reason: RepositoryContextUnavailable::MissingStore,
            }
        );
        assert!(
            !database.exists(),
            "readiness inspection must not create the store"
        );
    }

    #[test]
    fn readiness_uses_w55_preflight_for_unmapped_incomplete_stale_and_fresh_maps() {
        let home = tempfile::tempdir().unwrap();
        let indexed = tempfile::tempdir().unwrap();
        let unrelated = tempfile::tempdir().unwrap();
        let database = home.path().join("code_map.db");
        std::fs::write(indexed.path().join("src.rs"), "fn mapped_symbol() {}\n").unwrap();
        let config = enabled_config();

        persist_complete_map(indexed.path(), &database);
        assert!(matches!(
            inspect_automatic_context_readiness(&config, &database, unrelated.path()),
            AutomaticContextReadiness::Unavailable {
                reason: RepositoryContextUnavailable::UnmappedRoot
            }
        ));
        let conn = crate::code_map::persist::open_read_only(&database).unwrap();
        assert!(
            crate::code_map::recall::recall_receipt_for_prompt(
                &conn,
                unrelated.path(),
                "mapped_symbol",
                3,
                crate::code_map::recall::RecallStaleness::Check,
            )
            .unwrap()
            .is_none()
        );
        assert!(matches!(
            inspect_automatic_context_readiness(&config, &database, indexed.path()),
            AutomaticContextReadiness::Eligible { .. }
        ));
        let fresh_turn = crate::code_map::recall::recall_receipt_for_prompt(
            &conn,
            indexed.path(),
            "mapped_symbol",
            3,
            crate::code_map::recall::RecallStaleness::Check,
        )
        .unwrap()
        .expect("fresh map produces the real turn receipt");
        assert_eq!(fresh_turn.stale, Some(false));
        drop(conn);

        std::fs::write(
            indexed.path().join("src.rs"),
            "fn mapped_symbol() { let changed = 1; }\n",
        )
        .unwrap();
        assert!(matches!(
            inspect_automatic_context_readiness(&config, &database, indexed.path()),
            AutomaticContextReadiness::Unavailable {
                reason: RepositoryContextUnavailable::StaleSnapshot
            }
        ));
        let conn = crate::code_map::persist::open_read_only(&database).unwrap();
        let stale_turn = crate::code_map::recall::recall_receipt_for_prompt(
            &conn,
            indexed.path(),
            "mapped_symbol",
            3,
            crate::code_map::recall::RecallStaleness::Check,
        )
        .unwrap()
        .expect("stale map produces a bounded turn receipt");
        assert_eq!(stale_turn.stale, Some(true));
        assert!(stale_turn.ranked_files.is_empty());
    }

    #[test]
    fn readiness_classifies_partial_and_corrupt_existing_stores_without_writes() {
        let home = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        let database = home.path().join("code_map.db");
        std::fs::write(repository.path().join("src.rs"), "fn partial_symbol() {}\n").unwrap();
        let config = enabled_config();
        let map = crate::code_map::walker::RepoMapBuilder::new(repository.path())
            .scan()
            .unwrap();
        let mut conn = crate::code_map::persist::open(&database).unwrap();
        crate::code_map::persist::persist_map(&mut conn, &map).unwrap();
        drop(conn);

        assert!(matches!(
            inspect_automatic_context_readiness(&config, &database, repository.path()),
            AutomaticContextReadiness::Unavailable {
                reason: RepositoryContextUnavailable::StaleSnapshot
            }
        ));

        let corrupt = home.path().join("corrupt-code-map.db");
        std::fs::write(&corrupt, b"not sqlite").unwrap();
        assert!(matches!(
            inspect_automatic_context_readiness(&config, &corrupt, repository.path()),
            AutomaticContextReadiness::Unavailable {
                reason: RepositoryContextUnavailable::UnreadableStore
            }
        ));
    }

    #[test]
    fn readiness_and_turn_preflight_choose_the_same_root_for_multiroot_aliases() {
        let home = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        let other_repository = tempfile::tempdir().unwrap();
        let nested = repository.path().join("src/nested");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            repository.path().join("src/lib.rs"),
            "fn alias_symbol() {}\n",
        )
        .unwrap();
        std::fs::write(
            other_repository.path().join("other.rs"),
            "fn other_symbol() {}\n",
        )
        .unwrap();
        let database = home.path().join("code_map.db");
        let config = enabled_config();
        persist_complete_map(repository.path(), &database);
        persist_complete_map(other_repository.path(), &database);
        let alias = nested.join("..");

        let readiness = inspect_automatic_context_readiness(&config, &database, &alias);
        let conn = crate::code_map::persist::open_read_only(&database).unwrap();
        let turn_preflight = crate::code_map::recall::automatic_context_preflight(&conn, &alias)
            .unwrap()
            .expect("alias stays within the indexed root");

        assert!(matches!(
            readiness,
            AutomaticContextReadiness::Eligible { .. }
        ));
        assert!(!turn_preflight.1);
        assert_eq!(
            turn_preflight.0.root.display(),
            std::fs::canonicalize(repository.path())
                .unwrap()
                .to_str()
                .unwrap()
        );
    }

    #[test]
    fn strict_empty_envelope_roundtrips() {
        let envelope = RecallWireEnvelope::empty(
            RecallWireStatus::Unavailable,
            "find auth",
            5,
            "index missing",
        )
        .unwrap();
        let json = serde_json::to_string(&envelope).unwrap();
        assert_eq!(RecallWireEnvelope::parse_json(&json).unwrap(), envelope);
    }

    #[test]
    fn parser_rejects_unknown_fields_and_status_receipt_mismatch() {
        let unknown = r#"{"schema":"neoth.code_map.recall.v1","status":"unavailable","prompt":"q","max":5,"receipt":null,"extra":true}"#;
        assert!(RecallWireEnvelope::parse_json(unknown).is_err());

        let mismatched = r#"{"schema":"neoth.code_map.recall.v1","status":"ok","prompt":"q","max":5,"receipt":null}"#;
        assert!(RecallWireEnvelope::parse_json(mismatched).is_err());
    }

    #[test]
    fn parser_rejects_zero_or_mixed_snapshot_generations() {
        let zero = r#"{"schema":"neoth.code_map.recall.v1","status":"ok","prompt":"q","max":5,"receipt":{"root":"/repo","root_identity":"id","index_generation":1,"graph_generation":0,"stale":false,"truncated":false,"hits":[]}}"#;
        assert!(
            RecallWireEnvelope::parse_json(zero)
                .unwrap_err()
                .to_string()
                .contains("requires positive index and graph generations")
        );

        let mixed = r#"{"schema":"neoth.code_map.recall.v1","status":"ok","prompt":"q","max":5,"receipt":{"root":"/repo","root_identity":"id","index_generation":2,"graph_generation":1,"stale":false,"truncated":false,"hits":[]}}"#;
        assert!(
            RecallWireEnvelope::parse_json(mixed)
                .unwrap_err()
                .to_string()
                .contains("mixes different index and graph generations")
        );
    }
}
