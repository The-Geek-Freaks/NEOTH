//! Deterministic, side-effect-free planning for reflection hygiene.
//!
//! The planner receives all data in memory and produces an explicit plan. It
//! neither opens a database nor reads, writes, or deletes reflection files.
//! In particular, yearly synthesis uses only the supplied period reflections;
//! it never derives topics from `views.db` or any other storage surface.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::periodic::PeriodReflection;

/// Version of [`VersionedHygieneInput`] accepted by this planner.
pub const HYGIENE_PLAN_SCHEMA_VERSION: u16 = 1;
/// Version of the deterministic synonym-map semantics.
pub const TOPIC_SYNONYM_MAP_VERSION: u16 = 1;
/// Raw reflections may remain for no more than this many whole days.
pub const RAW_RETENTION_DAYS: i64 = 90;
/// A yearly synthesis sees this many whole days of supplied period data.
pub const YEARLY_HORIZON_DAYS: i64 = 365;
/// Basis-point threshold for conservative duplicate classification.
pub const EXACT_TOPIC_MATCH_BPS: u16 = 10_000;

const SECONDS_PER_DAY: i64 = 86_400;

/// A persisted reflection together with its raw-retention timestamp and stable
/// identifier. The embedded [`PeriodReflection`] is deliberately stored whole,
/// so its historical fields are never discarded by hygiene planning.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RawReflection {
    pub id: String,
    pub recorded_at_unix: i64,
    pub reflection: PeriodReflection,
}

/// Versioned topic aliases. Both keys and values are normalized before use and
/// retained in ordered maps, making equivalent inputs produce the same plan.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TopicSynonymMap {
    pub version: u16,
    pub entries: BTreeMap<String, String>,
}

impl Default for TopicSynonymMap {
    fn default() -> Self {
        Self {
            version: TOPIC_SYNONYM_MAP_VERSION,
            entries: BTreeMap::new(),
        }
    }
}

/// The current, explicitly versioned planner input.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VersionedHygieneInput {
    pub schema_version: u16,
    pub now_unix: i64,
    pub raw_reflections: Vec<RawReflection>,
    /// Daily period/rollup records used as the only source for yearly inputs.
    pub period_reflections: Vec<PeriodReflection>,
    pub topic_synonyms: TopicSynonymMap,
}

/// The pre-versioned representation. It embeds the existing
/// [`PeriodReflection`] type directly, preserving every current field in
/// memory while callers explicitly migrate to [`VersionedHygieneInput`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LegacyHygieneInput {
    pub now_unix: i64,
    pub raw_reflections: Vec<RawReflection>,
    pub period_reflections: Vec<PeriodReflection>,
    pub topic_synonyms: TopicSynonymMap,
}

/// Evidence of whether the plan used native V1 data or an explicit in-memory
/// migration from the unversioned period-reflection shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HygieneMigrationReport {
    NativeV1,
    MigratedLegacyPeriodReflections {
        raw_reflection_count: usize,
        period_reflection_count: usize,
    },
}

/// A raw reflection excluded only because a retained representative has the
/// same non-empty canonical topic set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateRawReflection {
    pub raw: RawReflection,
    pub retained_raw_id: String,
    pub jaccard_basis_points: u16,
}

/// Ordered period data from which a later yearly materializer may synthesize a
/// yearly reflection. This is plan data, not a generated/refreshed record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YearlySynthesisInput {
    pub year: String,
    pub source_tags: Vec<String>,
    pub canonical_topics: Vec<String>,
}

/// Pure plan output. The three raw vectors are mutually exclusive and each is
/// deterministically ordered by timestamp then stable identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HygienePlan {
    pub schema_version: u16,
    pub topic_synonym_map_version: u16,
    pub raw_retention_days: i64,
    pub yearly_horizon_days: i64,
    pub dedup_jaccard_basis_points: u16,
    pub migration: HygieneMigrationReport,
    pub retained_raw: Vec<RawReflection>,
    pub expired_raw: Vec<RawReflection>,
    pub duplicate_raw: Vec<DuplicateRawReflection>,
    pub yearly_inputs: Vec<YearlySynthesisInput>,
}

/// A visible refusal to plan malformed or unsupported data. No error is
/// silently converted into a retention or deletion decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HygieneError {
    UnknownSchemaVersion {
        found: u16,
    },
    UnknownSynonymMapVersion {
        found: u16,
    },
    EmptyRawId {
        index: usize,
    },
    DuplicateRawId {
        id: String,
    },
    FutureTimestamp {
        source: String,
        timestamp: i64,
        now_unix: i64,
    },
    InvalidPeriodReflection {
        source: String,
        reason: &'static str,
    },
    InvalidSynonym {
        alias: String,
        canonical: String,
    },
    SynonymCycle {
        alias: String,
    },
}

impl fmt::Display for HygieneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownSchemaVersion { found } => {
                write!(f, "unsupported reflection-hygiene schema version {found}")
            }
            Self::UnknownSynonymMapVersion { found } => {
                write!(
                    f,
                    "unsupported reflection topic-synonym map version {found}"
                )
            }
            Self::EmptyRawId { index } => write!(f, "raw reflection at index {index} has no id"),
            Self::DuplicateRawId { id } => write!(f, "raw reflection id {id:?} is duplicated"),
            Self::FutureTimestamp {
                source,
                timestamp,
                now_unix,
            } => write!(
                f,
                "reflection {source:?} timestamp {timestamp} is after planner time {now_unix}"
            ),
            Self::InvalidPeriodReflection { source, reason } => {
                write!(f, "period reflection {source:?} is invalid: {reason}")
            }
            Self::InvalidSynonym { alias, canonical } => write!(
                f,
                "topic synonym {alias:?} -> {canonical:?} becomes empty after normalization"
            ),
            Self::SynonymCycle { alias } => {
                write!(f, "topic synonym graph contains a cycle at {alias:?}")
            }
        }
    }
}

impl std::error::Error for HygieneError {}

/// Converts the old, unversioned in-memory representation without changing any
/// embedded [`PeriodReflection`] fields. The returned report makes migration a
/// durable caller-visible decision instead of an implicit fallback.
pub fn migrate_legacy(
    legacy: LegacyHygieneInput,
) -> (VersionedHygieneInput, HygieneMigrationReport) {
    let report = HygieneMigrationReport::MigratedLegacyPeriodReflections {
        raw_reflection_count: legacy.raw_reflections.len(),
        period_reflection_count: legacy.period_reflections.len(),
    };
    (
        VersionedHygieneInput {
            schema_version: HYGIENE_PLAN_SCHEMA_VERSION,
            now_unix: legacy.now_unix,
            raw_reflections: legacy.raw_reflections,
            period_reflections: legacy.period_reflections,
            topic_synonyms: legacy.topic_synonyms,
        },
        report,
    )
}

/// Builds a plan for native V1 input.
pub fn plan_versioned(input: VersionedHygieneInput) -> Result<HygienePlan, HygieneError> {
    plan_with_migration(input, HygieneMigrationReport::NativeV1)
}

/// Builds a plan after reporting an explicit legacy migration.
pub fn plan_legacy(input: LegacyHygieneInput) -> Result<HygienePlan, HygieneError> {
    let (versioned, migration) = migrate_legacy(input);
    plan_with_migration(versioned, migration)
}

/// Normalizes a topic without locale-dependent state: trims, lowercases,
/// treats whitespace/`_`/`-` as one space, and drops remaining punctuation.
pub fn normalize_topic(topic: &str) -> String {
    let mut normalized = String::new();
    let mut pending_space = false;

    for character in topic.trim().chars() {
        if character.is_alphanumeric() {
            if pending_space && !normalized.is_empty() {
                normalized.push(' ');
            }
            pending_space = false;
            normalized.extend(character.to_lowercase());
        } else if character.is_whitespace() || matches!(character, '_' | '-') {
            pending_space = true;
        }
    }

    normalized
}

/// Calculates integer Jaccard similarity in basis points. Two empty sets are
/// intentionally `0`, not an exact match, so no empty-topic reflections are
/// automatically discarded as duplicates.
pub fn jaccard_basis_points(left: &BTreeSet<String>, right: &BTreeSet<String>) -> u16 {
    if left.is_empty() && right.is_empty() {
        return 0;
    }

    let intersection = left.intersection(right).count() as u64;
    let union = left.union(right).count() as u64;
    ((intersection * u64::from(EXACT_TOPIC_MATCH_BPS)) / union) as u16
}

fn plan_with_migration(
    input: VersionedHygieneInput,
    migration: HygieneMigrationReport,
) -> Result<HygienePlan, HygieneError> {
    if input.schema_version != HYGIENE_PLAN_SCHEMA_VERSION {
        return Err(HygieneError::UnknownSchemaVersion {
            found: input.schema_version,
        });
    }

    let synonyms = normalized_synonym_map(&input.topic_synonyms)?;
    validate_input(&input)?;

    let raw_cutoff = input
        .now_unix
        .saturating_sub(RAW_RETENTION_DAYS.saturating_mul(SECONDS_PER_DAY));
    let mut prepared_raw = input
        .raw_reflections
        .into_iter()
        .map(|raw| {
            let canonical_topics = canonical_topic_set(&raw.reflection.topics, &synonyms);
            (raw, canonical_topics)
        })
        .collect::<Vec<_>>();
    prepared_raw.sort_by(|(left, _), (right, _)| {
        left.recorded_at_unix
            .cmp(&right.recorded_at_unix)
            .then_with(|| left.id.cmp(&right.id))
    });

    let mut retained_raw = Vec::new();
    let mut expired_raw = Vec::new();
    let mut duplicate_raw = Vec::new();
    let mut representatives = BTreeMap::<Vec<String>, String>::new();

    for (raw, canonical_topics) in prepared_raw {
        if raw.recorded_at_unix < raw_cutoff {
            expired_raw.push(raw);
            continue;
        }

        let signature = canonical_topics.iter().cloned().collect::<Vec<_>>();
        if !signature.is_empty() {
            if let Some(retained_raw_id) = representatives.get(&signature) {
                duplicate_raw.push(DuplicateRawReflection {
                    raw,
                    retained_raw_id: retained_raw_id.clone(),
                    jaccard_basis_points: EXACT_TOPIC_MATCH_BPS,
                });
                continue;
            }
            representatives.insert(signature, raw.id.clone());
        }

        retained_raw.push(raw);
    }

    let yearly_inputs = derive_yearly_inputs(&input.period_reflections, input.now_unix, &synonyms);

    Ok(HygienePlan {
        schema_version: HYGIENE_PLAN_SCHEMA_VERSION,
        topic_synonym_map_version: input.topic_synonyms.version,
        raw_retention_days: RAW_RETENTION_DAYS,
        yearly_horizon_days: YEARLY_HORIZON_DAYS,
        dedup_jaccard_basis_points: EXACT_TOPIC_MATCH_BPS,
        migration,
        retained_raw,
        expired_raw,
        duplicate_raw,
        yearly_inputs,
    })
}

fn validate_input(input: &VersionedHygieneInput) -> Result<(), HygieneError> {
    let mut ids = BTreeSet::new();
    for (index, raw) in input.raw_reflections.iter().enumerate() {
        if raw.id.trim().is_empty() {
            return Err(HygieneError::EmptyRawId { index });
        }
        if !ids.insert(raw.id.clone()) {
            return Err(HygieneError::DuplicateRawId { id: raw.id.clone() });
        }
        if raw.recorded_at_unix > input.now_unix {
            return Err(HygieneError::FutureTimestamp {
                source: raw.id.clone(),
                timestamp: raw.recorded_at_unix,
                now_unix: input.now_unix,
            });
        }
        validate_period_reflection(&raw.reflection, &format!("raw:{}", raw.id), input.now_unix)?;
    }

    for reflection in &input.period_reflections {
        validate_period_reflection(
            reflection,
            &format!("period:{}", reflection.tag),
            input.now_unix,
        )?;
    }

    Ok(())
}

fn validate_period_reflection(
    reflection: &PeriodReflection,
    source: &str,
    now_unix: i64,
) -> Result<(), HygieneError> {
    if reflection.generated_ts_unix > now_unix {
        return Err(HygieneError::FutureTimestamp {
            source: source.to_string(),
            timestamp: reflection.generated_ts_unix,
            now_unix,
        });
    }

    match reflection.kind.as_str() {
        "daily" if is_daily_tag(&reflection.tag) => Ok(()),
        "yearly" if is_year_tag(&reflection.tag) => Ok(()),
        "daily" | "yearly" => Err(HygieneError::InvalidPeriodReflection {
            source: source.to_string(),
            reason: "tag does not match its cadence",
        }),
        _ => Err(HygieneError::InvalidPeriodReflection {
            source: source.to_string(),
            reason: "kind must be daily or yearly",
        }),
    }
}

fn is_year_tag(tag: &str) -> bool {
    tag.len() == 4
        && tag.bytes().all(|byte| byte.is_ascii_digit())
        && decimal_component(tag.as_bytes()) != 0
}

fn is_daily_tag(tag: &str) -> bool {
    let bytes = tag.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit())
    {
        return false;
    }

    let year = decimal_component(&bytes[0..4]);
    let month = decimal_component(&bytes[5..7]);
    let day = decimal_component(&bytes[8..10]);
    if year == 0 || !(1..=12).contains(&month) {
        return false;
    }

    day >= 1 && day <= days_in_month(year, month)
}

fn decimal_component(bytes: &[u8]) -> u16 {
    bytes.iter().fold(0_u16, |value, byte| {
        value * 10 + u16::from(byte.saturating_sub(b'0'))
    })
}

fn days_in_month(year: u16, month: u16) -> u16 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: u16) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn normalized_synonym_map(
    source: &TopicSynonymMap,
) -> Result<BTreeMap<String, String>, HygieneError> {
    if source.version != TOPIC_SYNONYM_MAP_VERSION {
        return Err(HygieneError::UnknownSynonymMapVersion {
            found: source.version,
        });
    }

    let mut direct = BTreeMap::new();
    for (alias, canonical) in &source.entries {
        let normalized_alias = normalize_topic(alias);
        let normalized_canonical = normalize_topic(canonical);
        if normalized_alias.is_empty() || normalized_canonical.is_empty() {
            return Err(HygieneError::InvalidSynonym {
                alias: alias.clone(),
                canonical: canonical.clone(),
            });
        }
        if normalized_alias == normalized_canonical {
            continue;
        }
        if let Some(previous) =
            direct.insert(normalized_alias.clone(), normalized_canonical.clone())
            && previous != normalized_canonical
        {
            return Err(HygieneError::InvalidSynonym {
                alias: normalized_alias,
                canonical: normalized_canonical,
            });
        }
    }

    let mut resolved = BTreeMap::new();
    for alias in direct.keys() {
        let mut current = alias.clone();
        let mut seen = BTreeSet::new();
        while let Some(next) = direct.get(&current) {
            if !seen.insert(current.clone()) {
                return Err(HygieneError::SynonymCycle {
                    alias: alias.clone(),
                });
            }
            current = next.clone();
        }
        resolved.insert(alias.clone(), current);
    }
    Ok(resolved)
}

fn canonical_topic_set(topics: &[String], synonyms: &BTreeMap<String, String>) -> BTreeSet<String> {
    topics
        .iter()
        .map(|topic| normalize_topic(topic))
        .filter(|topic| !topic.is_empty())
        .map(|topic| synonyms.get(&topic).cloned().unwrap_or(topic))
        .collect()
}

fn derive_yearly_inputs(
    period_reflections: &[PeriodReflection],
    now_unix: i64,
    synonyms: &BTreeMap<String, String>,
) -> Vec<YearlySynthesisInput> {
    let cutoff = now_unix.saturating_sub(YEARLY_HORIZON_DAYS.saturating_mul(SECONDS_PER_DAY));
    let mut groups = BTreeMap::<String, (BTreeSet<String>, BTreeSet<String>)>::new();

    for reflection in period_reflections {
        // Yearly output is not fed back into a later yearly synthesis. The
        // only source is supplied daily period/rollup data within the horizon.
        if reflection.kind != "daily"
            || reflection.generated_ts_unix < cutoff
            || reflection.generated_ts_unix > now_unix
        {
            continue;
        }

        let year = reflection.tag[..4].to_string();
        let (source_tags, canonical_topics) = groups
            .entry(year)
            .or_insert_with(|| (BTreeSet::new(), BTreeSet::new()));
        source_tags.insert(reflection.tag.clone());
        canonical_topics.extend(canonical_topic_set(&reflection.topics, synonyms));
    }

    groups
        .into_iter()
        .map(
            |(year, (source_tags, canonical_topics))| YearlySynthesisInput {
                year,
                source_tags: source_tags.into_iter().collect(),
                canonical_topics: canonical_topics.into_iter().collect(),
            },
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day(day: i64) -> i64 {
        day * SECONDS_PER_DAY
    }

    fn period(kind: &str, tag: &str, timestamp: i64, topics: &[&str]) -> PeriodReflection {
        PeriodReflection {
            kind: kind.to_string(),
            tag: tag.to_string(),
            generated_ts_unix: timestamp,
            topics: topics.iter().map(|topic| (*topic).to_string()).collect(),
            body: "unchanged historical body".to_string(),
            tags: vec!["historical-tag".to_string()],
        }
    }

    fn raw(id: &str, timestamp: i64, topics: &[&str]) -> RawReflection {
        RawReflection {
            id: id.to_string(),
            recorded_at_unix: timestamp,
            reflection: period("daily", "2026-01-01", timestamp, topics),
        }
    }

    fn input(now_unix: i64) -> VersionedHygieneInput {
        VersionedHygieneInput {
            schema_version: HYGIENE_PLAN_SCHEMA_VERSION,
            now_unix,
            raw_reflections: Vec::new(),
            period_reflections: Vec::new(),
            topic_synonyms: TopicSynonymMap::default(),
        }
    }

    #[test]
    fn ninety_day_boundary_is_retained_and_older_raw_is_expired() {
        let now = day(200);
        let mut request = input(now);
        request.raw_reflections = vec![
            raw("exact-boundary", now - day(90), &["rust"]),
            raw("one-second-older", now - day(90) - 1, &["async"]),
        ];

        let plan = plan_versioned(request).expect("valid boundary plan");
        assert_eq!(plan.retained_raw.len(), 1);
        assert_eq!(plan.retained_raw[0].id, "exact-boundary");
        assert_eq!(plan.expired_raw.len(), 1);
        assert_eq!(plan.expired_raw[0].id, "one-second-older");
        assert!(plan.duplicate_raw.is_empty());
    }

    #[test]
    fn input_permutations_produce_the_same_plan() {
        let now = day(500);
        let mut first = input(now);
        first
            .topic_synonyms
            .entries
            .insert("ml".into(), "machine learning".into());
        first.raw_reflections = vec![
            raw("later", now - day(1), &["ML"]),
            raw("first", now - day(2), &["machine-learning"]),
            raw("other", now - day(3), &["rust"]),
        ];
        first.period_reflections = vec![
            period("daily", "2026-02-02", now - day(2), &["ML"]),
            period("daily", "2026-02-01", now - day(3), &["rust"]),
        ];

        let mut second = first.clone();
        second.raw_reflections.reverse();
        second.period_reflections.reverse();

        assert_eq!(
            plan_versioned(first).expect("first ordering"),
            plan_versioned(second).expect("second ordering")
        );
    }

    #[test]
    fn jaccard_is_integer_basis_points_and_empty_sets_never_match() {
        let left = BTreeSet::from(["async".to_string(), "rust".to_string()]);
        let right = BTreeSet::from(["rust".to_string(), "web".to_string()]);
        assert_eq!(jaccard_basis_points(&left, &right), 3_333);
        assert_eq!(jaccard_basis_points(&left, &left), EXACT_TOPIC_MATCH_BPS);
        assert_eq!(jaccard_basis_points(&BTreeSet::new(), &BTreeSet::new()), 0);
    }

    #[test]
    fn synonyms_canonicalize_topics_and_empty_normalized_topics_are_ignored() {
        let mut map = TopicSynonymMap::default();
        map.entries.insert("ML".into(), "Machine Learning".into());
        let synonyms = normalized_synonym_map(&map).expect("valid map");
        let topics = canonical_topic_set(
            &[" ml ".into(), "machine-learning".into(), "!!!".into()],
            &synonyms,
        );
        assert_eq!(topics, BTreeSet::from(["machine learning".to_string()]));
    }

    #[test]
    fn deduplication_requires_an_exact_non_empty_topic_match() {
        let now = day(200);
        let mut request = input(now);
        request.raw_reflections = vec![
            raw("representative", now - day(3), &["rust", "async"]),
            raw("partial-overlap", now - day(2), &["rust", "web"]),
            raw("exact-match", now - day(1), &["async", "rust"]),
            raw("empty-one", now, &[]),
            raw("empty-two", now - 1, &[]),
        ];

        let plan = plan_versioned(request).expect("valid dedup plan");
        assert_eq!(
            plan.retained_raw
                .iter()
                .map(|raw| raw.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "representative",
                "partial-overlap",
                "empty-two",
                "empty-one"
            ]
        );
        assert_eq!(plan.duplicate_raw.len(), 1);
        assert_eq!(plan.duplicate_raw[0].raw.id, "exact-match");
        assert_eq!(plan.duplicate_raw[0].retained_raw_id, "representative");
        assert_eq!(plan.duplicate_raw[0].jaccard_basis_points, 10_000);
    }

    #[test]
    fn yearly_inputs_use_only_supplied_daily_period_data_inside_one_year() {
        let now = day(500);
        let mut request = input(now);
        request.raw_reflections = vec![raw("raw-only", now - day(1), &["must not leak"])];
        request.period_reflections = vec![
            period("daily", "2025-01-01", now - day(365), &["period topic"]),
            period("daily", "2024-12-31", now - day(365) - 1, &["old topic"]),
            period("yearly", "2025", now - day(1), &["prior yearly output"]),
        ];

        let plan = plan_versioned(request).expect("valid yearly plan");
        assert_eq!(
            plan.yearly_inputs,
            vec![YearlySynthesisInput {
                year: "2025".to_string(),
                source_tags: vec!["2025-01-01".to_string()],
                canonical_topics: vec!["period topic".to_string()],
            }]
        );
    }

    #[test]
    fn legacy_migration_preserves_period_reflection_fields_and_reports_it() {
        let now = day(200);
        let preserved = PeriodReflection {
            kind: "daily".to_string(),
            tag: "2026-01-01".to_string(),
            generated_ts_unix: now - 1,
            topics: vec!["Rust".to_string()],
            body: "legacy body is kept verbatim".to_string(),
            tags: vec!["operator".to_string(), "history".to_string()],
        };
        let legacy = LegacyHygieneInput {
            now_unix: now,
            raw_reflections: Vec::new(),
            period_reflections: vec![preserved.clone()],
            topic_synonyms: TopicSynonymMap::default(),
        };

        let (migrated, report) = migrate_legacy(legacy);
        assert_eq!(migrated.period_reflections, vec![preserved]);
        assert_eq!(
            report,
            HygieneMigrationReport::MigratedLegacyPeriodReflections {
                raw_reflection_count: 0,
                period_reflection_count: 1,
            }
        );
        assert!(matches!(
            plan_legacy(LegacyHygieneInput {
                now_unix: now,
                raw_reflections: Vec::new(),
                period_reflections: Vec::new(),
                topic_synonyms: TopicSynonymMap::default(),
            })
            .expect("migrated legacy plan")
            .migration,
            HygieneMigrationReport::MigratedLegacyPeriodReflections { .. }
        ));
    }

    #[test]
    fn unknown_versions_and_corrupt_input_fail_visibly() {
        let mut unknown_schema = input(day(200));
        unknown_schema.schema_version = HYGIENE_PLAN_SCHEMA_VERSION + 1;
        assert_eq!(
            plan_versioned(unknown_schema),
            Err(HygieneError::UnknownSchemaVersion {
                found: HYGIENE_PLAN_SCHEMA_VERSION + 1,
            })
        );

        let mut unknown_synonyms = input(day(200));
        unknown_synonyms.topic_synonyms.version = TOPIC_SYNONYM_MAP_VERSION + 1;
        assert_eq!(
            plan_versioned(unknown_synonyms),
            Err(HygieneError::UnknownSynonymMapVersion {
                found: TOPIC_SYNONYM_MAP_VERSION + 1,
            })
        );

        let mut corrupt = input(day(200));
        corrupt.raw_reflections.push(raw("", day(199), &["rust"]));
        assert_eq!(
            plan_versioned(corrupt),
            Err(HygieneError::EmptyRawId { index: 0 })
        );
    }

    #[test]
    fn malformed_calendar_dates_fail_before_an_expiry_decision() {
        let now = day(200);
        for invalid_tag in ["2025-02-30", "2025-13-01", "2025-00-01"] {
            let mut request = input(now);
            let mut invalid_raw = raw("would-expire", now - day(91), &["rust"]);
            invalid_raw.reflection.tag = invalid_tag.to_string();
            request.raw_reflections.push(invalid_raw);

            assert!(matches!(
                plan_versioned(request),
                Err(HygieneError::InvalidPeriodReflection { .. })
            ));
        }
        assert!(is_daily_tag("2024-02-29"));
        assert!(!is_daily_tag("2025-02-29"));

        let mut yearly_zero = input(now);
        let mut invalid_raw = raw("year-zero", now - day(91), &["rust"]);
        invalid_raw.reflection.kind = "yearly".to_string();
        invalid_raw.reflection.tag = "0000".to_string();
        yearly_zero.raw_reflections.push(invalid_raw);
        assert!(matches!(
            plan_versioned(yearly_zero),
            Err(HygieneError::InvalidPeriodReflection { .. })
        ));
    }

    #[test]
    fn synonym_cycles_fail_before_any_plan_is_emitted() {
        let mut request = input(day(200));
        request
            .topic_synonyms
            .entries
            .insert("a".into(), "b".into());
        request
            .topic_synonyms
            .entries
            .insert("b".into(), "a".into());
        assert!(matches!(
            plan_versioned(request),
            Err(HygieneError::SynonymCycle { .. })
        ));
    }
}
