//! Capability-bound Obsidian export for canonical weekly reflections.
//!
//! The legacy reflection exporter stays deliberately tolerant for historical
//! reads. This producer-facing path validates a complete bounded JSONL source
//! before it creates any vault directory or replaces a note.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::skills::store::{
    atomic_write_private_child_reported, open_absolute_bound_directory, open_bound_regular_file,
    open_or_create_private_child_dir, open_real_child_dir_if_present, read_regular_file_bounded,
    PrivateChildCommit,
};

use super::weekly_archive::{
    validate_archived_weekly_intent, validate_iso_week_tag,
    validate_weekly_reflection_producer_key,
};
use super::WeeklyReflection;

const REFLECTIONS_DIR: &str = "reflections";
const OBSIDIAN_REFLECTIONS_DIR: &str = "Reflections";
const MAX_SOURCE_BYTES: usize = 8 * 1024 * 1024;
const MAX_LINE_BYTES: usize = 256 * 1024;
const MAX_REFLECTIONS: usize = 1024;
const MAX_RENDERED_BYTES: usize = 8 * 1024 * 1024;
const MAX_INTENT_BYTES: usize = 128 * 1024;
const INTENTS_DIR: &str = "weekly-intents";

/// The post-publication boundary observed by [`sync_week_checked`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReflectionSyncDurability {
    NotWritten,
    PublishedAndSynced,
    PublishedDurabilityUnknown,
}

/// Result of a fully checked weekly Obsidian publication.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct CheckedReflectionSyncOutcome {
    pub(crate) iso_week_tag: String,
    pub(crate) written: bool,
    pub(crate) target_path: PathBuf,
    pub(crate) reflection_count: usize,
    pub(crate) bytes_written: usize,
    pub(crate) durability: ReflectionSyncDurability,
}

/// Validate and render one persisted weekly JSONL archive into Obsidian.
///
/// A missing home, reflection directory, or requested archive is a quiet
/// outcome and does not create the destination. Any present source is read
/// through retained no-follow capabilities and must validate completely before
/// this function opens the vault for mutation.
pub(crate) fn sync_week_checked(
    home: &Path,
    vault: &Path,
    subdir: &str,
    iso_week_tag: &str,
) -> Result<CheckedReflectionSyncOutcome> {
    validate_inputs(home, vault, subdir, iso_week_tag)?;

    let source_leaf = format!("{iso_week_tag}.jsonl");
    let source_display = home.join(REFLECTIONS_DIR).join(&source_leaf);
    let target_path = vault
        .join(subdir)
        .join(OBSIDIAN_REFLECTIONS_DIR)
        .join(format!("{iso_week_tag}.md"));

    let Some(home) = open_absolute_bound_directory(home, false, "weekly reflection sync home")? else {
        return Ok(quiet_outcome(iso_week_tag, target_path));
    };
    let reflections_display = home.display_path.join(REFLECTIONS_DIR);
    let Some(reflections_dir) = open_real_child_dir_if_present(
        &home.dir,
        OsStr::new(REFLECTIONS_DIR),
        &reflections_display,
    )? else {
        return Ok(quiet_outcome(iso_week_tag, target_path));
    };
    let source_bytes = match read_regular_file_bounded(
        &reflections_dir,
        OsStr::new(&source_leaf),
        &source_display,
        MAX_SOURCE_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(error) if error_is_not_found(&error) => return Ok(quiet_outcome(iso_week_tag, target_path)),
        Err(error) => return Err(error).context("read checked weekly reflection JSONL"),
    };
    let reflections = parse_checked_reflections(&source_bytes, iso_week_tag)?;
    if reflections.is_empty() {
        return Ok(quiet_outcome(iso_week_tag, target_path));
    }
    validate_producer_owned_record(
        &reflections,
        &reflections_dir,
        &reflections_display,
        iso_week_tag,
    )?;

    let body = render_checked_reflections(&reflections)?;
    let reflection_count = reflections.len();
    let bytes_written = body.len();

    let vault = open_absolute_bound_directory(vault, true, "Obsidian vault")?
        .context("create or open explicit Obsidian vault")?;
    let subdir_display = vault.display_path.join(subdir);
    let subdir_dir = open_or_create_private_child_dir(
        &vault.dir,
        OsStr::new(subdir),
        &subdir_display,
    )?;
    let target_dir_display = subdir_display.join(OBSIDIAN_REFLECTIONS_DIR);
    let target_dir = open_or_create_private_child_dir(
        &subdir_dir,
        OsStr::new(OBSIDIAN_REFLECTIONS_DIR),
        &target_dir_display,
    )?;
    let target_leaf = format!("{iso_week_tag}.md");
    reject_unsafe_existing_target(&target_dir, OsStr::new(&target_leaf), &target_path)?;

    let durability = match atomic_write_private_child_reported(
        &target_dir,
        OsStr::new(&target_leaf),
        &target_path,
        body.as_bytes(),
    )? {
        PrivateChildCommit::PublishedAndSynced => ReflectionSyncDurability::PublishedAndSynced,
        PrivateChildCommit::PublishedDurabilityUnknown(reason) => {
            tracing::warn!(
                target = %target_path.display(),
                %reason,
                "weekly Obsidian reflection was published with unknown durability"
            );
            ReflectionSyncDurability::PublishedDurabilityUnknown
        }
    };

    Ok(CheckedReflectionSyncOutcome {
        iso_week_tag: iso_week_tag.to_owned(),
        written: true,
        target_path,
        reflection_count,
        bytes_written,
        durability,
    })
}

fn validate_inputs(home: &Path, vault: &Path, subdir: &str, iso_week_tag: &str) -> Result<()> {
    anyhow::ensure!(home.is_absolute(), "weekly reflection sync home must be an explicit absolute path");
    anyhow::ensure!(vault.is_absolute(), "Obsidian vault must be an explicit absolute path");
    validate_iso_week_tag(iso_week_tag)?;
    validate_subdir(subdir)
}

fn validate_subdir(subdir: &str) -> Result<()> {
    crate::cli::obsidian::validate_subdir(Path::new(subdir))
        .context("validate Obsidian reflection subdirectory")?;
    let mut components = Path::new(subdir).components();
    let Some(Component::Normal(component)) = components.next() else {
        anyhow::bail!("Obsidian subdirectory must be one normal path component: {subdir:?}");
    };
    anyhow::ensure!(
        components.next().is_none() && component == OsStr::new(subdir),
        "Obsidian subdirectory must be one normal path component: {subdir:?}"
    );
    Ok(())
}

fn quiet_outcome(iso_week_tag: &str, target_path: PathBuf) -> CheckedReflectionSyncOutcome {
    CheckedReflectionSyncOutcome {
        iso_week_tag: iso_week_tag.to_owned(),
        written: false,
        target_path,
        reflection_count: 0,
        bytes_written: 0,
        durability: ReflectionSyncDurability::NotWritten,
    }
}

fn parse_checked_reflections(bytes: &[u8], requested_week: &str) -> Result<Vec<WeeklyReflection>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    anyhow::ensure!(
        bytes.ends_with(b"\n"),
        "weekly reflection JSONL has a truncated final record"
    );
    let source = std::str::from_utf8(bytes).context("weekly reflection JSONL must be valid UTF-8")?;
    let mut reflections = Vec::new();
    let mut producer_keys = HashSet::new();
    for (index, raw) in source.split_inclusive('\n').enumerate() {
        let line = raw.strip_suffix('\n').expect("split_inclusive retains delimiter");
        let line = line.strip_suffix('\r').unwrap_or(line);
        anyhow::ensure!(
            !line.is_empty() && line.len() <= MAX_LINE_BYTES,
            "weekly reflection JSONL line {} is blank or exceeds the bounded line limit",
            index + 1
        );
        anyhow::ensure!(
            index < MAX_REFLECTIONS,
            "weekly reflection JSONL exceeds the {MAX_REFLECTIONS}-record limit"
        );
        let reflection = serde_json::from_str::<WeeklyReflection>(line)
            .with_context(|| format!("parse weekly reflection JSONL line {}", index + 1))?;
        anyhow::ensure!(
            reflection.iso_week_tag == requested_week,
            "weekly reflection JSONL line {} belongs to a different week",
            index + 1
        );
        if let Some(key) = reflection.producer_key.as_deref() {
            validate_weekly_reflection_producer_key(&reflection)?;
            anyhow::ensure!(
                producer_keys.insert(key.to_owned()),
                "weekly reflection JSONL contains duplicate producer key at line {}",
                index + 1
            );
        }
        reflections.push(reflection);
    }
    Ok(reflections)
}

/// Legacy source archives need no producer intent. A keyed producer record is
/// different: its immutable intent is the authority for every rendered field.
fn validate_producer_owned_record(
    reflections: &[WeeklyReflection],
    reflections_dir: &cap_std::fs::Dir,
    reflections_display: &Path,
    iso_week_tag: &str,
) -> Result<()> {
    let Some(record) = reflections.iter().find(|record| record.producer_key.is_some()) else {
        return Ok(());
    };
    anyhow::ensure!(
        reflections.iter().filter(|record| record.producer_key.is_some()).count() == 1,
        "weekly reflection JSONL must contain at most one producer-owned record"
    );
    let intents_display = reflections_display.join(INTENTS_DIR);
    let intents_dir = open_real_child_dir_if_present(
        reflections_dir,
        OsStr::new(INTENTS_DIR),
        &intents_display,
    )?
    .context("weekly producer record requires its immutable intent directory")?;
    let intent_leaf = format!("{iso_week_tag}.json");
    let intent_bytes = read_regular_file_bounded(
        &intents_dir,
        OsStr::new(&intent_leaf),
        &intents_display.join(&intent_leaf),
        MAX_INTENT_BYTES,
    )
    .context("read immutable weekly producer intent")?;
    validate_archived_weekly_intent(&intent_bytes, record)
        .context("weekly producer record must exactly match its immutable intent")
}

fn render_checked_reflections(reflections: &[WeeklyReflection]) -> Result<String> {
    let mut body = String::new();
    for reflection in reflections {
        if !body.is_empty() {
            append_bounded(&mut body, "\n---\n\n")?;
        }
        append_bounded(&mut body, &reflection.to_obsidian_md())?;
    }
    Ok(body)
}

fn append_bounded(output: &mut String, chunk: &str) -> Result<()> {
    let length = output
        .len()
        .checked_add(chunk.len())
        .context("rendered weekly reflection markdown length overflow")?;
    anyhow::ensure!(
        length <= MAX_RENDERED_BYTES,
        "rendered weekly reflection markdown exceeds the {}-byte limit",
        MAX_RENDERED_BYTES
    );
    output.push_str(chunk);
    Ok(())
}

fn reject_unsafe_existing_target(
    parent: &cap_std::fs::Dir,
    name: &OsStr,
    display_path: &Path,
) -> Result<()> {
    let (file, binding) = match open_bound_regular_file(parent, name, display_path) {
        Ok(bound) => bound,
        Err(error) if error_is_not_found(&error) => return Ok(()),
        Err(error) => return Err(error).context("inspect existing weekly Obsidian target"),
    };
    ensure_single_hard_link(&file)?;
    anyhow::ensure!(
        binding.matches_regular_file_child_readonly(parent, name, display_path)?,
        "existing weekly Obsidian target changed while its identity was bound: {}",
        display_path.display()
    );
    Ok(())
}

fn ensure_single_hard_link(file: &cap_std::fs::File) -> Result<()> {
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt as _;

        let links = file.metadata().context("read weekly Obsidian target link count")?.nlink();
        anyhow::ensure!(
            links == 1,
            "existing weekly Obsidian target has {links} hard links; exactly one is required"
        );
        Ok(())
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };

        let std_file = file
            .try_clone()
            .context("clone no-follow weekly Obsidian target handle")?
            .into_std();
        let mut information = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
        // SAFETY: `std_file` owns the no-follow-opened handle and Windows
        // initializes the complete structure when the call succeeds.
        anyhow::ensure!(
            unsafe { GetFileInformationByHandle(std_file.as_raw_handle() as _, information.as_mut_ptr()) } != 0,
            "read no-follow weekly Obsidian target link count: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: the preceding API call returned success.
        let information = unsafe { information.assume_init() };
        anyhow::ensure!(
            information.nNumberOfLinks == 1,
            "existing weekly Obsidian target has {} hard links; exactly one is required",
            information.nNumberOfLinks
        );
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        anyhow::bail!("Obsidian target hard-link checks are unsupported on this platform")
    }
}

fn error_is_not_found(error: &anyhow::Error) -> bool {
    error.chain().any(|source| {
        source
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_error| io_error.kind() == std::io::ErrorKind::NotFound)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::canonical_tempdir as tempdir;

    fn reflection(week: &str, body: &str) -> WeeklyReflection {
        WeeklyReflection {
            iso_week_tag: week.to_owned(),
            generated_ts_unix: 1_700_000_000,
            topics: vec!["rust".to_owned(), "memory".to_owned()],
            body: body.to_owned(),
            tags: vec!["checked".to_owned()],
            producer_key: None,
        }
    }

    fn source_file(home: &Path, week: &str) -> PathBuf {
        home.join(REFLECTIONS_DIR).join(format!("{week}.jsonl"))
    }

    fn target_file(vault: &Path, week: &str) -> PathBuf {
        vault
            .join("NEOTH")
            .join(OBSIDIAN_REFLECTIONS_DIR)
            .join(format!("{week}.md"))
    }

    fn write_source_bytes(home: &Path, week: &str, bytes: &[u8]) {
        std::fs::create_dir_all(home.join(REFLECTIONS_DIR)).unwrap();
        std::fs::write(source_file(home, week), bytes).unwrap();
    }

    fn write_source_reflections(home: &Path, week: &str, reflections: &[WeeklyReflection]) {
        let mut body = reflections
            .iter()
            .map(serde_json::to_string)
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
            .join("\n");
        body.push('\n');
        write_source_bytes(home, week, body.as_bytes());
    }

    fn write_canonical_producer_source(home: &Path, week: &str) -> WeeklyReflection {
        let mut session = crate::reflection::weekly_archive::open_weekly_archive_session(home, week)
            .unwrap();
        let intent = session
            .load_or_create_intent(crate::reflection::weekly_archive::WeeklyArchiveCandidate {
                generated_ts_unix: 1_700_000_000,
                topics: vec!["rust".to_owned(), "memory".to_owned()],
                body: "canonical producer body".to_owned(),
            })
            .unwrap();
        let record = intent.to_reflection();
        drop(session);
        write_source_reflections(home, week, std::slice::from_ref(&record));
        record
    }

    #[test]
    fn multirecord_source_preserves_order_separator_and_replaces_target_on_repeat() {
        let home = tempdir().unwrap();
        let vault = tempdir().unwrap();
        let week = "2026-W21";
        write_source_reflections(
            home.path(),
            week,
            &[reflection(week, "first body"), reflection(week, "second body")],
        );

        let first = sync_week_checked(home.path(), vault.path(), "NEOTH", week).unwrap();
        let target = target_file(vault.path(), week);
        let rendered = std::fs::read_to_string(&target).unwrap();
        let expected = format!(
            "{}\n---\n\n{}",
            reflection(week, "first body").to_obsidian_md(),
            reflection(week, "second body").to_obsidian_md(),
        );
        assert!(first.written);
        assert_eq!(first.target_path, target);
        assert_eq!(first.reflection_count, 2);
        assert_eq!(first.bytes_written, expected.len());
        assert_eq!(rendered, expected);

        let before_repeat = std::fs::read(&target).unwrap();
        let repeat = sync_week_checked(home.path(), vault.path(), "NEOTH", week).unwrap();
        assert_eq!(repeat.bytes_written, expected.len());
        assert_eq!(std::fs::read(&target).unwrap(), before_repeat);

        write_source_reflections(home.path(), week, &[reflection(week, "replacement body")]);
        let second = sync_week_checked(home.path(), vault.path(), "NEOTH", week).unwrap();
        let rendered = std::fs::read_to_string(target).unwrap();
        assert!(second.written);
        assert!(rendered.contains("replacement body"));
        assert!(!rendered.contains("first body"));
    }

    #[test]
    fn missing_source_is_quiet_without_creating_target() {
        let home = tempdir().unwrap();
        let workspace = tempdir().unwrap();
        let vault = workspace.path().join("missing-vault");
        let week = "2026-W21";

        let outcome = sync_week_checked(home.path(), &vault, "NEOTH", week).unwrap();

        assert!(!outcome.written);
        assert_eq!(outcome.durability, ReflectionSyncDurability::NotWritten);
        assert_eq!(outcome.target_path, target_file(&vault, week));
        assert!(!vault.exists());
    }

    #[test]
    fn malformed_source_and_limits_fail_closed_without_replacing_target() {
        let week = "2026-W21";
        for bytes in [b"{bad json}\n".as_slice(), b"\xff\n".as_slice(), b"\n".as_slice()] {
            let home = tempdir().unwrap();
            let vault = tempdir().unwrap();
            let target = target_file(vault.path(), week);
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::write(&target, "preserve me").unwrap();
            write_source_bytes(home.path(), week, bytes);
            assert!(sync_week_checked(home.path(), vault.path(), "NEOTH", week).is_err());
            assert_eq!(std::fs::read_to_string(target).unwrap(), "preserve me");
        }

        let home = tempdir().unwrap();
        let vault = tempdir().unwrap();
        write_source_bytes(home.path(), week, &vec![b'x'; MAX_SOURCE_BYTES + 1]);
        assert!(sync_week_checked(home.path(), vault.path(), "NEOTH", week).is_err());

        let home = tempdir().unwrap();
        let vault = tempdir().unwrap();
        let mut too_long_line = vec![b'x'; MAX_LINE_BYTES + 1];
        too_long_line.push(b'\n');
        write_source_bytes(home.path(), week, &too_long_line);
        assert!(sync_week_checked(home.path(), vault.path(), "NEOTH", week).is_err());
    }

    #[test]
    fn final_newline_week_and_producer_key_invariants_are_strict() {
        let week = "2026-W21";
        let home = tempdir().unwrap();
        let vault = tempdir().unwrap();
        let line = serde_json::to_string(&reflection(week, "body")).unwrap();
        write_source_bytes(home.path(), week, line.as_bytes());
        assert!(sync_week_checked(home.path(), vault.path(), "NEOTH", week).is_err());

        let home = tempdir().unwrap();
        let vault = tempdir().unwrap();
        write_source_reflections(home.path(), week, &[reflection("2026-W22", "body")]);
        assert!(sync_week_checked(home.path(), vault.path(), "NEOTH", week).is_err());

        let home = tempdir().unwrap();
        let vault = tempdir().unwrap();
        let keyed = write_canonical_producer_source(home.path(), week);
        write_source_reflections(home.path(), week, &[keyed.clone(), keyed]);
        assert!(sync_week_checked(home.path(), vault.path(), "NEOTH", week).is_err());
    }

    #[test]
    fn producer_record_must_match_its_immutable_intent() {
        let week = "2026-W21";
        let home = tempdir().unwrap();
        let vault = tempdir().unwrap();
        write_canonical_producer_source(home.path(), week);
        assert!(sync_week_checked(home.path(), vault.path(), "NEOTH", week).unwrap().written);

        let mutations: [fn(&mut WeeklyReflection); 3] = [
            |record: &mut WeeklyReflection| record.generated_ts_unix += 1,
            |record: &mut WeeklyReflection| record.tags.push("changed".to_owned()),
            |record: &mut WeeklyReflection| record.body.push_str(" changed"),
        ];
        for mutate in mutations {
            let home = tempdir().unwrap();
            let vault = tempdir().unwrap();
            let mut record = write_canonical_producer_source(home.path(), week);
            mutate(&mut record);
            write_source_reflections(home.path(), week, &[record]);
            assert!(sync_week_checked(home.path(), vault.path(), "NEOTH", week).is_err());
        }
    }

    #[test]
    fn missing_or_corrupt_producer_intent_preserves_existing_target() {
        let week = "2026-W21";
        for corrupt in [false, true] {
            let home = tempdir().unwrap();
            let vault = tempdir().unwrap();
            write_canonical_producer_source(home.path(), week);
            let intent = home
                .path()
                .join(REFLECTIONS_DIR)
                .join(INTENTS_DIR)
                .join(format!("{week}.json"));
            if corrupt {
                std::fs::write(&intent, b"{corrupt intent}\n").unwrap();
            } else {
                std::fs::remove_file(&intent).unwrap();
            }
            let target = target_file(vault.path(), week);
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::write(&target, "preserve me").unwrap();

            assert!(sync_week_checked(home.path(), vault.path(), "NEOTH", week).is_err());
            assert_eq!(std::fs::read_to_string(target).unwrap(), "preserve me");
        }
    }

    #[test]
    fn record_limit_subdir_and_week_validation_fail_before_destination_mutation() {
        let home = tempdir().unwrap();
        let vault = tempdir().unwrap();
        let week = "2026-W21";
        let line = serde_json::to_string(&reflection(week, "body")).unwrap();
        write_source_bytes(home.path(), week, format!("{}\n", line).repeat(MAX_REFLECTIONS + 1).as_bytes());
        assert!(sync_week_checked(home.path(), vault.path(), "NEOTH", week).is_err());
        assert!(sync_week_checked(home.path(), vault.path(), "../NEOTH", week).is_err());
        assert!(sync_week_checked(home.path(), vault.path(), "NEOTH", "2026-W54").is_err());
        assert!(sync_week_checked(home.path(), vault.path(), "NEOTH", "+2026-W21").is_err());
    }

    #[test]
    fn durability_tags_serialize_in_snake_case() {
        assert_eq!(serde_json::to_string(&ReflectionSyncDurability::NotWritten).unwrap(), "\"not_written\"");
        assert_eq!(
            serde_json::to_string(&ReflectionSyncDurability::PublishedAndSynced).unwrap(),
            "\"published_and_synced\""
        );
        assert_eq!(
            serde_json::to_string(&ReflectionSyncDurability::PublishedDurabilityUnknown).unwrap(),
            "\"published_durability_unknown\""
        );
    }

    #[cfg(unix)]
    #[test]
    fn linked_source_root_and_target_are_refused_without_touching_outside_files() {
        let week = "2026-W21";
        let home = tempdir().unwrap();
        let vault = tempdir().unwrap();
        let outside = tempdir().unwrap();
        std::fs::create_dir_all(outside.path().join(REFLECTIONS_DIR)).unwrap();
        write_source_reflections(outside.path(), week, &[reflection(week, "body")]);
        std::os::unix::fs::symlink(
            outside.path().join(REFLECTIONS_DIR),
            home.path().join(REFLECTIONS_DIR),
        )
        .unwrap();
        assert!(sync_week_checked(home.path(), vault.path(), "NEOTH", week).is_err());

        let home = tempdir().unwrap();
        write_source_reflections(home.path(), week, &[reflection(week, "body")]);
        let target = target_file(vault.path(), week);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        let sentinel = outside.path().join("keep.md");
        std::fs::write(&sentinel, "keep").unwrap();
        std::os::unix::fs::symlink(&sentinel, &target).unwrap();
        assert!(sync_week_checked(home.path(), vault.path(), "NEOTH", week).is_err());
        assert_eq!(std::fs::read_to_string(sentinel).unwrap(), "keep");

        let home = tempdir().unwrap();
        let workspace = tempdir().unwrap();
        write_source_reflections(home.path(), week, &[reflection(week, "body")]);
        let linked_vault = workspace.path().join("linked-vault");
        std::os::unix::fs::symlink(outside.path(), &linked_vault).unwrap();
        assert!(sync_week_checked(home.path(), &linked_vault, "NEOTH", week).is_err());
    }

    #[test]
    fn hardlinked_target_is_refused_and_preserved() {
        let home = tempdir().unwrap();
        let vault = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let week = "2026-W21";
        write_source_reflections(home.path(), week, &[reflection(week, "body")]);
        let target = target_file(vault.path(), week);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        let sentinel = outside.path().join("keep.md");
        std::fs::write(&sentinel, "keep").unwrap();
        std::fs::hard_link(&sentinel, &target).unwrap();

        assert!(sync_week_checked(home.path(), vault.path(), "NEOTH", week).is_err());
        assert_eq!(std::fs::read_to_string(sentinel).unwrap(), "keep");
    }

    #[cfg(unix)]
    #[test]
    fn linked_producer_intent_file_and_directory_are_refused() {
        let week = "2026-W21";
        for link_directory in [false, true] {
            let home = tempdir().unwrap();
            let vault = tempdir().unwrap();
            let outside = tempdir().unwrap();
            write_canonical_producer_source(home.path(), week);
            let intents = home.path().join(REFLECTIONS_DIR).join(INTENTS_DIR);
            let intent = intents.join(format!("{week}.json"));
            let sentinel = outside.path().join("intent.json");
            std::fs::write(&sentinel, "keep").unwrap();
            if link_directory {
                std::fs::remove_file(&intent).unwrap();
                std::fs::remove_dir(&intents).unwrap();
                std::os::unix::fs::symlink(outside.path(), &intents).unwrap();
            } else {
                std::fs::remove_file(&intent).unwrap();
                std::os::unix::fs::symlink(&sentinel, &intent).unwrap();
            }

            assert!(sync_week_checked(home.path(), vault.path(), "NEOTH", week).is_err());
            assert_eq!(std::fs::read_to_string(sentinel).unwrap(), "keep");
        }
    }

    #[test]
    fn post_commit_validation_failure_reports_published_durability_unknown() {
        let home = tempdir().unwrap();
        let vault = tempdir().unwrap();
        let week = "2026-W21";
        write_source_reflections(home.path(), week, &[reflection(week, "body")]);
        let target = target_file(vault.path(), week);
        crate::skills::store::fail_private_child_post_commit_validation_for_test(&target);

        let outcome = sync_week_checked(home.path(), vault.path(), "NEOTH", week).unwrap();

        assert!(outcome.written);
        assert_eq!(outcome.durability, ReflectionSyncDurability::PublishedDurabilityUnknown);
        assert!(std::fs::read_to_string(target).unwrap().contains("body"));
    }
}
