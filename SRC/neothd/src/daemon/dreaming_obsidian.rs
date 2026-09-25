//! Capability-bound Obsidian export for persisted daily dreams.
//!
//! This is intentionally separate from the legacy exporter in `dreaming`.
//! Callers supply both roots explicitly; source and destination traversal is
//! retained-directory-capability based, so no `HOME` or current-directory
//! lookup participates in the sync.

use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::skills::store::{
    PrivateChildCommit, atomic_write_private_child_reported, open_absolute_bound_directory,
    open_bound_regular_file, open_or_create_private_child_dir, open_real_child_dir_if_present,
    read_regular_file_bounded,
};

const DREAMS_DIR: &str = "dreams";
const OBSIDIAN_DREAMS_DIR: &str = "Dreams";
const MAX_SOURCE_BYTES: usize = 8 * 1024 * 1024;
const MAX_LINE_BYTES: usize = 256 * 1024;
const MAX_DREAMS: usize = 1024;
const MAX_RENDERED_BYTES: usize = 8 * 1024 * 1024;

/// The publication boundary observed by [`sync_day_checked`].
///
/// `PublishedDurabilityUnknown` never means that no file was written: the
/// atomic namespace commit already happened, but power-loss durability was not
/// confirmed. Callers must retain this distinction rather than retrying.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DreamSyncDurability {
    NotWritten,
    PublishedAndSynced,
    PublishedDurabilityUnknown,
}

/// Checked counterpart to the legacy [`super::dreaming::DreamSyncOutcome`].
///
/// It preserves the legacy fields while exposing the post-publication
/// durability boundary for audit and HTTP callers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct CheckedDreamSyncOutcome {
    pub(crate) day: String,
    pub(crate) written: bool,
    pub(crate) target_path: PathBuf,
    pub(crate) dream_count: usize,
    pub(crate) bytes_written: usize,
    pub(crate) durability: DreamSyncDurability,
}

/// Synchronize one checked daily JSONL file into an Obsidian note.
///
/// A missing source root, dreams directory, or daily file is a quiet day. A
/// present source is fail-closed: each line must be valid UTF-8 JSON for the
/// current [`super::dreaming::Dream`] schema and must name precisely `day`.
/// The target is reached only after a non-empty source has been completely
/// validated and rendered.
pub(crate) fn sync_day_checked(
    home: &Path,
    vault: &Path,
    subdir: &str,
    day: &str,
) -> Result<CheckedDreamSyncOutcome> {
    validate_inputs(home, vault, subdir, day)?;

    let source_display = home.join(DREAMS_DIR).join(format!("{day}.jsonl"));
    let target_path = vault
        .join(subdir)
        .join(OBSIDIAN_DREAMS_DIR)
        .join(format!("{day}.md"));
    let source_leaf = format!("{day}.jsonl");

    let Some(home) = open_absolute_bound_directory(home, false, "dream sync home")? else {
        return Ok(quiet_outcome(day, target_path));
    };
    let dreams_display = home.display_path.join(DREAMS_DIR);
    let Some(dreams_dir) =
        open_real_child_dir_if_present(&home.dir, OsStr::new(DREAMS_DIR), &dreams_display)?
    else {
        return Ok(quiet_outcome(day, target_path));
    };
    let source_bytes = match read_regular_file_bounded(
        &dreams_dir,
        OsStr::new(&source_leaf),
        &source_display,
        MAX_SOURCE_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(error) if error_is_not_found(&error) => return Ok(quiet_outcome(day, target_path)),
        Err(error) => return Err(error).context("read checked dream JSONL"),
    };
    let source = std::str::from_utf8(&source_bytes).context("dream JSONL must be valid UTF-8")?;
    let dreams = parse_checked_dreams(source, day)?;
    if dreams.is_empty() {
        return Ok(quiet_outcome(day, target_path));
    }

    let body = render_checked_dreams(&dreams)?;
    let dream_count = dreams.len();
    let bytes_written = body.len();

    let vault = open_absolute_bound_directory(vault, true, "Obsidian vault")?
        .context("create or open explicit Obsidian vault")?;
    let subdir_display = vault.display_path.join(subdir);
    let subdir_dir =
        open_or_create_private_child_dir(&vault.dir, OsStr::new(subdir), &subdir_display)?;
    let target_dir_display = subdir_display.join(OBSIDIAN_DREAMS_DIR);
    let target_dir = open_or_create_private_child_dir(
        &subdir_dir,
        OsStr::new(OBSIDIAN_DREAMS_DIR),
        &target_dir_display,
    )?;
    let target_leaf = format!("{day}.md");
    reject_unsafe_existing_target(&target_dir, OsStr::new(&target_leaf), &target_path)?;

    let durability = match atomic_write_private_child_reported(
        &target_dir,
        OsStr::new(&target_leaf),
        &target_path,
        body.as_bytes(),
    )? {
        PrivateChildCommit::PublishedAndSynced => DreamSyncDurability::PublishedAndSynced,
        PrivateChildCommit::PublishedDurabilityUnknown(reason) => {
            // The namespace commit has already happened. Returning an error
            // here would invite a caller to retry a completed publication.
            tracing::warn!(
                target = %target_path.display(),
                %reason,
                "dream Obsidian note was published but parent durability is unknown"
            );
            DreamSyncDurability::PublishedDurabilityUnknown
        }
    };

    Ok(CheckedDreamSyncOutcome {
        day: day.to_owned(),
        written: true,
        target_path,
        dream_count,
        bytes_written,
        durability,
    })
}

fn validate_inputs(home: &Path, vault: &Path, subdir: &str, day: &str) -> Result<()> {
    anyhow::ensure!(
        home.is_absolute(),
        "dream sync home must be an explicit absolute path"
    );
    anyhow::ensure!(
        vault.is_absolute(),
        "Obsidian vault must be an explicit absolute path"
    );
    validate_day(day)?;
    validate_subdir(subdir)
}

fn validate_day(day: &str) -> Result<()> {
    let bytes = day.as_bytes();
    anyhow::ensure!(
        bytes.len() == 10
            && bytes[4] == b'-'
            && bytes[7] == b'-'
            && bytes
                .iter()
                .enumerate()
                .all(|(index, byte)| matches!(index, 4 | 7) || (*byte).is_ascii_digit()),
        "dream day must be canonical YYYY-MM-DD: {day:?}"
    );
    let parsed = chrono::NaiveDate::parse_from_str(day, "%Y-%m-%d")
        .with_context(|| format!("dream day must be canonical YYYY-MM-DD: {day:?}"))?;
    anyhow::ensure!(
        parsed.format("%Y-%m-%d").to_string() == day,
        "dream day must be canonical YYYY-MM-DD: {day:?}"
    );
    Ok(())
}

fn validate_subdir(subdir: &str) -> Result<()> {
    crate::cli::obsidian::validate_subdir(Path::new(subdir))
        .context("validate Obsidian dream subdirectory")?;
    let mut components = Path::new(subdir).components();
    let Some(Component::Normal(component)) = components.next() else {
        anyhow::bail!("Obsidian subdirectory must be one normal path component: {subdir:?}");
    };
    let valid = components.next().is_none() && component == OsStr::new(subdir);
    anyhow::ensure!(
        valid,
        "Obsidian subdirectory must be one normal path component: {subdir:?}"
    );
    Ok(())
}

fn quiet_outcome(day: &str, target_path: PathBuf) -> CheckedDreamSyncOutcome {
    CheckedDreamSyncOutcome {
        day: day.to_owned(),
        written: false,
        target_path,
        dream_count: 0,
        bytes_written: 0,
        durability: DreamSyncDurability::NotWritten,
    }
}

fn parse_checked_dreams(source: &str, requested_day: &str) -> Result<Vec<super::dreaming::Dream>> {
    let mut dreams = Vec::new();
    for (index, line) in source.lines().enumerate() {
        anyhow::ensure!(
            line.len() <= MAX_LINE_BYTES,
            "dream JSONL line {} exceeds the {}-byte limit",
            index + 1,
            MAX_LINE_BYTES
        );
        anyhow::ensure!(
            !line.trim().is_empty(),
            "dream JSONL line {} must not be blank",
            index + 1
        );
        anyhow::ensure!(
            dreams.len() < MAX_DREAMS,
            "dream JSONL exceeds the {MAX_DREAMS}-record limit"
        );
        let dream = serde_json::from_str::<super::dreaming::Dream>(line)
            .with_context(|| format!("parse dream JSONL line {}", index + 1))?;
        anyhow::ensure!(
            dream.day == requested_day,
            "dream JSONL line {} names day {:?}, expected {:?}",
            index + 1,
            dream.day,
            requested_day
        );
        dreams.push(dream);
    }
    Ok(dreams)
}

fn render_checked_dreams(dreams: &[super::dreaming::Dream]) -> Result<String> {
    let mut body = String::new();
    for dream in dreams {
        if !body.is_empty() {
            append_bounded(&mut body, "\n---\n\n")?;
        }
        append_bounded(&mut body, &dream.to_obsidian_md())?;
    }
    Ok(body)
}

fn append_bounded(output: &mut String, chunk: &str) -> Result<()> {
    let len = output
        .len()
        .checked_add(chunk.len())
        .context("rendered dream markdown length overflow")?;
    anyhow::ensure!(
        len <= MAX_RENDERED_BYTES,
        "rendered dream markdown exceeds the {}-byte limit",
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
        Err(error) => return Err(error).context("inspect existing Obsidian dream target"),
    };
    ensure_single_hard_link(&file)?;
    anyhow::ensure!(
        binding.matches_regular_file_child_readonly(parent, name, display_path)?,
        "existing Obsidian dream target changed while its identity was bound: {}",
        display_path.display()
    );
    Ok(())
}

/// A checked target must be a single-link regular file. The count comes from
/// the no-follow-opened handle; platforms without an equivalent fail closed.
fn ensure_single_hard_link(file: &cap_std::fs::File) -> Result<()> {
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt as _;

        let links = file
            .metadata()
            .context("read no-follow Obsidian target link count")?
            .nlink();
        anyhow::ensure!(
            links == 1,
            "existing Obsidian dream target has {links} hard links; exactly one is required"
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
            .context("clone no-follow Obsidian target handle")?
            .into_std();
        let mut information = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
        // SAFETY: `std_file` owns the no-follow-opened target handle and the
        // Windows API initializes the complete output on success.
        anyhow::ensure!(
            unsafe {
                GetFileInformationByHandle(std_file.as_raw_handle() as _, information.as_mut_ptr())
            } != 0,
            "read no-follow Obsidian target link count: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: the preceding API call returned success.
        let information = unsafe { information.assume_init() };
        anyhow::ensure!(
            information.nNumberOfLinks == 1,
            "existing Obsidian dream target has {} hard links; exactly one is required",
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
    use tempfile::tempdir;

    fn dream(day: &str, theme: &str, summary: &str) -> super::super::dreaming::Dream {
        super::super::dreaming::Dream {
            composed_ts_unix: 42,
            day: day.to_owned(),
            theme_label: theme.to_owned(),
            summary: summary.to_owned(),
            event_ids: vec![7],
            tags: vec!["checked".to_owned()],
        }
    }

    fn source_file(home: &Path, day: &str) -> PathBuf {
        home.join(DREAMS_DIR).join(format!("{day}.jsonl"))
    }

    fn write_source_bytes(home: &Path, day: &str, bytes: &[u8]) {
        std::fs::create_dir_all(home.join(DREAMS_DIR)).unwrap();
        std::fs::write(source_file(home, day), bytes).unwrap();
    }

    fn write_source_dreams(home: &Path, day: &str, dreams: &[super::super::dreaming::Dream]) {
        let mut body = dreams
            .iter()
            .map(serde_json::to_string)
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
            .join("\n");
        body.push('\n');
        write_source_bytes(home, day, body.as_bytes());
    }

    #[test]
    fn valid_day_renders_and_repeated_sync_replaces_target() {
        let home = tempdir().unwrap();
        let vault = tempdir().unwrap();
        let day = "2026-09-24";
        write_source_dreams(home.path(), day, &[dream(day, "first", "first summary")]);

        let first = sync_day_checked(home.path(), vault.path(), "NEOTH", day).unwrap();
        let target = vault
            .path()
            .join("NEOTH")
            .join(OBSIDIAN_DREAMS_DIR)
            .join(format!("{day}.md"));
        assert!(first.written);
        assert_eq!(first.target_path, target);
        assert_ne!(first.durability, DreamSyncDurability::NotWritten);
        assert!(
            std::fs::read_to_string(&target)
                .unwrap()
                .contains("first summary")
        );

        write_source_dreams(home.path(), day, &[dream(day, "second", "second summary")]);
        let second = sync_day_checked(home.path(), vault.path(), "NEOTH", day).unwrap();
        let rendered = std::fs::read_to_string(&target).unwrap();
        assert!(second.written);
        assert!(rendered.contains("second summary"));
        assert!(!rendered.contains("first summary"));
    }

    #[test]
    fn missing_source_day_is_quiet_without_creating_vault() {
        let home = tempdir().unwrap();
        let workspace = tempdir().unwrap();
        let vault = workspace.path().join("missing-vault");

        let outcome = sync_day_checked(home.path(), &vault, "NEOTH", "2026-09-24").unwrap();

        assert!(!outcome.written);
        assert!(!vault.exists());
        assert_eq!(
            outcome.target_path,
            vault.join("NEOTH/Dreams/2026-09-24.md")
        );
        assert_eq!(outcome.durability, DreamSyncDurability::NotWritten);
    }

    #[test]
    fn durability_tags_serialize_in_snake_case() {
        assert_eq!(
            serde_json::to_string(&DreamSyncDurability::NotWritten).unwrap(),
            "\"not_written\""
        );
        assert_eq!(
            serde_json::to_string(&DreamSyncDurability::PublishedAndSynced).unwrap(),
            "\"published_and_synced\""
        );
        assert_eq!(
            serde_json::to_string(&DreamSyncDurability::PublishedDurabilityUnknown).unwrap(),
            "\"published_durability_unknown\""
        );
    }

    #[test]
    fn malformed_utf8_and_budget_failures_are_closed() {
        let day = "2026-09-24";
        for bytes in [b"{bad json}\n".as_slice(), b"\xff\n".as_slice()] {
            let home = tempdir().unwrap();
            let vault = tempdir().unwrap();
            write_source_bytes(home.path(), day, bytes);
            assert!(sync_day_checked(home.path(), vault.path(), "NEOTH", day).is_err());
        }

        let home = tempdir().unwrap();
        let vault = tempdir().unwrap();
        write_source_bytes(home.path(), day, &[b'x'; MAX_LINE_BYTES + 1]);
        assert!(sync_day_checked(home.path(), vault.path(), "NEOTH", day).is_err());

        let home = tempdir().unwrap();
        let vault = tempdir().unwrap();
        let line = serde_json::to_string(&dream(day, "theme", "summary")).unwrap();
        let too_many = vec![line; MAX_DREAMS + 1].join("\n");
        write_source_bytes(home.path(), day, too_many.as_bytes());
        assert!(sync_day_checked(home.path(), vault.path(), "NEOTH", day).is_err());

        let home = tempdir().unwrap();
        let vault = tempdir().unwrap();
        write_source_bytes(home.path(), day, &vec![b'x'; MAX_SOURCE_BYTES + 1]);
        assert!(sync_day_checked(home.path(), vault.path(), "NEOTH", day).is_err());
    }

    #[test]
    fn source_dream_day_must_match_requested_day_and_rendering_is_bounded() {
        let home = tempdir().unwrap();
        let vault = tempdir().unwrap();
        write_source_dreams(
            home.path(),
            "2026-09-24",
            &[dream("2026-09-23", "theme", "summary")],
        );
        assert!(sync_day_checked(home.path(), vault.path(), "NEOTH", "2026-09-24").is_err());

        let oversized = dream("2026-09-24", "theme", &"x".repeat(MAX_RENDERED_BYTES));
        assert!(render_checked_dreams(&[oversized]).is_err());
    }

    #[test]
    fn invalid_day_and_subdir_are_rejected_before_side_effects() {
        let workspace = tempdir().unwrap();
        let home = workspace.path().join("home");
        let vault = workspace.path().join("vault");

        assert!(sync_day_checked(&home, &vault, "../NEOTH", "2026-09-24").is_err());
        assert!(sync_day_checked(&home, &vault, "NEOTH/", "2026-09-24").is_err());
        assert!(sync_day_checked(&home, &vault, "C:NEOTH", "2026-09-24").is_err());
        assert!(sync_day_checked(&home, &vault, r"\\host\share", "2026-09-24").is_err());
        assert!(sync_day_checked(&home, &vault, "NEOTH\0escape", "2026-09-24").is_err());
        assert!(sync_day_checked(&home, &vault, "NEOTH", "2026-2-24").is_err());
        assert!(sync_day_checked(&home, &vault, "NEOTH", "+2026-09-24").is_err());
        assert!(sync_day_checked(&home, &vault, "NEOTH", "-001-09-24").is_err());
        assert!(!home.exists());
        assert!(!vault.exists());
    }

    #[cfg(unix)]
    #[test]
    fn source_and_target_symlinks_are_refused_without_touching_outside_file() {
        let day = "2026-09-24";
        let home = tempdir().unwrap();
        let vault = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let source_sentinel = outside.path().join("source.jsonl");
        write_source_dreams(outside.path(), day, &[dream(day, "theme", "summary")]);
        std::fs::rename(source_file(outside.path(), day), &source_sentinel).unwrap();
        std::os::unix::fs::symlink(&source_sentinel, home.path().join(DREAMS_DIR)).unwrap();
        assert!(sync_day_checked(home.path(), vault.path(), "NEOTH", day).is_err());

        let home = tempdir().unwrap();
        write_source_dreams(home.path(), day, &[dream(day, "theme", "summary")]);
        let target_dir = vault.path().join("NEOTH").join(OBSIDIAN_DREAMS_DIR);
        std::fs::create_dir_all(&target_dir).unwrap();
        let outside_sentinel = outside.path().join("keep.md");
        std::fs::write(&outside_sentinel, "keep").unwrap();
        std::os::unix::fs::symlink(&outside_sentinel, target_dir.join(format!("{day}.md")))
            .unwrap();
        assert!(sync_day_checked(home.path(), vault.path(), "NEOTH", day).is_err());
        assert_eq!(std::fs::read_to_string(outside_sentinel).unwrap(), "keep");
    }

    #[cfg(unix)]
    #[test]
    fn hardlinked_target_is_refused_and_preserved() {
        let day = "2026-09-24";
        let home = tempdir().unwrap();
        let vault = tempdir().unwrap();
        let outside = tempdir().unwrap();
        write_source_dreams(home.path(), day, &[dream(day, "theme", "summary")]);
        let target_dir = vault.path().join("NEOTH").join(OBSIDIAN_DREAMS_DIR);
        std::fs::create_dir_all(&target_dir).unwrap();
        let outside_sentinel = outside.path().join("keep.md");
        std::fs::write(&outside_sentinel, "keep").unwrap();
        std::fs::hard_link(&outside_sentinel, target_dir.join(format!("{day}.md"))).unwrap();

        assert!(sync_day_checked(home.path(), vault.path(), "NEOTH", day).is_err());
        assert_eq!(std::fs::read_to_string(outside_sentinel).unwrap(), "keep");
    }

    #[test]
    fn post_commit_validation_failure_is_reported_as_published_durability_unknown() {
        let home = tempdir().unwrap();
        let vault = tempdir().unwrap();
        let day = "2026-09-24";
        write_source_dreams(home.path(), day, &[dream(day, "theme", "summary")]);
        let target = vault
            .path()
            .join("NEOTH")
            .join(OBSIDIAN_DREAMS_DIR)
            .join(format!("{day}.md"));
        crate::skills::store::fail_private_child_post_commit_validation_for_test(&target);

        let outcome = sync_day_checked(home.path(), vault.path(), "NEOTH", day).unwrap();

        assert!(outcome.written);
        assert_eq!(
            outcome.durability,
            DreamSyncDurability::PublishedDurabilityUnknown
        );
        assert!(std::fs::read_to_string(target).unwrap().contains("summary"));
    }
}
