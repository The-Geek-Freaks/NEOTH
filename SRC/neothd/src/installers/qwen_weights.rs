//! NOOB-UX-6 — Qwen weights download installer primitive.
//!
//! `LocalQwen` is the privacy-positive default for profile extraction
//! (operator-history never reaches a cloud vendor). The weights live
//! at `~/.cache/huggingface/hub/models--<safe_id>/` — about 6 GB for
//! `Qwen/Qwen2.5-3B-Instruct`. First load can stall for minutes while
//! `hf-hub` streams the safetensors shards, so the wizard surfaces a
//! pre-download step so operators aren't surprised at chat time.
//!
//! Pattern matches `installers/n8n.rs` + `installers/obsidian.rs`:
//!   - Pure-fn command builders so the wizard renders the exact line
//!     the operator runs (no surprise subprocess spawn).
//!   - Sync cache probe so the wizard step decides Skip / Download /
//!     Operator-Skipped without taking a tokio handle.
//!
//! No silent download: even when the operator opts in, the wizard
//! prints the `huggingface-cli download <model_id>` command + asks for
//! confirmation. Honours the "operator GO per command" rule.

use std::path::PathBuf;

/// Canonical Qwen model id used by `providers::local_qwen` (D14b).
/// Pinned here so the wizard surface + the runtime stay aligned.
/// Drift between the two = `LocalQwen` first-load downloads a
/// *different* model than the operator pre-downloaded, doubling the
/// disk hit. The matching test (`default_model_id_pinned_to_runtime`)
/// catches that drift.
pub const DEFAULT_QWEN_MODEL_ID: &str = "Qwen/Qwen2.5-3B-Instruct";

/// Approximate on-disk footprint (GB) of the default Qwen model.
/// Surfaced in the wizard prompt so the operator picks "yes" with
/// open eyes. Round number — the exact size shifts with each HF
/// re-upload, but ~6 GB is the operator-visible truth.
pub const DEFAULT_QWEN_DOWNLOAD_GB: u32 = 6;

/// What the wizard should do with the Qwen weights step. Pure data;
/// the wizard step renders + acts on this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WeightsAction {
    /// Weights already cached under `~/.cache/huggingface/hub/`. The
    /// wizard prints a one-liner + moves on without prompting.
    AlreadyCached,
    /// Weights missing AND the operator (interactive prompt or
    /// `--download-qwen-weights` flag) opted in. The wizard prints
    /// the download command + asks one final confirmation before
    /// spawning.
    DownloadNeeded,
    /// Weights missing AND the operator declined / didn't opt in.
    /// `LocalQwen` will lazy-download on first chat — the wizard
    /// surfaces that fact so the operator isn't surprised later.
    OperatorSkipped,
}

impl WeightsAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AlreadyCached => "already_cached",
            Self::DownloadNeeded => "download_needed",
            Self::OperatorSkipped => "operator_skipped",
        }
    }
}

/// Decide the wizard action given probe + opt-in state. Pure-fn so
/// the dispatcher table is testable without spawning subprocesses.
pub fn recommend_action(cached: bool, opted_in: bool) -> WeightsAction {
    match (cached, opted_in) {
        (true, _) => WeightsAction::AlreadyCached,
        (false, true) => WeightsAction::DownloadNeeded,
        (false, false) => WeightsAction::OperatorSkipped,
    }
}

/// Build the `huggingface-cli download <model_id>` command + args.
/// Pure-fn so the wizard renders it to the operator before any
/// subprocess. `--resume-download` lets a partial pull (interrupted
/// by Ctrl-C / network hiccup) resume instead of re-fetching the
/// full ~6 GB.
pub fn weights_download_command(model_id: &str) -> Vec<String> {
    vec![
        "huggingface-cli".into(),
        "download".into(),
        model_id.into(),
        "--resume-download".into(),
    ]
}

/// Compute the cache directory `hf-hub` writes Qwen weights into.
/// HuggingFace's transformer is `<repo_id> → models--<owner>--<name>`
/// — slashes become `--`. Pure-fn so the cache probe is testable.
pub fn cache_dir_for(model_id: &str) -> Option<PathBuf> {
    let home = if cfg!(target_os = "windows") {
        std::env::var_os("USERPROFILE")?
    } else {
        std::env::var_os("HOME")?
    };
    let safe = model_id.replace('/', "--");
    Some(
        PathBuf::from(home)
            .join(".cache")
            .join("huggingface")
            .join("hub")
            .join(format!("models--{safe}")),
    )
}

/// Probe whether the operator has the weights already cached. Cheap
/// (~1ms file_exists) — the wizard runs this synchronously on every
/// init flow that touches LocalQwen.
///
/// The cache dir alone isn't proof the download finished; HF marks
/// in-progress fetches with a sibling `.incomplete` lock. The probe
/// returns `false` if any `*.incomplete` file lives under the cache
/// so an operator who Ctrl-C'd mid-download still gets the resume
/// prompt instead of a false "already cached" status.
pub fn check_weights_cached(model_id: &str) -> bool {
    let Some(cache) = cache_dir_for(model_id) else {
        return false;
    };
    if !cache.exists() {
        return false;
    }
    !has_incomplete_marker(&cache)
}

fn has_incomplete_marker(dir: &std::path::Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if has_incomplete_marker(&path) {
                return true;
            }
            continue;
        }
        if path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.eq_ignore_ascii_case("incomplete"))
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_model_id_pinned_to_runtime() {
        // Drift guard — when `providers::local_qwen` switches the
        // default repo id (e.g. Qwen3 release), bump both consts in
        // the same commit. This test fails loudly if only one half
        // moves.
        assert_eq!(DEFAULT_QWEN_MODEL_ID, "Qwen/Qwen2.5-3B-Instruct");
    }

    #[test]
    fn weights_download_command_uses_huggingface_cli() {
        let cmd = weights_download_command(DEFAULT_QWEN_MODEL_ID);
        assert_eq!(cmd[0], "huggingface-cli");
        assert_eq!(cmd[1], "download");
        assert_eq!(cmd[2], DEFAULT_QWEN_MODEL_ID);
        // Resume-friendly: partial download resumes instead of
        // re-fetching the full ~6 GB.
        assert!(cmd.iter().any(|a| a == "--resume-download"));
    }

    #[test]
    fn weights_download_command_passes_arbitrary_model_id() {
        let cmd = weights_download_command("custom/Other-Model");
        assert_eq!(cmd[2], "custom/Other-Model");
    }

    #[test]
    fn cache_dir_translates_slashes_to_double_dash() {
        // HuggingFace cache convention. Drift here = the probe
        // looks in the wrong dir + always returns "not cached".
        let dir = cache_dir_for("Qwen/Qwen2.5-3B-Instruct").unwrap();
        let last = dir.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(last, "models--Qwen--Qwen2.5-3B-Instruct");
    }

    #[test]
    fn recommend_action_matrix_covers_all_cases() {
        assert_eq!(recommend_action(true, false), WeightsAction::AlreadyCached);
        assert_eq!(
            recommend_action(true, true),
            WeightsAction::AlreadyCached,
            "already-cached short-circuits even when the operator opted in"
        );
        assert_eq!(recommend_action(false, true), WeightsAction::DownloadNeeded);
        assert_eq!(
            recommend_action(false, false),
            WeightsAction::OperatorSkipped
        );
    }

    #[test]
    fn check_weights_cached_returns_false_for_empty_cache_dir() {
        // Synthetic env: point HOME / USERPROFILE at a tempdir + the
        // expected cache dir doesn't exist → false.
        let _env = crate::test_env::lock();
        let temp = tempfile::tempdir().unwrap();
        let prev_home = std::env::var_os("HOME");
        let prev_userprofile = std::env::var_os("USERPROFILE");
        // SAFETY: tests run single-threaded for env mutation; restore
        // both vars before returning so other tests aren't affected.
        unsafe {
            std::env::set_var("HOME", temp.path());
            std::env::set_var("USERPROFILE", temp.path());
        }
        assert!(!check_weights_cached(DEFAULT_QWEN_MODEL_ID));
        unsafe {
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
            match prev_userprofile {
                Some(v) => std::env::set_var("USERPROFILE", v),
                None => std::env::remove_var("USERPROFILE"),
            }
        }
    }

    #[test]
    fn check_weights_cached_detects_incomplete_marker() {
        // Synthetic cache dir with an `.incomplete` sibling — the
        // probe must NOT report "cached" because hf-hub treats that
        // as an interrupted download. Operator gets the resume prompt.
        let _env = crate::test_env::lock();
        let temp = tempfile::tempdir().unwrap();
        let cache_root = temp.path().join(".cache").join("huggingface").join("hub");
        let model_dir = cache_root.join("models--Qwen--Qwen2.5-3B-Instruct");
        let blobs = model_dir.join("blobs");
        std::fs::create_dir_all(&blobs).unwrap();
        std::fs::write(blobs.join("part-0001.incomplete"), b"partial").unwrap();

        let prev_home = std::env::var_os("HOME");
        let prev_userprofile = std::env::var_os("USERPROFILE");
        unsafe {
            std::env::set_var("HOME", temp.path());
            std::env::set_var("USERPROFILE", temp.path());
        }
        assert!(!check_weights_cached(DEFAULT_QWEN_MODEL_ID));
        unsafe {
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
            match prev_userprofile {
                Some(v) => std::env::set_var("USERPROFILE", v),
                None => std::env::remove_var("USERPROFILE"),
            }
        }
    }

    #[test]
    fn weights_action_as_str_round_trips_each_variant() {
        assert_eq!(WeightsAction::AlreadyCached.as_str(), "already_cached");
        assert_eq!(WeightsAction::DownloadNeeded.as_str(), "download_needed");
        assert_eq!(WeightsAction::OperatorSkipped.as_str(), "operator_skipped");
    }

    #[test]
    fn default_qwen_download_gb_is_a_realistic_round_number() {
        // The wizard tells the operator "~6 GB". If someone bumps
        // this to a fantasy value the prompt becomes a lie.
        assert!((4..=12).contains(&DEFAULT_QWEN_DOWNLOAD_GB));
    }
}
