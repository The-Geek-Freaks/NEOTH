//! NOOB-UX-6 — Qwen weights download installer primitive.
//!
//! `LocalQwen` is the privacy-positive default for profile extraction
//! (operator-history never reaches a cloud vendor). Runtime-ready weights live
//! at `~/.neoth/models/<repo-flat>/` — about 6 GB for
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

use std::path::{Path, PathBuf};

/// Canonical Qwen model id used by `providers::local_qwen` (D14b).
/// Pinned here so the wizard surface + the runtime stay aligned.
/// Drift between the two = `LocalQwen` first-load downloads a
/// *different* model than the operator pre-downloaded, doubling the
/// disk hit. The matching test (`default_model_id_pinned_to_runtime`)
/// catches that drift.
pub const DEFAULT_QWEN_MODEL_ID: &str = crate::providers::local_qwen::DEFAULT_HF_REPO;

/// Approximate on-disk footprint (GB) of the default Qwen model.
/// Surfaced in the wizard prompt so the operator picks "yes" with
/// open eyes. Round number — the exact size shifts with each HF
/// re-upload, but ~6 GB is the operator-visible truth.
pub const DEFAULT_QWEN_DOWNLOAD_GB: u32 = 6;

/// What the wizard should do with the Qwen weights step. Pure data;
/// the wizard step renders + acts on this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WeightsAction {
    /// Runtime-loadable weights already exist under `~/.neoth/models/`. The
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
    let cache_dir = cache_dir_for(model_id);
    vec![
        "huggingface-cli".into(),
        "download".into(),
        model_id.into(),
        "--resume-download".into(),
        "--local-dir".into(),
        cache_dir.to_string_lossy().into_owned(),
    ]
}

/// Compute the exact NEOTH-owned cache directory opened by LocalQwen.
pub fn cache_dir_for(model_id: &str) -> PathBuf {
    cache_dir_for_at(
        &crate::config::FreedomConfig::default_neoth_home(),
        model_id,
    )
}

pub(crate) fn cache_dir_for_at(neoth_home: &Path, model_id: &str) -> PathBuf {
    crate::providers::local_qwen::cache_dir_at(neoth_home, model_id)
}

/// Probe whether the operator has runtime-loadable weights cached. The wizard
/// runs this synchronously only on init flows that touch LocalQwen; it parses
/// tokenizer/config metadata and the safetensors header, never model tensors.
///
/// The cache dir alone isn't proof the download finished; HF marks
/// in-progress fetches with a sibling `.incomplete` lock. The probe
/// returns `false` if any `*.incomplete` file lives under the cache
/// so an operator who Ctrl-C'd mid-download still gets the resume
/// prompt instead of a false "already cached" status.
pub fn check_weights_cached(model_id: &str) -> bool {
    check_weights_cached_at(
        &crate::config::FreedomConfig::default_neoth_home(),
        model_id,
    )
}

pub(crate) fn check_weights_cached_at(neoth_home: &Path, model_id: &str) -> bool {
    let cache = cache_dir_for_at(neoth_home, model_id);
    !has_incomplete_marker(&cache)
        && crate::providers::local_qwen::validate_runtime_artifacts_at(&cache, false).is_ok()
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
        assert_eq!(
            DEFAULT_QWEN_MODEL_ID,
            crate::providers::local_qwen::DEFAULT_HF_REPO
        );
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
        let local_dir = cmd.iter().position(|arg| arg == "--local-dir").unwrap();
        assert_eq!(
            PathBuf::from(&cmd[local_dir + 1]),
            crate::providers::local_qwen::default_cache_dir(DEFAULT_QWEN_MODEL_ID)
        );
    }

    #[test]
    fn weights_download_command_passes_arbitrary_model_id() {
        let cmd = weights_download_command("custom/Other-Model");
        assert_eq!(cmd[2], "custom/Other-Model");
    }

    #[test]
    fn wizard_doctor_and_runtime_share_canonical_cache_path() {
        let home = Path::new("/operator/.neoth");
        let installer = cache_dir_for_at(home, DEFAULT_QWEN_MODEL_ID);
        let runtime = crate::providers::local_qwen::cache_dir_at(home, DEFAULT_QWEN_MODEL_ID);
        assert_eq!(installer, runtime);
        assert_eq!(
            installer,
            home.join("models").join("Qwen-Qwen2.5-3B-Instruct")
        );
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
        let temp = tempfile::tempdir().unwrap();
        assert!(!check_weights_cached_at(temp.path(), DEFAULT_QWEN_MODEL_ID));
    }

    #[test]
    fn check_weights_cached_detects_incomplete_marker() {
        // Synthetic cache dir with an `.incomplete` sibling — the
        // probe must NOT report "cached" because hf-hub treats that
        // as an interrupted download. Operator gets the resume prompt.
        let temp = tempfile::tempdir().unwrap();
        let model_dir = cache_dir_for_at(temp.path(), DEFAULT_QWEN_MODEL_ID);
        let blobs = model_dir.join("blobs");
        std::fs::create_dir_all(&blobs).unwrap();
        std::fs::write(blobs.join("part-0001.incomplete"), b"partial").unwrap();
        assert!(!check_weights_cached_at(temp.path(), DEFAULT_QWEN_MODEL_ID));
    }

    fn write_runtime_loadable_fixture(cache: &Path) {
        std::fs::create_dir_all(cache).unwrap();
        tokenizers::Tokenizer::new(tokenizers::models::bpe::BPE::default())
            .save(
                cache.join(crate::providers::local_qwen::TOKENIZER_FILE),
                false,
            )
            .unwrap();
        std::fs::write(
            cache.join(crate::providers::local_qwen::CONFIG_FILE),
            r#"{
                "vocab_size": 1,
                "hidden_size": 2,
                "intermediate_size": 4,
                "num_hidden_layers": 1,
                "num_attention_heads": 1,
                "num_key_value_heads": 1,
                "max_position_embeddings": 16,
                "sliding_window": 16,
                "max_window_layers": 1,
                "tie_word_embeddings": false,
                "rope_theta": 10000.0,
                "rms_norm_eps": 0.000001,
                "use_sliding_window": false,
                "hidden_act": "silu"
            }"#,
        )
        .unwrap();
        let header = br#"{"tensor":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#;
        let mut weights = Vec::new();
        weights.extend_from_slice(&(header.len() as u64).to_le_bytes());
        weights.extend_from_slice(header);
        weights.extend_from_slice(&[0_u8; 4]);
        std::fs::write(
            cache.join(crate::providers::local_qwen::SAFETENSORS_FILE),
            weights,
        )
        .unwrap();
    }

    #[test]
    fn ready_requires_exact_runtime_loadable_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let cache = cache_dir_for_at(temp.path(), DEFAULT_QWEN_MODEL_ID);
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(cache.join("unrelated.bin"), b"not a model").unwrap();
        assert!(!check_weights_cached_at(temp.path(), DEFAULT_QWEN_MODEL_ID));

        write_runtime_loadable_fixture(&cache);
        assert!(crate::providers::local_qwen::validate_runtime_artifacts_at(&cache, false).is_ok());
        assert!(check_weights_cached_at(temp.path(), DEFAULT_QWEN_MODEL_ID));
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
