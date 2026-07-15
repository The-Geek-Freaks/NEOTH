//! `neoth init` -- interactive onboarding wizard.
//!
//! Normative reference: PLAN/SPEC_onboarding.md
//!
//! All 7 wizard steps are implemented. Interactive prompts (dialoguer) require
//! the `wizard` Cargo feature (enabled by default). Non-interactive operation
//! works without `wizard` and is driven entirely by CLI flags + env vars.

use anyhow::Result;
use tracing::{debug, info};

mod catalog;
mod io;
mod steps_autonomy;
mod steps_channel;
mod steps_env;
mod steps_identity;
mod steps_omi;
mod steps_provider;
mod steps_topology;
mod types;
mod validation;

pub use catalog::*;
pub(crate) use io::*;
pub(crate) use steps_autonomy::*;
pub(crate) use steps_channel::*;
pub(crate) use steps_env::*;
pub(crate) use steps_identity::*;
pub(crate) use steps_omi::*;
pub(crate) use steps_provider::*;
pub(crate) use steps_topology::*;
pub use types::*;
pub use validation::*;

/// Main entry point for `neoth init`.
pub async fn run_init(args: InitArgs) -> Result<()> {
    let interactive = is_interactive(&args);
    debug!(interactive, force = args.force, "neoth init starting");

    let neoth_dir = crate::config::FreedomConfig::default_neoth_home();
    let marker = neoth_dir.join(".initialized");

    // Step 0 — operator picks GUI or CLI mode before anything else, including
    // legacy `.initialized` reconfiguration and checkpoint-resume prompts.
    // Existing installations without interface.json therefore receive the
    // one-time choice instead of permanently bypassing it.
    // Per the HARD RULE `neoth_gui_first_screen_and_settings_parity`:
    // NEOTH targets non-developer operators ("noobs") who land on a
    // mode-selection screen, not a tracing-style logspew. If the
    // operator picks GUI here we launch the packaged sibling directly. The
    // launcher's successful spawn is the commit point for the durable GUI
    // preference; dry-run only reports the handoff and writes nothing.
    if step0_mode_selection(&args, interactive, &neoth_dir)?.exit_for_gui() {
        if args.dry_run {
            println!("[dry-run] Would launch the NEOTH GUI; no preference written.");
            return Ok(());
        }
        crate::cli::gui::run_gui(
            crate::cli::gui::GuiArgs::default(),
            crate::cli::OutputFormat::Table,
        )?;
        return Ok(());
    }

    if marker.exists() && !args.force {
        info!("Already initialized. Showing reconfigure menu.");
        return run_reconfigure_menu(&args);
    }

    let mut state = fresh_wizard_state();
    // `init --force` is a reconfiguration, not an OMI reset. Preserve the
    // complete existing OMI block (including advanced bounds not surfaced by
    // the wizard) and the credential backend before applying explicit answers.
    hydrate_existing_init_state(&neoth_dir, &mut state)?;

    // R-04 (Session 24) — restore in-flight wizard state from
    // ~/.neoth/wizard_checkpoint.json when the operator confirms
    // resume. Secrets are never persisted (the checkpoint module
    // strips them); operator re-enters provider_key + telegram_token
    // on resume. Decline → clear the file + start fresh.
    maybe_resume_from_checkpoint(&neoth_dir, interactive, &mut state)?;

    // Non-interactive (pipe / CI / --non-interactive flag) requires explicit
    // license accept. This gate intentionally runs AFTER the surface handoff:
    // `neoth init --gui` owns its licence screen and must not fail merely
    // because the launching terminal has no stdin TTY.
    if !interactive && !args.accept_license {
        anyhow::bail!(
            "--accept-license is required when running non-interactively \
             (no TTY detected or --non-interactive set)"
        );
    }
    step1_license(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step1b_detect_environment(&args, interactive, &neoth_dir).await;
    step1c_experience_level(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    // GOLD-HON-10 — new-vs-migration question, before the identity step.
    step1d_onboarding_mode(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step2_operator_id(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    // ZF-02 — preset picker moved to position 2 (right after first identity
    // question). When the operator picks any built-in preset (full-auto /
    // balanced / essentials / local-sovereign), `is_express` is set to `true`
    // and the detail steps (role, topology, channels, autonomy, etc.) are
    // skipped — the preset covers them. `custom` keeps the full flow.
    //
    // Semantics change from ZF-01: `is_express` is now "non-custom preset was
    // chosen" (a superset of the old `args.zero_friction` flag, which maps to
    // `full-auto`). Checkpoint compat: `is_express` has `#[serde(default)]`
    // so old checkpoints without it resume correctly (false = full flow).
    let chosen_preset = step_zero_friction(&args, interactive, &mut state)?;
    state.chosen_preset = chosen_preset.clone();
    state.is_express = chosen_preset.as_deref().is_some_and(|n| n != "custom");
    save_checkpoint_best_effort(&neoth_dir, &state);

    step3_language(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step3b_hmac_backup(interactive, &neoth_dir, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    if !state.is_express {
        step4_role(&args, interactive, &mut state)?;
        save_checkpoint_best_effort(&neoth_dir, &state);
    }
    let existing_security_policy = {
        let path = neoth_dir.join("freedom.yaml");
        crate::config::FreedomConfig::load_from_path_or_default(&path)?.security
    };
    step5_provider(&args, interactive, &mut state, &existing_security_policy).await?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    if !state.is_express {
        step5b_inference_topology(&args, interactive, &mut state)?;
        save_checkpoint_best_effort(&neoth_dir, &state);
        step5b2_ollama_provision(interactive, &mut state).await?;
        save_checkpoint_best_effort(&neoth_dir, &state);
        step5c_qwen_weights(&args, interactive, &mut state).await?;
        save_checkpoint_best_effort(&neoth_dir, &state);
        step5d_profile_approval_gate(interactive, &mut state)?;
        save_checkpoint_best_effort(&neoth_dir, &state);
        // GOLD-ADAPT-CBM-02 — optional code-intelligence rail (terminal offer,
        // no resume marker needed; re-derived each run).
        step5e_cbm_offer(interactive).await?;
        // GOLD-ADAPT-CCS-01 — exact-pinned semantic code-graph rail.
        step5f_hex_graph_offer(interactive, args.dry_run).await?;
        step6_channel(&args, interactive, &mut state).await?;
        save_checkpoint_best_effort(&neoth_dir, &state);
        step6_omi(&args, interactive, &neoth_dir, &mut state)?;
        save_checkpoint_best_effort(&neoth_dir, &state);
        step6b_keet_pairing(&args, interactive, &mut state).await?;
        save_checkpoint_best_effort(&neoth_dir, &state);
        step6c_obsidian_install(&args, interactive, &mut state).await?;
        save_checkpoint_best_effort(&neoth_dir, &state);
        step6d_obsidian_vault_bootstrap(&args, interactive, &mut state)?;
        save_checkpoint_best_effort(&neoth_dir, &state);
        step6e_n8n_install(&args, interactive, &mut state).await?;
        save_checkpoint_best_effort(&neoth_dir, &state);
        step6f_import_memory(&args, interactive, &mut state)?;
        save_checkpoint_best_effort(&neoth_dir, &state);
        step6g_credential_import(&args, interactive, &neoth_dir).await;
        // GOLD-ADAPT-TUDU-01
        step6i_tududi_offer(interactive).await?;
        // GOLD-ADAPT-SYS-01
        step6j_mobile_mcp_offer(interactive).await?;
        // GOLD-ADAPT-ODY-24
        step6k_companion_pairing_offer(interactive, &mut state).await?;
        step6h_install_recommended(&args, interactive, &neoth_dir);
        step7_autonomy(&args, interactive, &mut state)?;
        save_checkpoint_best_effort(&neoth_dir, &state);
        step7b_auto_update(&args, interactive, &mut state)?;
        save_checkpoint_best_effort(&neoth_dir, &state);
        step7c_wasm_plugin_activation(&args, interactive, &neoth_dir, &mut state)?;
        save_checkpoint_best_effort(&neoth_dir, &state);
        step7d_supervisor(&args, interactive, &mut state)?;
        save_checkpoint_best_effort(&neoth_dir, &state);
    } else {
        // Express presets intentionally skip privacy prompts, but explicit OMI
        // flags still have to work in CI and an existing enabled OMI block must
        // still pass the same fail-closed credential validation.
        step6_omi(&args, false, &neoth_dir, &mut state)?;
        save_checkpoint_best_effort(&neoth_dir, &state);
        if interactive {
            // ZF-02 — post-setup tips for channels and optional rails.
            println!(
                "\n  Later you can enable additional features:\n\
                 \n    Channels:   neoth channel add telegram / discord / matrix …\
                 \n    OMI:        neoth omi status          (private conversation/media ingest)\
                 \n    Code graph: neoth init --force         (optional pinned hex-graph MCP)\
                 \n    Obsidian:   neoth obsidian connect   (knowledge vault)\
                 \n    n8n:        neoth n8n connect        (workflow automation)\
                 \n    Mobile:     neoth mobile-mcp setup   (iOS/Android control)\
                 \n    tududi:     neoth tududi setup        (task manager)\
                 \n    GUI tab:    start neothd-gui → Channels / Integrations tab\
                 \n"
            );
        }
    }
    step8_summary(&args, &mut state)?;

    if args.dry_run {
        println!("[dry-run] No files written.");
    } else {
        write_config(&neoth_dir, &state).await?;
        // ZF-01 — merge the chosen built-in's feature-flag overrides into the
        // freshly written freedom.yaml. Autonomy is stripped: the wizard's
        // explicit selection already wrote it into the config (the selection
        // IS the ceremony on a fresh install — no daemon, no WAL yet).
        if let Some(name) = &chosen_preset {
            if let Some(mut preset) = crate::config::preset_builtins::builtin_by_name(name) {
                preset.autonomy = None;
                match crate::config::presets::apply_preset_to_freedom_yaml(&neoth_dir, &preset) {
                    Ok(report) => {
                        println!(
                            "  ⚡ preset `{name}` applied ({} feature toggles set).",
                            report.fields_changed.len()
                        );
                        if !report.warn_changes.is_empty() {
                            println!("     cost/privacy-relevant toggles included:");
                            for (path, _, new) in &report.warn_changes {
                                println!("       • {path} → {new}");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, preset = %name, "preset overlay failed");
                        println!(
                            "  ⚠ preset `{name}` overlay failed ({e}) — base config written; \
                             run `neoth preset apply {name}` to retry."
                        );
                    }
                }
            }
        }
        write_initialized_marker(&neoth_dir, &state)?;
        // R-04: wizard reached the `.initialized` marker — the
        // checkpoint is no longer needed. Clear it so the next
        // `neoth init` (e.g. via --force or reconfigure) starts
        // from scratch instead of offering resume.
        if let Err(e) = crate::cli::wizard_checkpoint::clear_checkpoint(&neoth_dir) {
            tracing::warn!(error = %e, "post-init checkpoint clear failed (cosmetic)");
        }
        println!("Configuration written to ~/.neoth/");
        // R-05 (Session 24) — offer to auto-start the daemon + greet
        // with the first-tour message. Runs on TTY only; CI / pipe
        // skip so the wizard remains scriptable.
        if interactive {
            if let Err(e) = step9_offer_start_daemon(&neoth_dir) {
                tracing::warn!(error = %e, "auto-start daemon offer failed (cosmetic)");
            }
        }
        // Phase 28c R-24 GT-4: optional Q&A ground-truth seed. Runs only on
        // a TTY; non-interactive flow points operator at `neoth groundtruth
        // ask` instead. Skippable in interactive mode too.
        if interactive {
            maybe_run_groundtruth_qa(&state)?;
        } else {
            println!(
                "Run `neoth groundtruth ask` to seed ground-truth facts \
                 (or skip and add later via `neoth groundtruth add ...`)."
            );
        }
    }
    Ok(())
}

// ── Atomic, mode-0600 file write helpers ──────────────────────────────────────
//
// SECURITY P0 (from Security Engineer review, OPEN_DECISIONS.md D-003):
// freedom.yaml and .initialized MUST be created with mode 0600 on `OpenOptions`
// BEFORE `open()` — never chmod-after-create (TOCTOU race). Pattern below uses
// `create_new(true)` + `.mode(0o600)` for unix; Windows inherits parent DACL
// (see wal/writer.rs::open_segment for the parallel Windows TODO).

// ── Validation helpers ────────────────────────────────────────────────────────

// ── OS utilities ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── SC-09 step 3b: HMAC key backup prompt ─────────────────────────

    #[test]
    fn step3b_non_interactive_is_a_noop() {
        // Non-interactive runs must NOT prompt, NOT back up, and NOT create a
        // key — the operator can run `neoth security backup-hmac-key` later.
        let dir = tempfile::tempdir().unwrap();
        let mut state = WizardState::default();
        step3b_hmac_backup(false, dir.path(), &mut state).expect("noop ok");
        assert!(!state.hmac_backup_offered, "non-interactive must not offer");
        assert!(
            !dir.path().join("wal").join("hmac_backup.bin").exists(),
            "non-interactive must write no backup"
        );
        assert!(
            !dir.path().join("wal").join("hmac.key").exists(),
            "non-interactive must not create a key"
        );
    }

    #[test]
    fn hmac_backup_offered_defaults_false_and_round_trips() {
        let s = WizardState::default();
        assert!(!s.hmac_backup_offered);
        // Round-trips, and a checkpoint written BEFORE this field existed (the
        // key absent from an otherwise-complete JSON) still loads — proving the
        // `#[serde(default)]` on the new field keeps old checkpoints valid.
        let mut v: serde_json::Value = serde_json::to_value(&s).unwrap();
        v.as_object_mut().unwrap().remove("hmac_backup_offered");
        let legacy: WizardState = serde_json::from_value(v).unwrap();
        assert!(!legacy.hmac_backup_offered);
    }

    // ── R-04 (Session 24) wizard resume gate ──────────────────────────

    #[test]
    fn maybe_resume_no_checkpoint_leaves_state_default() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = WizardState::default();
        maybe_resume_from_checkpoint(dir.path(), false, &mut state).expect("noop ok");
        assert!(state.operator_id.is_none());
        assert!(state.steps_completed.is_empty());
    }

    #[test]
    fn maybe_resume_non_interactive_auto_hydrates_from_checkpoint() {
        // CI / pipe path: auto-resume without prompting. The checkpoint
        // payload is the source of truth for non-secret fields.
        let dir = tempfile::tempdir().unwrap();
        let mut saved = WizardState::default();
        saved.operator_id = Some("sam".into());
        saved.language_code = Some("de".into());
        saved.steps_completed = vec![1, 2, 3, 4];
        saved.bootstrap_vault = true;
        crate::cli::wizard_checkpoint::save_checkpoint(dir.path(), &saved).expect("save");

        let mut state = WizardState::default();
        maybe_resume_from_checkpoint(dir.path(), false, &mut state).expect("auto-resume");
        assert_eq!(state.operator_id.as_deref(), Some("sam"));
        assert_eq!(state.language_code.as_deref(), Some("de"));
        assert_eq!(state.steps_completed, vec![1, 2, 3, 4]);
        assert!(state.bootstrap_vault);
        // Checkpoint file must still exist after auto-resume — it gets
        // cleared at the very end of run_init or by an operator decline.
        assert!(
            crate::cli::wizard_checkpoint::checkpoint_path(dir.path()).exists(),
            "non-interactive auto-resume keeps the file in place for the next save",
        );
    }

    #[test]
    fn maybe_resume_with_corrupt_file_clears_it_and_proceeds() {
        // Garbage JSON in the checkpoint must NOT brick the wizard.
        // Operator sees a fresh wizard + the bad file goes away.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(
            crate::cli::wizard_checkpoint::checkpoint_path(dir.path()),
            b"<<<not real json>>>",
        )
        .unwrap();

        let mut state = WizardState::default();
        maybe_resume_from_checkpoint(dir.path(), false, &mut state).expect("survives corruption");
        assert!(state.operator_id.is_none());
        assert!(
            !crate::cli::wizard_checkpoint::checkpoint_path(dir.path()).exists(),
            "corrupt checkpoint must be cleared",
        );
    }

    #[test]
    fn format_checkpoint_age_handles_zero_and_negative() {
        // Defensive: an operator who hand-edits the file to ts=0 or
        // pre-epoch shouldn't crash the resume prompt.
        assert_eq!(format_checkpoint_age(0), "timestamp unavailable");
        assert_eq!(format_checkpoint_age(-1), "timestamp unavailable");
    }

    // ── R-05 (Session 24) auto-start + first-tour marker ─────────────

    #[test]
    fn write_first_tour_marker_creates_file_with_canonical_body() {
        let dir = tempfile::tempdir().unwrap();
        super::write_first_tour_marker(dir.path()).expect("write marker");
        let path = dir.path().join(super::FIRST_TOUR_MARKER);
        assert!(path.exists(), "marker file must exist after write");
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body, super::FIRST_TOUR_MESSAGE);
    }

    #[test]
    fn consume_first_tour_marker_returns_some_then_none() {
        let dir = tempfile::tempdir().unwrap();
        super::write_first_tour_marker(dir.path()).expect("write");
        let first = super::consume_first_tour_marker(dir.path());
        assert!(first.is_some());
        assert_eq!(first.as_deref(), Some(super::FIRST_TOUR_MESSAGE));

        // Second call: marker consumed → None.
        let second = super::consume_first_tour_marker(dir.path());
        assert!(
            second.is_none(),
            "marker is single-use; second consume must return None",
        );
        assert!(
            !dir.path().join(super::FIRST_TOUR_MARKER).exists(),
            "consume must delete the file",
        );
    }

    #[test]
    fn consume_first_tour_marker_returns_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let out = super::consume_first_tour_marker(dir.path());
        assert!(
            out.is_none(),
            "fresh-install state (no wizard ran yet) → None, not Err",
        );
    }

    #[test]
    fn write_first_tour_marker_is_idempotent_on_rewrite() {
        // Operator re-runs `neoth init --force` → second write must
        // succeed + leave the file at the canonical message. Catches
        // a future regression that switches to "fail if exists" mode.
        let dir = tempfile::tempdir().unwrap();
        super::write_first_tour_marker(dir.path()).expect("first");
        // Tamper with the file as if a partial write happened.
        std::fs::write(dir.path().join(super::FIRST_TOUR_MARKER), b"stale-content").unwrap();
        super::write_first_tour_marker(dir.path()).expect("second");
        let body = std::fs::read_to_string(dir.path().join(super::FIRST_TOUR_MARKER)).unwrap();
        assert_eq!(body, super::FIRST_TOUR_MESSAGE);
    }

    #[test]
    fn first_tour_message_is_actionable_one_liner() {
        // Drift guard: the greeting must mention a runnable command so
        // a first-time operator has a clear next step. If a future
        // refactor reduces it to "Hello." this fails.
        assert!(
            super::FIRST_TOUR_MESSAGE.contains("neoth chat")
                || super::FIRST_TOUR_MESSAGE.contains("neoth recall"),
            "greeting must reference a runnable command: {}",
            super::FIRST_TOUR_MESSAGE,
        );
    }

    #[test]
    fn format_checkpoint_age_picks_human_units() {
        // The exact phrasing isn't a contract, but the unit boundary
        // selection is — a 2-hour-old checkpoint should not say
        // "7200 seconds ago" to an operator.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(format_checkpoint_age(now - 30).contains("minute"));
        assert!(format_checkpoint_age(now - 600).contains("minutes ago"));
        assert!(format_checkpoint_age(now - 7_200).contains("hours ago"));
        assert!(format_checkpoint_age(now - 172_800).contains("days ago"));
    }

    /// Process-level lock for tests that mutate the global `HOME` /
    /// `USERPROFILE` env vars. `std::env::set_var` is process-global,
    /// so two parallel tests in this lib that both set HOME race —
    /// one sees the other's tempdir and asserts wrong, surfacing as
    /// the intermittent failure of e.g. step6d_non_interactive_*.
    /// Every test that calls `set_var("HOME"/"USERPROFILE", ...)`
    /// MUST take this lock at function entry; release on drop
    /// happens after the restore-prev block.
    /// Delegates to the CRATE-WIDE env lock (crate::test_env) so init's
    /// HOME/USERPROFILE tests serialise against EVERY env test in the
    /// crate, not just each other. (Was a file-local HOME_ENV_LOCK,
    /// which only serialised within init.rs → a split-mechanism race
    /// vs pidfile/mode/code_map; the SC-11-era sweep unified it.)
    fn lock_home_env() -> std::sync::MutexGuard<'static, ()> {
        crate::test_env::lock()
    }

    #[test]
    fn operator_id_valid() {
        assert!(validate_operator_id("sam").is_ok());
        assert!(validate_operator_id("my-dev_1").is_ok());
    }

    #[test]
    fn operator_id_reserved() {
        assert!(validate_operator_id("root").is_err());
        assert!(validate_operator_id("neoth").is_err());
    }

    #[test]
    fn operator_id_length() {
        assert!(validate_operator_id("a").is_err());
        assert!(validate_operator_id(&"a".repeat(33)).is_err());
    }

    #[test]
    fn operator_id_charset() {
        assert!(validate_operator_id("has space").is_err());
        assert!(validate_operator_id("has@sym").is_err());
    }

    /// NOOB-UX-4 drift guard — every interactive wizard prompt
    /// (`dialoguer::Confirm/Select/Input`) MUST have an operator-
    /// readable `(recommended)` / `recommended` marker explaining
    /// the default choice. The full editorial pass needs real
    /// fresh-OS install testing, but this test pins the coverage
    /// ratio so a future refactor that drops a marker surfaces.
    /// Failure mode: a wizard prompt without a `(recommended)`
    /// tag forces a non-developer operator to guess.
    #[test]
    fn noob_ux_4_wizard_prompts_keep_recommended_markers() {
        let src = include_str!("init.rs");
        let prompt_count = src.matches("dialoguer::Confirm").count()
            + src.matches("dialoguer::Select").count()
            + src.matches("dialoguer::Input").count();
        let recommended_count = src.matches("recommended").count();
        assert!(
            prompt_count >= 1,
            "wizard prompt count went to zero — surface check"
        );
        assert!(
            recommended_count >= prompt_count,
            "NOOB-UX-4 drift: {} wizard prompts, {} 'recommended' markers — \
             every interactive prompt needs at least one recommended-default \
             hint for non-developer operators",
            prompt_count,
            recommended_count
        );
    }

    #[test]
    fn recommended_provider_matches_spec_table() {
        use crate::config::inference::InferenceProvider as I;
        // SPEC_hemisphere_provider_selection.md §2 table — pinned so a
        // future refactor of the recommendation logic doesn't silently
        // drift away from the documented operator-facing defaults.
        assert_eq!(recommended_provider_for_role("left"), I::ClaudeCli);
        assert_eq!(recommended_provider_for_role("right"), I::Gemini);
        assert_eq!(recommended_provider_for_role("cerebellum"), I::LocalQwen);
    }

    #[test]
    fn recommended_local_provider_puts_ouro_on_analytic_left() {
        // GOLD-ADOPT-12: the local mirror — Ouro (reasoning LoopLM) takes the
        // analytic LEFT slot just as ClaudeCli does in the cloud default;
        // right + cerebellum stay on local Qwen.
        use crate::config::inference::InferenceProvider as I;
        assert_eq!(recommended_local_provider_for_role("left"), I::LocalOuro);
        assert_eq!(recommended_local_provider_for_role("right"), I::LocalQwen);
        assert_eq!(
            recommended_local_provider_for_role("cerebellum"),
            I::LocalQwen
        );
        assert_eq!(
            recommended_local_provider_for_role("hippocampus"),
            I::LocalQwen
        );
    }

    // ── Finding 6 (Session 13) wizard local-only preset ─────────────

    #[test]
    fn apply_local_only_preset_binds_every_slot_to_local_qwen() {
        use crate::config::inference::{InferenceProvider, InferenceTopology, TopologyMode};
        let mut topo = InferenceTopology::default();
        apply_local_only_preset(&mut topo);
        assert_eq!(topo.mode, TopologyMode::Triplet);
        assert_eq!(
            topo.default_slot.provider,
            Some(InferenceProvider::LocalQwen)
        );
        assert_eq!(topo.left.provider, Some(InferenceProvider::LocalQwen));
        assert_eq!(topo.right.provider, Some(InferenceProvider::LocalQwen));
        assert_eq!(topo.cerebellum.provider, Some(InferenceProvider::LocalQwen));
    }

    #[test]
    fn apply_local_only_preset_clears_keys_and_endpoints() {
        // Pre-fill the topology with cloud secrets, then assert the preset
        // wipes them — local-only must not retain stale cloud credentials
        // that confuse later wizard reconfigure passes.
        use crate::config::inference::{HemisphereSlot, InferenceProvider, InferenceTopology};
        let dirty = HemisphereSlot {
            provider: Some(InferenceProvider::OpenAi),
            model: Some("gpt-4o".into()),
            key: Some(crate::secret::SecretString::from("sk-test")),
            endpoint: Some("https://api.openai.com/v1".into()),
            region: None,
            api_version: None,
            voice: None,
        };
        let mut topo = InferenceTopology {
            left: dirty.clone(),
            right: dirty.clone(),
            cerebellum: dirty.clone(),
            default_slot: dirty,
            ..InferenceTopology::default()
        };
        apply_local_only_preset(&mut topo);
        for slot in [
            &topo.left,
            &topo.right,
            &topo.cerebellum,
            &topo.default_slot,
        ] {
            assert_eq!(slot.provider, Some(InferenceProvider::LocalQwen));
            assert!(slot.model.is_none(), "model should be cleared");
            assert!(slot.key.is_none(), "key should be cleared");
            assert!(slot.endpoint.is_none(), "endpoint should be cleared");
        }
    }

    #[test]
    fn apply_local_abliterated_preset_all_local_is_triplet_ollama() {
        use crate::config::inference::{InferenceProvider, InferenceTopology, TopologyMode};
        use crate::installers::ollama::DEFAULT_OLLAMA_PORT;
        use crate::models::gguf_variants::VariantClass;
        use crate::models::hemisphere_preset::build_local_preset;
        // 24 GiB → 3 local abliterated hemispheres.
        let preset = build_local_preset(
            Some(24 * 1024),
            3,
            VariantClass::Abliterated,
            DEFAULT_OLLAMA_PORT,
        );
        let mut topo = InferenceTopology::default();
        apply_local_abliterated_preset(&mut topo, &preset);
        assert_eq!(topo.mode, TopologyMode::Triplet);
        for slot in [
            &topo.left,
            &topo.right,
            &topo.cerebellum,
            &topo.default_slot,
        ] {
            assert_eq!(slot.provider, Some(InferenceProvider::OpenAiCompat));
            assert_eq!(slot.endpoint.as_deref(), Some("http://127.0.0.1:11434/v1"));
            assert!(slot.key.is_none(), "Ollama needs no API key");
            let m = slot.model.as_deref().unwrap_or("");
            assert!(m.starts_with("hf.co/mradermacher/"), "got {m}");
            assert!(m.contains("abliterated-GGUF"));
        }
    }

    #[test]
    fn apply_local_abliterated_preset_mixed_is_custom_keeps_cloud() {
        use crate::config::inference::{
            HemisphereSlot, InferenceProvider, InferenceTopology, TopologyMode,
        };
        use crate::installers::ollama::DEFAULT_OLLAMA_PORT;
        use crate::models::gguf_variants::VariantClass;
        use crate::models::hemisphere_preset::build_local_preset;
        // Pre-seed cloud slots; a 1-local preset must leave right+cerebellum cloud.
        let cloud = HemisphereSlot {
            provider: Some(InferenceProvider::Gemini),
            model: Some("gemini-3.1-pro-preview".into()),
            key: Some(crate::secret::SecretString::from("k")),
            endpoint: None,
            region: None,
            api_version: None,
            voice: None,
        };
        let mut topo = InferenceTopology {
            left: cloud.clone(),
            right: cloud.clone(),
            cerebellum: cloud.clone(),
            default_slot: cloud,
            ..InferenceTopology::default()
        };
        let preset = build_local_preset(
            Some(24 * 1024),
            1,
            VariantClass::Abliterated,
            DEFAULT_OLLAMA_PORT,
        );
        apply_local_abliterated_preset(&mut topo, &preset);
        assert_eq!(topo.mode, TopologyMode::Custom);
        // Left went local…
        assert_eq!(topo.left.provider, Some(InferenceProvider::OpenAiCompat));
        // …right + cerebellum + default stayed cloud (Gemini).
        assert_eq!(topo.right.provider, Some(InferenceProvider::Gemini));
        assert_eq!(topo.cerebellum.provider, Some(InferenceProvider::Gemini));
        assert_eq!(topo.default_slot.provider, Some(InferenceProvider::Gemini));
    }

    #[test]
    fn collect_ollama_model_refs_dedups_local_hemispheres() {
        use crate::config::inference::{InferenceProvider, InferenceTopology, TopologyMode};
        use crate::installers::ollama::DEFAULT_OLLAMA_PORT;
        use crate::models::gguf_variants::VariantClass;
        use crate::models::hemisphere_preset::build_local_preset;
        // 3 local hemispheres at the same VRAM-share → identical model on all 3.
        let preset = build_local_preset(
            Some(24 * 1024),
            3,
            VariantClass::Abliterated,
            DEFAULT_OLLAMA_PORT,
        );
        let mut topo = InferenceTopology::default();
        apply_local_abliterated_preset(&mut topo, &preset);
        let refs = collect_ollama_model_refs(&topo);
        // Same model across all 3 slots → pulled once.
        assert_eq!(refs.len(), 1, "expected dedup, got {refs:?}");
        assert!(refs[0].starts_with("hf.co/mradermacher/"));

        // A non-Ollama (cloud) topology yields nothing to provision.
        let cloud = InferenceTopology {
            mode: TopologyMode::Single,
            ..InferenceTopology::default()
        };
        assert!(collect_ollama_model_refs(&cloud).is_empty());
        // A slot that's OpenAiCompat but NOT the Ollama endpoint is ignored.
        let mut other = InferenceTopology::default();
        other.left.provider = Some(InferenceProvider::OpenAiCompat);
        other.left.endpoint = Some("https://openrouter.ai/api/v1".into());
        other.left.model = Some("hf.co/x/y:Q4_K_M".into());
        assert!(collect_ollama_model_refs(&other).is_empty());
    }

    #[test]
    fn topology_default_idx_picks_local_only_when_gpu_detected() {
        use crate::daemon::accelerator::{Accelerator, Probe};
        for picked in [Accelerator::Cuda, Accelerator::Metal, Accelerator::OpenVino] {
            let probe = Probe {
                picked,
                cuda: matches!(picked, Accelerator::Cuda),
                metal: matches!(picked, Accelerator::Metal),
                openvino: matches!(picked, Accelerator::OpenVino),
            };
            assert_eq!(
                topology_default_idx_for_probe(&probe),
                3,
                "GPU-detected probe must default to local-only (idx 3), got otherwise for {picked:?}",
            );
        }
    }

    #[test]
    fn topology_default_idx_picks_single_when_cpu_only() {
        use crate::daemon::accelerator::{Accelerator, Probe};
        let probe = Probe {
            picked: Accelerator::Cpu,
            cuda: false,
            metal: false,
            openvino: false,
        };
        assert_eq!(topology_default_idx_for_probe(&probe), 0);
    }

    #[test]
    fn recommended_provider_unknown_role_falls_back_safely() {
        use crate::config::inference::InferenceProvider as I;
        // Defensive default — never crash if a renamed role is passed.
        assert_eq!(recommended_provider_for_role("hippocampus"), I::ClaudeCli);
        assert_eq!(recommended_provider_for_role(""), I::ClaudeCli);
    }

    #[test]
    fn default_model_for_known_pairs() {
        use crate::config::inference::InferenceProvider as I;
        assert_eq!(
            default_model_for("left", I::ClaudeCli),
            Some("claude-opus-4-7")
        );
        assert_eq!(
            default_model_for("right", I::Gemini),
            Some("gemini-3.1-pro-preview")
        );
        assert_eq!(
            default_model_for("cerebellum", I::LocalQwen),
            Some("Qwen/Qwen2.5-3B-Instruct"),
        );
    }

    #[test]
    fn default_model_for_unknown_role_provider_pair_returns_none() {
        use crate::config::inference::InferenceProvider as I;
        // Pick #11 Phase A (Session 14): the Hermes/OpenClaw stub
        // test was removed alongside the variants. This replacement
        // pins the broader "unknown role+provider pair → fall back
        // to free-text input" contract that the wizard depends on.
        assert_eq!(default_model_for("hippocampus", I::ClaudeCli), None);
        assert_eq!(default_model_for("left", I::LocalQwen), None);
        assert_eq!(default_model_for("cerebellum", I::Gemini), None);
    }

    // ── K-Models-Wizard-Integration (Session 14 Pick #4) ─────────────────

    #[test]
    fn catalog_key_for_provider_kind_maps_all_real_providers() {
        assert_eq!(ProviderKind::ClaudeCli.catalog_key(), Some("anthropic_api"));
        assert_eq!(ProviderKind::OpenaiApi.catalog_key(), Some("openai_api"));
        assert_eq!(ProviderKind::GeminiApi.catalog_key(), Some("gemini_api"));
        assert_eq!(ProviderKind::AwsBedrock.catalog_key(), Some("aws_bedrock"));
        assert_eq!(
            ProviderKind::OpenaiCompat.catalog_key(),
            Some("openai_compat")
        );
    }

    #[test]
    fn catalog_key_for_provider_kind_returns_none_for_kinds_without_catalog_source() {
        // No remote list-models endpoint for these — wizard falls back
        // to bundled defaults.
        assert_eq!(ProviderKind::LocalQwen.catalog_key(), None);
        assert_eq!(ProviderKind::AzureOpenAi.catalog_key(), None);
        assert_eq!(ProviderKind::Skip.catalog_key(), None);
    }

    #[test]
    fn provider_kind_as_str_matches_serde_wire_form_for_all_variants() {
        // COR-13: as_str() must equal the serde-serialised slug for every
        // variant (incl. the AzureOpenAi rename), so the manual stringifier
        // and the persisted config form can never drift.
        use clap::ValueEnum;
        for kind in ProviderKind::value_variants() {
            let serde_form = serde_json::to_string(kind)
                .unwrap()
                .trim_matches('"')
                .to_string();
            assert_eq!(
                kind.as_str(),
                serde_form,
                "as_str() must match serde for {kind:?}"
            );
        }
        // Pin the two surface differences as_provider_id() carries.
        assert_eq!(ProviderKind::Cohere.as_str(), "cohere");
        assert_eq!(ProviderKind::AzureOpenAi.as_str(), "azure_openai");
        assert_eq!(ProviderKind::Skip.as_str(), "skip");
    }

    #[test]
    fn provider_kind_as_provider_id_canonicalises_status_form() {
        // Cohere + Skip diverge from as_str(); everything else matches.
        assert_eq!(ProviderKind::Cohere.as_provider_id(), "cohere_api");
        assert_eq!(ProviderKind::Skip.as_provider_id(), "none");
        assert_eq!(ProviderKind::AzureOpenAi.as_provider_id(), "azure_openai");
        assert_eq!(ProviderKind::OpenaiApi.as_provider_id(), "openai_api");
        assert_eq!(ProviderKind::ClaudeCli.as_provider_id(), "claude_cli");
        // The drift token: Skip resolves to "none", and kind_from_slug
        // treats it as non-cloud (same as the old unconfigured/unknown).
        assert!(crate::consent::kind_from_slug(ProviderKind::Skip.as_provider_id()).is_none());
    }

    #[tokio::test]
    async fn step5_non_interactive_wires_aws_bedrock_runtime_fields() {
        let mut state = fixture_state();
        let args = InitArgs {
            provider: Some(ProviderKind::AwsBedrock),
            provider_region: Some("eu-central-1".to_string()),
            provider_model: Some("anthropic.claude-sonnet-4-6-v1:0".to_string()),
            ..Default::default()
        };
        step5_provider(
            &args,
            false,
            &mut state,
            &crate::config::SecurityPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(state.provider_kind, Some(ProviderKind::AwsBedrock));
        assert_eq!(state.provider_region.as_deref(), Some("eu-central-1"));
        assert_eq!(
            state.provider_model.as_deref(),
            Some("anthropic.claude-sonnet-4-6-v1:0")
        );
    }

    #[tokio::test]
    async fn step5_non_interactive_wires_complete_azure_openai_contract() {
        let mut state = fixture_state();
        let args = InitArgs {
            provider: Some(ProviderKind::AzureOpenAi),
            provider_endpoint: Some("https://prod.openai.azure.com".to_string()),
            provider_model: Some("gpt-prod".to_string()),
            provider_api_version: Some("2025-04-01-preview".to_string()),
            provider_key: Some("azure-secret".to_string()),
            ..Default::default()
        };
        step5_provider(
            &args,
            false,
            &mut state,
            &crate::config::SecurityPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(state.provider_kind, Some(ProviderKind::AzureOpenAi));
        assert_eq!(
            state.provider_endpoint.as_deref(),
            Some("https://prod.openai.azure.com")
        );
        assert_eq!(state.provider_model.as_deref(), Some("gpt-prod"));
        assert_eq!(
            state.provider_api_version.as_deref(),
            Some("2025-04-01-preview")
        );
        assert_eq!(
            state.provider_key.as_ref().map(|key| key.expose()),
            Some("azure-secret")
        );
    }

    #[test]
    fn provider_kind_display_forwards_to_as_str() {
        assert_eq!(format!("{}", ProviderKind::LocalOuro), "local_ouro");
        assert_eq!(format!("{}", ProviderKind::AzureOpenAi), "azure_openai");
    }

    #[test]
    fn provider_kind_to_inference_maps_every_variant() {
        use crate::config::inference::InferenceProvider as I;
        assert_eq!(ProviderKind::ClaudeCli.to_inference(), I::ClaudeCli);
        assert_eq!(ProviderKind::OpenaiApi.to_inference(), I::OpenAi);
        assert_eq!(ProviderKind::AnthropicApi.to_inference(), I::AnthropicApi);
        assert_eq!(ProviderKind::OpenaiCompat.to_inference(), I::OpenAiCompat);
        assert_eq!(ProviderKind::GeminiApi.to_inference(), I::Gemini);
        assert_eq!(ProviderKind::Cohere.to_inference(), I::Cohere);
        assert_eq!(ProviderKind::LocalQwen.to_inference(), I::LocalQwen);
        assert_eq!(ProviderKind::LocalOuro.to_inference(), I::LocalOuro);
        assert_eq!(ProviderKind::AwsBedrock.to_inference(), I::AwsBedrock);
        assert_eq!(ProviderKind::AzureOpenAi.to_inference(), I::AzureOpenAi);
        assert_eq!(ProviderKind::Skip.to_inference(), I::ClaudeCli);
    }

    #[test]
    fn azure_openai_serde_uses_canonical_slug_with_legacy_alias() {
        // COR-13: AzureOpenAi must serialise to the canonical "azure_openai"
        // (not serde's default "azure_open_ai") so freedom.yaml round-trips
        // against consent/cost/InferenceProvider, and the learn_provider
        // error message that promises "azure_openai" actually parses.
        let json = serde_json::to_string(&ProviderKind::AzureOpenAi).unwrap();
        assert_eq!(json, "\"azure_openai\"");
        // Canonical form round-trips.
        let back: ProviderKind = serde_json::from_str("\"azure_openai\"").unwrap();
        assert_eq!(back, ProviderKind::AzureOpenAi);
        // Legacy form still loads via the alias (back-compat for any
        // existing on-disk config).
        let legacy: ProviderKind = serde_json::from_str("\"azure_open_ai\"").unwrap();
        assert_eq!(legacy, ProviderKind::AzureOpenAi);
    }

    #[test]
    fn catalog_recommended_returns_none_when_catalog_missing() {
        // Pointing at a non-existent catalog path → load returns empty
        // catalog → no provider entry → None. Confirms the wizard
        // bundled-fallback path fires on a fresh install.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("never_existed.json");
        let result = catalog_recommended_for_provider_kind_at(&path, ProviderKind::ClaudeCli);
        assert_eq!(result, None);
    }

    #[test]
    fn catalog_recommended_returns_id_when_catalog_has_provider_entry() {
        use crate::models::catalog::{ModelEntry, ModelsCatalog, SourceOrigin};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog.json");
        let mut catalog = ModelsCatalog::default().with_path(path.clone());
        catalog.upsert(
            "anthropic_api",
            SourceOrigin::Api,
            vec![
                ModelEntry::new("claude-opus-4-7"),
                ModelEntry::new("claude-sonnet-4-6"),
            ],
        );
        catalog.save().unwrap();

        // ClaudeCli → anthropic_api → recommended = first non-deprecated = opus-4-7
        let result = catalog_recommended_for_provider_kind_at(&path, ProviderKind::ClaudeCli);
        assert_eq!(result, Some("claude-opus-4-7".to_string()));
    }

    #[test]
    fn catalog_recommended_skips_deprecated_first_entry() {
        use crate::models::catalog::{ModelEntry, ModelsCatalog, SourceOrigin};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog.json");
        let mut catalog = ModelsCatalog::default().with_path(path.clone());
        catalog.upsert(
            "openai_api",
            SourceOrigin::Api,
            vec![
                ModelEntry::new("gpt-4o").marked_deprecated(),
                ModelEntry::new("gpt-5.4"),
                ModelEntry::new("gpt-5.5"),
            ],
        );
        catalog.save().unwrap();

        let result = catalog_recommended_for_provider_kind_at(&path, ProviderKind::OpenaiApi);
        assert_eq!(result, Some("gpt-5.4".to_string()));
    }

    #[test]
    fn catalog_recommended_returns_none_for_kinds_without_source() {
        // Even when catalog file exists, LocalQwen has no source entry
        // because catalog_key_for_provider_kind returns None.
        use crate::models::catalog::{ModelEntry, ModelsCatalog, SourceOrigin};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog.json");
        let mut catalog = ModelsCatalog::default().with_path(path.clone());
        catalog.upsert(
            "anthropic_api",
            SourceOrigin::Api,
            vec![ModelEntry::new("claude-opus-4-7")],
        );
        catalog.save().unwrap();

        let result = catalog_recommended_for_provider_kind_at(&path, ProviderKind::LocalQwen);
        assert_eq!(result, None);
    }

    #[test]
    fn default_model_for_unknown_pair_returns_none() {
        use crate::config::inference::InferenceProvider as I;
        // Pairs the SPEC doesn't pin (e.g. ClaudeCli for cerebellum)
        // return None so the wizard inherits the operator's step-5 model.
        assert_eq!(default_model_for("cerebellum", I::ClaudeCli), None);
        assert_eq!(default_model_for("right", I::OpenAi), None);
    }

    #[test]
    fn bcp47_valid() {
        assert!(validate_bcp47("en").is_ok());
        assert!(validate_bcp47("zh-CN").is_ok());
        assert!(validate_bcp47("pt-BR").is_ok());
    }

    #[test]
    fn bcp47_invalid() {
        assert!(validate_bcp47("").is_err());
        assert!(validate_bcp47("x").is_err());
    }

    #[test]
    fn role_valid() {
        assert!(validate_role("developer").is_ok());
        assert!(validate_role("security-researcher").is_ok());
        assert!(validate_role("custom-role").is_ok());
    }

    #[test]
    fn role_invalid() {
        assert!(validate_role("has space").is_err());
        assert!(validate_role(&"a".repeat(33)).is_err());
    }

    #[test]
    fn telegram_token_valid() {
        let token = format!("12345678:{}", "A".repeat(35));
        assert!(validate_telegram_token(&token).is_ok());
    }

    #[test]
    fn telegram_token_invalid() {
        assert!(validate_telegram_token("notvalid").is_err());
        assert!(validate_telegram_token("123:short").is_err());
    }

    // ── write_config + write_initialized_marker (O-1 acceptance) ───────────────

    fn fixture_state() -> WizardState {
        WizardState {
            experience_level: crate::wizard::recommend::ExperienceLevel::Beginner,
            onboarding_mode: OnboardingMode::New,
            chosen_preset: None,
            is_express: false,
            operator_id: Some("alice".to_string()),
            language_primary: Some("en".to_string()),
            language_code: Some("en".to_string()),
            role: Some(OperatorRole::Developer),
            role_custom: None,
            provider_kind: Some(ProviderKind::ClaudeCli),
            provider_binary: Some("/usr/local/bin/claude".to_string()),
            provider_key: None,
            provider_endpoint: None,
            provider_model: Some("claude-opus-4-7".to_string()),
            provider_region: None,
            provider_api_version: None,
            telegram_token: Some(crate::secret::SecretString::from(
                "12345678:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            )),
            telegram_user_id: Some(987654321),
            secrets_backend: crate::config::SecretsBackend::File,
            omi: crate::config::OmiConfig::default(),
            audit_rpc: crate::config::AuditRpcConfig {
                enabled: true,
                required_for_oneshot_permission_events: false,
            },
            omi_developer_api_key: None,
            omi_ingest_token: None,
            autonomy: crate::permissions::AutonomyLevel::Standard,
            custom_autonomy: crate::permissions::CustomAutonomyConfig::default(),
            inference: crate::config::inference::InferenceTopology::default(),
            auto_update: crate::config::AutoUpdateConfig::default(),
            supervisor: crate::config::SupervisorConfig::default(),
            plugins: crate::config::PluginsConfig::default(),
            keet_seed_phrase: None,
            keet_bridge_bearer_token: None,
            download_qwen_weights: false,
            install_obsidian: false,
            bootstrap_vault: false,
            vault_path: None,
            install_n8n: false,
            import_memory: None,
            hmac_backup_offered: false,
            // GOLD-ADAPT-OH-03: fixture has telegram configured → flag is true.
            onboarding_complete: true,
            // GOLD-ADAPT-OH-11: fixture represents a post-wizard state where
            // chat has not yet happened → write_config will reset this to false.
            chat_onboarding_completed: false,
            // GOLD-ADAPT-ODY-24: companion is off by default in fixture state.
            companion: crate::config::CompanionConfig::default(),
            steps_completed: vec![1, 2, 3, 4, 5, 6, 7, 8],
        }
    }

    #[test]
    fn fresh_and_express_wizard_enable_audit_rpc_without_forcing_compliance_mode() {
        let fresh = fresh_wizard_state();
        assert!(fresh.audit_rpc.enabled);
        assert!(!fresh.audit_rpc.required_for_oneshot_permission_events);

        let mut express = fresh_wizard_state();
        express.is_express = true;
        assert!(
            express.audit_rpc.enabled,
            "express presets skip detail prompts but must retain the fresh-wizard audit listener"
        );
    }

    #[tokio::test]
    async fn write_config_creates_freedom_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        let state = fixture_state();

        write_config(&neoth_dir, &state)
            .await
            .expect("write_config");

        let yaml = neoth_dir.join("freedom.yaml");
        assert!(
            yaml.exists(),
            "freedom.yaml should exist after write_config"
        );

        let body = std::fs::read_to_string(&yaml).unwrap();
        assert!(body.contains("operator_id: alice"));
        assert!(body.contains("provider_kind: claude_cli"));
        assert!(body.contains("role: developer"));
        // Phase 33+ split: secrets are NOT in freedom.yaml. They live in
        // the sibling credentials.yaml — verify the negative + check the
        // sibling file contains the token.
        assert!(
            !body.contains("12345678:AAAAAAAAA"),
            "telegram_token must NOT be embedded in freedom.yaml after the split",
        );
        let creds_body =
            std::fs::read_to_string(neoth_dir.join("credentials.yaml")).expect("credentials.yaml");
        assert!(
            creds_body.contains("12345678:AAAAAAAAA"),
            "telegram_token must be in credentials.yaml",
        );
        // V03-09 Phase 2a — freedom.yaml MUST carry the auto_update
        // block so operators see the field exists + can edit it
        // without a docs roundtrip.
        assert!(
            body.contains("auto_update:"),
            "freedom.yaml must serialize auto_update block: {body}"
        );
        assert!(
            body.contains("enabled: false"),
            "auto_update default must serialize enabled: false"
        );
    }

    #[tokio::test]
    async fn write_config_losslessly_merges_unknown_top_level_and_nested_fields() {
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        std::fs::create_dir_all(&neoth_dir).unwrap();
        std::fs::write(
            neoth_dir.join("freedom.yaml"),
            r#"operator_id: old
future_top_level:
  keep_me: 41
omi:
  enabled: false
  future_omi_limit: 9001
inference:
  future_router_policy: preserve
  default_slot:
    future_slot_field: preserve-too
audit_rpc:
  enabled: false
  future_transport_field: preserve-audit-extension
security:
  trusted_roots:
    - /operator/custom
"#,
        )
        .unwrap();

        let mut state = fixture_state();
        state.operator_id = Some("new".to_string());
        state.omi.retention_days = 7;
        write_config(&neoth_dir, &state).await.expect("merge write");

        let raw = std::fs::read_to_string(neoth_dir.join("freedom.yaml")).unwrap();
        let merged: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap();
        assert_eq!(merged["operator_id"].as_str(), Some("new"));
        assert_eq!(merged["future_top_level"]["keep_me"].as_i64(), Some(41));
        assert_eq!(merged["omi"]["future_omi_limit"].as_i64(), Some(9001));
        assert_eq!(merged["omi"]["retention_days"].as_i64(), Some(7));
        assert_eq!(
            merged["inference"]["future_router_policy"].as_str(),
            Some("preserve")
        );
        assert_eq!(
            merged["inference"]["default_slot"]["future_slot_field"].as_str(),
            Some("preserve-too")
        );
        assert_eq!(merged["audit_rpc"]["enabled"].as_bool(), Some(true));
        assert_eq!(
            merged["audit_rpc"]["future_transport_field"].as_str(),
            Some("preserve-audit-extension")
        );
        assert_eq!(
            merged["security"]["trusted_roots"][0].as_str(),
            Some("/operator/custom")
        );
    }

    #[test]
    fn force_hydration_preserves_advanced_owned_values_without_importing_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        std::fs::create_dir_all(&neoth_dir).unwrap();
        std::fs::write(
            neoth_dir.join("freedom.yaml"),
            r#"operator_id: existing-operator
inference:
  mode: custom
  left:
    region: eu-central-1
omi:
  enabled: false
  max_connections: 17
  allowed_uids:
    - trusted-device
audit_rpc:
  enabled: false
  required_for_oneshot_permission_events: false
"#,
        )
        .unwrap();
        let mut credentials = crate::config::credentials::Credentials::default();
        credentials.inference_left_key = Some(crate::secret::SecretString::from(
            "SECRET-MUST-STAY-IN-CREDENTIAL-STORE",
        ));
        credentials
            .write(&neoth_dir.join("credentials.yaml"))
            .unwrap();

        let mut state = WizardState::default();
        hydrate_existing_init_state(&neoth_dir, &mut state).unwrap();
        assert_eq!(state.operator_id.as_deref(), Some("existing-operator"));
        assert_eq!(state.omi.max_connections, 17);
        assert_eq!(state.omi.allowed_uids, vec!["trusted-device"]);
        assert_eq!(state.inference.left.region.as_deref(), Some("eu-central-1"));
        assert!(!state.audit_rpc.enabled);
        assert!(!state.audit_rpc.required_for_oneshot_permission_events);
        assert!(
            state.inference.left.key.is_none(),
            "effective keychain/file secrets must never be hydrated into public wizard state"
        );
    }

    #[test]
    fn force_hydration_treats_corrupt_config_as_recoverable() {
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        std::fs::create_dir_all(&neoth_dir).unwrap();
        std::fs::write(neoth_dir.join("freedom.yaml"), b"not: [valid yaml").unwrap();

        let mut state = fresh_wizard_state();
        hydrate_existing_init_state(&neoth_dir, &mut state)
            .expect("--force recovery must not be bricked by corrupt public config");
        assert!(
            state.audit_rpc.enabled,
            "failed hydration must leave safe fresh-wizard defaults intact"
        );
    }

    #[tokio::test]
    async fn write_config_persists_omi_credentials_first_and_preserves_unrelated_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        std::fs::create_dir_all(&neoth_dir).unwrap();
        let cred_path = neoth_dir.join("credentials.yaml");
        let mut existing = crate::config::credentials::Credentials::default();
        existing.whatsapp_phone_id = Some("operator-phone-id".to_string());
        existing.write(&cred_path).unwrap();

        let mut state = fixture_state();
        state.omi.enabled = true;
        state.omi.mode = crate::config::OmiIngestMode::Both;
        state.omi.audio_enabled = true;
        state.omi.visual_enabled = true;
        state.omi.video_enabled = true;
        state.omi_developer_api_key = Some(crate::secret::SecretString::from(
            "omi_dev_init_persist_test",
        ));
        state.omi_ingest_token = Some(crate::secret::SecretString::from(
            "0123456789abcdef0123456789abcdef",
        ));

        write_config(&neoth_dir, &state).await.expect("OMI write");
        let freedom = std::fs::read_to_string(neoth_dir.join("freedom.yaml")).unwrap();
        assert!(!freedom.contains("omi_dev_init_persist_test"));
        assert!(!freedom.contains("0123456789abcdef0123456789abcdef"));

        let credentials =
            crate::config::credentials::Credentials::load_or_default(&cred_path).unwrap();
        assert_eq!(
            credentials.whatsapp_phone_id.as_deref(),
            Some("operator-phone-id")
        );
        assert_eq!(
            credentials.omi_developer_api_key.as_ref().unwrap().expose(),
            "omi_dev_init_persist_test"
        );
        assert_eq!(
            credentials.omi_ingest_token.as_ref().unwrap().expose(),
            "0123456789abcdef0123456789abcdef"
        );
    }

    #[tokio::test]
    async fn malformed_existing_yaml_fails_before_any_credential_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        std::fs::create_dir_all(&neoth_dir).unwrap();
        let freedom_path = neoth_dir.join("freedom.yaml");
        std::fs::write(&freedom_path, b"operator_id: [unterminated\n").unwrap();
        let cred_path = neoth_dir.join("credentials.yaml");
        let mut existing = crate::config::credentials::Credentials::default();
        existing.whatsapp_phone_id = Some("must-survive".to_string());
        existing.write(&cred_path).unwrap();
        let before = std::fs::read(&cred_path).unwrap();

        let result = write_config(&neoth_dir, &fixture_state()).await;
        assert!(result.is_err());
        assert_eq!(
            std::fs::read(&cred_path).unwrap(),
            before,
            "config parse failure must happen before the credentials-first commit phase"
        );
        assert_eq!(
            std::fs::read(&freedom_path).unwrap(),
            b"operator_id: [unterminated\n".to_vec()
        );
    }

    #[tokio::test]
    async fn write_config_maps_bootstrapped_vault_to_runtime_obsidian_config() {
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        let vault = dir.path().join("NEOTH-Vault");
        let mut state = fixture_state();
        state.bootstrap_vault = true;
        state.vault_path = Some(vault.clone());

        write_config(&neoth_dir, &state)
            .await
            .expect("write_config");

        let cfg = crate::config::FreedomConfig::load_from_path(&neoth_dir.join("freedom.yaml"))
            .expect("load freedom.yaml");
        let vault_s = vault.to_string_lossy().to_string();
        assert_eq!(cfg.obsidian_vault.as_deref(), Some(vault_s.as_str()));
        assert_eq!(cfg.obsidian_subdir.as_deref(), Some("NEOTH-sessions"));
    }

    #[tokio::test]
    async fn step7b_non_interactive_leaves_default_auto_update() {
        // The step writes the default AutoUpdateConfig when
        // interactive == false. Pin the contract so a future
        // refactor that flips the default doesn't silently
        // enable background HTTP traffic.
        let mut state = fixture_state();
        state.auto_update = crate::config::AutoUpdateConfig {
            // Pretend a prior wizard run had enabled it; the
            // non-interactive re-run MUST NOT clobber that.
            enabled: true,
            auto_apply: true,
            ..crate::config::AutoUpdateConfig::default()
        };

        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            ..Default::default()
        };
        step7b_auto_update(&args, false, &mut state).unwrap();

        // Non-interactive run preserves whatever the prior state
        // had — does NOT prompt, does NOT reset.
        assert!(state.auto_update.enabled);
        assert!(state.auto_update.auto_apply);
        // Step marker recorded.
        assert!(
            state
                .steps_completed
                .contains(&(WizardStep::AutoUpdate as u8))
        );
    }

    #[test]
    fn step7b_non_interactive_flags_apply_complete_policy() {
        let mut state = fixture_state();
        let check_only = InitArgs {
            auto_update: true,
            ..Default::default()
        };
        step7b_auto_update(&check_only, false, &mut state).unwrap();
        assert!(state.auto_update.enabled);
        assert!(!state.auto_update.auto_apply);

        let apply = InitArgs {
            auto_update_apply: true,
            ..Default::default()
        };
        step7b_auto_update(&apply, false, &mut state).unwrap();
        assert!(state.auto_update.enabled);
        assert!(state.auto_update.auto_apply);

        let disable = InitArgs {
            no_auto_update: true,
            ..Default::default()
        };
        step7b_auto_update(&disable, false, &mut state).unwrap();
        assert!(!state.auto_update.enabled);
        assert!(!state.auto_update.auto_apply);
    }

    #[test]
    fn step7d_non_interactive_leaves_supervisor_disabled() {
        // A background auto-restart service is a real system change —
        // non-interactive onboarding MUST NOT install one. Pin the
        // off-by-default contract + the step marker.
        let mut state = fixture_state();
        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            ..Default::default()
        };
        step7d_supervisor(&args, false, &mut state).unwrap();
        assert!(
            !state.supervisor.enabled,
            "non-interactive must not install a supervisor"
        );
        assert_eq!(state.supervisor.kind, crate::config::SupervisorKind::None);
        assert!(
            state
                .steps_completed
                .contains(&(WizardStep::Supervisor as u8))
        );
    }

    #[tokio::test]
    async fn write_config_uses_atomic_temp_then_rename() {
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        write_config(&neoth_dir, &fixture_state())
            .await
            .expect("write_config");

        // After successful write, the .tmp sibling must be gone (rename consumed it).
        let tmp = neoth_dir.join("freedom.tmp");
        assert!(!tmp.exists(), "intermediate .tmp must be renamed away");
    }

    #[tokio::test]
    async fn write_config_overwrites_existing_on_force_path() {
        // Simulate a --force re-run: write twice with different states.
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");

        let mut s1 = fixture_state();
        s1.operator_id = Some("first".to_string());
        write_config(&neoth_dir, &s1).await.expect("first write");

        let mut s2 = fixture_state();
        s2.operator_id = Some("second".to_string());
        write_config(&neoth_dir, &s2)
            .await
            .expect("second write replaces first");

        let yaml = neoth_dir.join("freedom.yaml");
        let body = std::fs::read_to_string(&yaml).unwrap();
        assert!(body.contains("operator_id: second"));
        assert!(!body.contains("operator_id: first"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn write_config_sets_mode_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        write_config(&neoth_dir, &fixture_state())
            .await
            .expect("write_config");

        let yaml = neoth_dir.join("freedom.yaml");
        let mode = std::fs::metadata(&yaml).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "freedom.yaml must be 0600 on unix");

        let dir_mode = std::fs::metadata(&neoth_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "~/.neoth/ must be 0700 on unix");
    }

    #[test]
    fn write_initialized_marker_writes_json() {
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        std::fs::create_dir_all(&neoth_dir).unwrap();
        let state = fixture_state();

        write_initialized_marker(&neoth_dir, &state).expect("marker write");

        let path = neoth_dir.join(".initialized");
        assert!(path.exists());

        let body = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        // F-22: wizard_version bumped to 2 after schema extension.
        assert_eq!(parsed["wizard_version"], 2);
        assert_eq!(parsed["operator_id"], "alice");
        // 8 steps after Phase 28b inserted the autonomy step.
        assert_eq!(parsed["steps_completed"].as_array().unwrap().len(), 8);
        assert!(parsed["init_time_unix"].as_u64().unwrap() > 0);
        // F-22: new fields all populated.
        assert!(
            !parsed["neoth_version"].as_str().unwrap().is_empty(),
            "neoth_version must reflect the daemon binary version"
        );
        let iso = parsed["init_time_iso8601"].as_str().unwrap();
        assert!(
            iso.ends_with('Z') && iso.contains('T'),
            "iso8601 must be RFC 3339 UTC: {iso}"
        );
        // fixture_state sets provider_kind = ClaudeCli — should round-trip.
        assert_eq!(parsed["provider_kind"], "claude_cli");
        // fixture_state sets telegram_token, so channels lists telegram.
        let channels = parsed["channels"].as_array().unwrap();
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0], "telegram");
    }

    #[test]
    fn write_initialized_marker_records_telegram_channel() {
        // F-22: when the wizard configured Telegram, the marker should
        // list it under `channels`. Mirrors what `neoth doctor` will
        // surface to the operator.
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        std::fs::create_dir_all(&neoth_dir).unwrap();
        let mut state = fixture_state();
        state.telegram_token = Some(crate::secret::SecretString::from("dummy-token"));

        write_initialized_marker(&neoth_dir, &state).expect("marker write");

        let body = std::fs::read_to_string(neoth_dir.join(".initialized")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        let channels = parsed["channels"].as_array().unwrap();
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0], "telegram");
    }

    #[test]
    fn format_iso8601_rfc3339_round_trips_known_epoch() {
        // Bounds check: zero epoch maps to 1970.
        assert_eq!(format_iso8601(0), "1970-01-01T00:00:00Z");
        // RFC 3339 round-trip via chrono: write → parse → compare.
        let s = format_iso8601(1_700_000_000);
        let parsed = chrono::DateTime::parse_from_rfc3339(&s).expect("RFC3339 parse");
        assert_eq!(parsed.timestamp(), 1_700_000_000);
        // Format invariant — every output ends with Z + carries a T separator.
        assert!(s.ends_with('Z'));
        assert!(s.contains('T'));
    }

    #[test]
    fn configured_channels_lists_telegram_when_token_set() {
        let mut s = fixture_state();
        s.telegram_token = None;
        assert!(configured_channels(&s).is_empty());
        s.telegram_token = Some(crate::secret::SecretString::from("t"));
        assert_eq!(configured_channels(&s), vec!["telegram".to_string()]);
    }

    #[test]
    fn initialized_marker_deserialises_old_v1_format() {
        // F-22 invariant: a `.initialized` file written by the previous
        // wizard (without neoth_version / iso8601 / provider_kind /
        // channels) must still parse — `#[serde(default)]` makes the
        // new fields optional. Future code paths (status, doctor)
        // depend on being able to read old markers without operator
        // intervention.
        let old_marker_json = r#"{
            "wizard_version": 1,
            "operator_id": "legacy_op",
            "steps_completed": [1, 2, 3, 4, 5, 6, 7],
            "init_time_unix": 1700000000
        }"#;
        let parsed: InitializedMarker = serde_json::from_str(old_marker_json).unwrap();
        assert_eq!(parsed.wizard_version, 1);
        assert_eq!(parsed.operator_id, "legacy_op");
        assert!(parsed.neoth_version.is_empty(), "missing field defaults");
        assert!(parsed.init_time_iso8601.is_empty());
        assert!(parsed.provider_kind.is_none());
        assert!(parsed.channels.is_empty());
    }

    #[tokio::test]
    async fn freedom_yaml_roundtrip_via_serde() {
        // Phase 33+ split: freedom.yaml carries the public fields, secrets
        // live in credentials.yaml. Verify the WizardState round-trips by
        // reading BOTH files (the daemon's `FreedomConfig::load_from_path`
        // does the same merge automatically).
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        let original = fixture_state();
        write_config(&neoth_dir, &original).await.expect("write");

        let body = std::fs::read_to_string(neoth_dir.join("freedom.yaml")).unwrap();
        let restored =
            crate::config::FreedomConfig::load_from_path(&neoth_dir.join("freedom.yaml"))
                .expect("deserialize public config + credentials");

        assert_eq!(restored.operator_id, original.operator_id);
        assert_eq!(restored.role, original.role);
        assert_eq!(restored.provider_kind, original.provider_kind);
        // Secrets MUST be absent from freedom.yaml.
        assert!(
            !body.contains("12345678:AAAAAAAAA"),
            "telegram_token must NOT live in freedom.yaml after the split",
        );
        assert!(
            !body.contains("provider_key: /"),
            "provider_key must NOT live in freedom.yaml after the split",
        );
        // But they DO live in the sibling credentials.yaml.
        let cred_path = neoth_dir.join("credentials.yaml");
        assert!(cred_path.exists(), "credentials.yaml must be created");
        let creds = crate::config::credentials::Credentials::load_or_default(&cred_path).unwrap();
        let restored_token = creds.telegram_token.unwrap();
        assert_eq!(
            restored_token.expose(),
            "12345678:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
        assert!(format!("{restored_token:?}").contains("REDACTED"));
    }

    // ── Pick #23 (Session 14) — E-2 Phase 4 council-depth cost warning

    #[test]
    fn depth_warning_at_depth_1_is_not_invoked_in_production_but_still_pure_fn() {
        // The wizard never calls render_council_depth_cost_warning
        // when depth <= 1 — but the fn must stay pure-fn + total so a
        // future refactor that DOES call it with 0/1 still produces a
        // sensible string instead of panicking. At depth=1 the leaf
        // count is 3^1 = 3 (the three outer hemispheres, no recursion).
        let s = render_council_depth_cost_warning(1);
        assert!(s.contains("depth=1"));
        assert!(
            s.contains("3 leaf"),
            "depth=1 should report 3 leaf calls; got: {s}"
        );
    }

    #[test]
    fn depth_warning_at_2_shows_9_leaf_calls() {
        let s = render_council_depth_cost_warning(2);
        assert!(s.contains("depth=2"));
        assert!(s.contains("9 leaf"), "want 9 leaf calls; got: {s}");
        // Default cap is 15 — 9 ≤ 15, so the "fits within" branch
        // should fire.
        assert!(
            s.contains("fits within"),
            "depth-2 cost note must mention cap-fit; got: {s}"
        );
    }

    #[test]
    fn depth_warning_at_3_shows_27_leaf_calls_and_exceeds_cap() {
        let s = render_council_depth_cost_warning(3);
        assert!(s.contains("depth=3"));
        assert!(s.contains("27 leaf"), "want 27 leaf calls; got: {s}");
        // 27 > 15 default cap → must mention budget-exhausted.
        assert!(
            s.contains("exceeds"),
            "depth-3 cost note must mention exceeding cap; got: {s}"
        );
        assert!(
            s.contains("budget-exhausted"),
            "depth-3 must surface the Pick #19 BudgetToken interaction; got: {s}"
        );
    }

    #[test]
    fn depth_warning_at_4_shows_81_leaf_calls() {
        let s = render_council_depth_cost_warning(4);
        assert!(s.contains("depth=4"));
        assert!(s.contains("81 leaf"), "want 81 leaf calls; got: {s}");
    }

    #[test]
    fn depth_warning_clamps_above_max_to_max_leaf_count() {
        // Defensive: even if a caller bypasses the type system and
        // passes depth=255, the render fn must not over-compute.
        let s = render_council_depth_cost_warning(255);
        // Worst-case render still bounded to MAX_HEMISPHERE_COUNCIL_DEPTH
        // power = 3^4 = 81.
        assert!(
            s.contains("81 leaf"),
            "render must clamp internally to MAX depth; got: {s}"
        );
    }

    #[test]
    fn depth_warning_mentions_remedies_in_freedom_yaml() {
        // Operator-facing strings must point at the lever they can pull.
        let s = render_council_depth_cost_warning(3);
        assert!(s.contains("freedom.yaml"), "operator needs the remedy file");
        assert!(
            s.contains("max_calls_per_user_message"),
            "must name the actual config key"
        );
    }

    #[test]
    fn depth_warning_lists_recommended_defaults() {
        let s = render_council_depth_cost_warning(2);
        assert!(s.contains("depth=1"));
        assert!(s.contains("depth=2"));
        // The "depth=3+" hint should still be in the table even when
        // the operator picked depth=2 — they should see the next-step
        // implications too.
        assert!(s.contains("depth=3+"));
    }

    // ── D-102 wizard step 7c — bulk plugin activation tests ─────────

    #[test]
    fn step7c_missing_plugins_dir_silent_noop_records_marker() {
        // Common first-run state: ~/.neoth/plugins/ doesn't exist yet.
        // Step must not panic + must record its marker so a wizard
        // resume can tell the step ran.
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth-empty");
        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            ..Default::default()
        };
        let mut state = fixture_state();
        step7c_wasm_plugin_activation(&args, false, &neoth_dir, &mut state).unwrap();
        assert!(
            state.plugins.wasm.activations.is_empty(),
            "no plugins discovered → no activations recorded"
        );
        assert!(
            state
                .steps_completed
                .contains(&(WizardStep::WasmPlugins as u8))
        );
    }

    #[test]
    fn step7c_empty_plugins_dir_silent_noop() {
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        std::fs::create_dir_all(neoth_dir.join("plugins")).unwrap();
        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            ..Default::default()
        };
        let mut state = fixture_state();
        step7c_wasm_plugin_activation(&args, false, &neoth_dir, &mut state).unwrap();
        assert!(state.plugins.wasm.activations.is_empty());
        assert!(
            state
                .steps_completed
                .contains(&(WizardStep::WasmPlugins as u8))
        );
    }

    #[test]
    fn step7c_non_interactive_with_discovered_plugins_leaves_activations_empty() {
        // Per panel verdict on D-102 + non-interactive contract:
        // automatically opting plugins in without operator review
        // would defeat the default-inactive guarantee. Activations
        // must stay empty (= every id falls through to default
        // Pending at boot).
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        let plugins_root = neoth_dir.join("plugins").join("indexer_v1");
        std::fs::create_dir_all(&plugins_root).unwrap();
        std::fs::write(
            plugins_root.join("plugin.toml"),
            "id = \"indexer_v1\"\nname = \"Indexer\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        // Minimal valid WASM module bytes (wasm magic + version).
        std::fs::write(
            plugins_root.join("plugin.wasm"),
            [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
        )
        .unwrap();
        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            ..Default::default()
        };
        let mut state = fixture_state();
        step7c_wasm_plugin_activation(&args, false, &neoth_dir, &mut state).unwrap();
        assert!(
            state.plugins.wasm.activations.is_empty(),
            "non-interactive run MUST NOT auto-activate; got {:?}",
            state.plugins.wasm.activations,
        );
        assert!(
            state
                .steps_completed
                .contains(&(WizardStep::WasmPlugins as u8))
        );
    }

    #[test]
    fn step7c_non_interactive_with_enable_plugin_flag_activates_named_ids() {
        // E-21 non-interactive follow-up: `--enable-plugin indexer_v1`
        // during scripted bring-up MUST land indexer_v1 = Active in
        // freedom.yaml without prompting. Other discovered plugins
        // stay Pending (no entry = default at boot).
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        for id in ["indexer_v1", "recall_rerank"] {
            let pd = neoth_dir.join("plugins").join(id);
            std::fs::create_dir_all(&pd).unwrap();
            std::fs::write(
                pd.join("plugin.toml"),
                format!("id = \"{id}\"\nname = \"x\"\nversion = \"0.1.0\"\n"),
            )
            .unwrap();
            std::fs::write(
                pd.join("plugin.wasm"),
                [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            )
            .unwrap();
        }
        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            enable_plugin: vec!["indexer_v1".to_string()],
            ..Default::default()
        };
        let mut state = fixture_state();
        step7c_wasm_plugin_activation(&args, false, &neoth_dir, &mut state).unwrap();
        assert_eq!(
            state
                .plugins
                .wasm
                .activations
                .get("indexer_v1")
                .map(|record| record.state),
            Some(crate::wasm_plugin::discovery::PluginActivation::Active),
            "indexer_v1 must be Active after --enable-plugin",
        );
        // recall_rerank stays absent from the map → default Pending
        // at daemon boot.
        assert!(
            !state.plugins.wasm.activations.contains_key("recall_rerank"),
            "unspecified plugins must stay PENDING (no map entry); got {:?}",
            state.plugins.wasm.activations,
        );
    }

    #[test]
    fn step7c_non_interactive_unknown_enable_plugin_id_is_warn_not_fail() {
        // Typo on the operator's CLI line MUST NOT fail the wizard.
        // Per the non-interactive contract: partial activation is
        // better than a failed init.
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        let pd = neoth_dir.join("plugins").join("indexer_v1");
        std::fs::create_dir_all(&pd).unwrap();
        std::fs::write(
            pd.join("plugin.toml"),
            "id = \"indexer_v1\"\nname = \"x\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::write(
            pd.join("plugin.wasm"),
            [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
        )
        .unwrap();
        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            enable_plugin: vec!["typoed_id".to_string(), "indexer_v1".to_string()],
            ..Default::default()
        };
        let mut state = fixture_state();
        // Should not panic / not bail; typoed_id is ignored, the valid
        // id still activates.
        step7c_wasm_plugin_activation(&args, false, &neoth_dir, &mut state).unwrap();
        assert!(state.plugins.wasm.activations.contains_key("indexer_v1"));
        assert!(!state.plugins.wasm.activations.contains_key("typoed_id"));
    }

    #[tokio::test]
    async fn step6b_non_interactive_silent_noop_records_marker() {
        // K-3.5 contract: non-interactive runs skip the prompt
        // entirely (no flag yet). The step must record its marker
        // for resume tracking.
        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            ..Default::default()
        };
        let mut state = fixture_state();
        step6b_keet_pairing(&args, false, &mut state).await.unwrap();
        assert!(state.keet_seed_phrase.is_none());
        assert!(state.keet_bridge_bearer_token.is_none());
        // GOLD-COR-07: 6b's marker is now distinct from 5d's (was both 60).
        assert!(
            state
                .steps_completed
                .contains(&(WizardStep::KeetPairing as u8))
        );
    }

    #[test]
    fn wizard_step_all_covered() {
        // GOLD-COR-07 / A-26 + GOLD-ARCH-20: the regression guard. step 5d and
        // step 6b both used to push `60`, making the checkpoint record
        // ambiguous. Every discriminant in `WizardStep::ALL` must be distinct —
        // a future duplicate (or a re-used value on a new sub-step) trips this
        // test instead of silently corrupting resume state. The count guard
        // trips when a variant is added to the enum without registering it in
        // `ALL` (or vice versa).
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for &step in WizardStep::ALL {
            let m = step as u8;
            assert!(
                seen.insert(m),
                "duplicate wizard step discriminant {m} in WizardStep::ALL"
            );
        }
        assert_eq!(
            seen.len(),
            WizardStep::ALL.len(),
            "WizardStep::ALL must contain only distinct discriminants"
        );
        assert_eq!(
            WizardStep::ALL.len(),
            23,
            "WizardStep variant count drifted"
        );
    }

    #[test]
    fn wizard_step_try_from_round_trips_and_rejects_unknown() {
        // GOLD-ARCH-20: every registered step survives u8 -> WizardStep -> u8;
        // gaps and out-of-range values are rejected (no silent Default).
        for &step in WizardStep::ALL {
            let raw = step as u8;
            assert_eq!(WizardStep::try_from(raw).unwrap() as u8, raw);
        }
        assert!(WizardStep::try_from(0u8).is_err());
        assert!(WizardStep::try_from(9u8).is_err()); // gap between 8 and 56
        assert!(WizardStep::try_from(255u8).is_err());
    }

    #[test]
    fn initialized_marker_steps_completed_deserializes_raw_u8_array() {
        // GOLD-ARCH-20 backward-compat pin: `.initialized` files written before
        // the WizardStep enum hold raw JSON integers in steps_completed. The
        // Vec<u8> persistence boundary keeps parsing them, and every stored
        // value maps to a known WizardStep.
        let json = r#"{
            "wizard_version": 2,
            "neoth_version": "0.4.0",
            "operator_id": "legacy_op",
            "steps_completed": [1, 14, 2, 3, 4, 5, 6, 7, 8, 56, 58, 60, 65, 61, 62, 63, 64, 70, 71, 72],
            "init_time_unix": 1700000000,
            "init_time_iso8601": "2023-11-14T22:13:20Z",
            "channels": []
        }"#;
        let parsed: super::InitializedMarker = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.steps_completed.len(), 20);
        for &raw in &parsed.steps_completed {
            WizardStep::try_from(raw)
                .unwrap_or_else(|_| panic!("step value {raw} not covered by WizardStep"));
        }
    }

    #[test]
    fn legacy_keet_credentials_remain_parseable_for_cleanup() {
        // Backward compatibility only: older files must remain readable so
        // `neoth channel remove keet` can erase both fields.
        let legacy = format!(
            "keet_seed_phrase: alpha-bravo-charlie\npears_bearer_token: {}\n",
            "deadbeef".repeat(8)
        );
        let cred: crate::config::credentials::Credentials =
            serde_yaml::from_str(&legacy).expect("deserialize legacy credential keys");
        assert!(cred.has_any());
        let yaml = serde_yaml::to_string(&cred).expect("serialize");
        assert!(yaml.contains("keet_seed_phrase:"));
        assert!(yaml.contains("keet_bridge_bearer_token:"));
        assert!(!yaml.contains("pears_bearer_token:"));
        let back: crate::config::credentials::Credentials =
            serde_yaml::from_str(&yaml).expect("deserialize");
        assert_eq!(
            back.keet_seed_phrase
                .as_ref()
                .map(|s| s.expose().to_string()),
            Some("alpha-bravo-charlie".to_string()),
        );
        assert_eq!(
            back.keet_bridge_bearer_token
                .as_ref()
                .map(|s| s.expose().len()),
            Some(64),
        );
    }

    // ── K-4b telegram-prompt text tests (Session 21) ────────────────

    #[test]
    fn telegram_prompt_ignores_unrelated_pear_runtime_presence() {
        let s = k4b_telegram_prompt_text(true);
        assert!(!s.contains("FALLBACK"), "msg: {s}");
        assert!(!s.contains("Keet"), "msg: {s}");
        assert!(s.contains("Telegram"), "msg: {s}");
        assert_eq!(s, k4b_telegram_prompt_text(false));
    }

    #[test]
    fn k4b_prompt_neutral_when_pear_missing() {
        // Backward-compat pin: unrelated Pear Runtime presence must not change
        // the Telegram prompt. Keet readiness is proven through the companion,
        // not by finding a `pear` executable.
        let s = k4b_telegram_prompt_text(false);
        assert!(!s.contains("FALLBACK"));
        assert!(!s.contains("Keet"));
        assert!(s.contains("Telegram"));
        assert!(s.contains("optional"));
    }

    #[test]
    fn k4b_prompt_keeps_step_label_consistent_across_modes() {
        // Both variants must carry the same `[6/9]` step label so the
        // wizard transcript stays parseable — operators (or automated
        // probes) grepping for "[6/9]" find it regardless of the pear
        // detection outcome.
        assert!(k4b_telegram_prompt_text(true).contains("[6/9]"));
        assert!(k4b_telegram_prompt_text(false).contains("[6/9]"));
    }

    // ── K-4 channel-ordering tests (Session 21) ─────────────────────

    #[test]
    fn configured_channels_ignores_legacy_keet_seed() {
        let mut s = fixture_state();
        s.keet_seed_phrase = Some(crate::secret::SecretString::from(
            "alpha bravo charlie delta echo foxtrot golf hotel india juliet \
             kilo lima mike november oscar papa quebec romeo sierra tango \
             uniform victor whiskey xray",
        ));
        let chans = configured_channels(&s);
        assert_eq!(chans, vec!["telegram".to_string()]);
    }

    #[test]
    fn legacy_keet_seed_does_not_complete_onboarding() {
        let mut s = fixture_state();
        s.telegram_token = None;
        s.keet_seed_phrase = Some(crate::secret::SecretString::from("seed".to_string()));
        let chans = configured_channels(&s);
        assert!(chans.is_empty());
    }

    #[test]
    fn configured_channels_lists_telegram() {
        let s = fixture_state(); // has Telegram, no Keet
        let chans = configured_channels(&s);
        assert_eq!(chans, vec!["telegram".to_string()]);
    }

    #[test]
    fn k4_configured_channels_empty_when_neither_paired() {
        let mut s = fixture_state();
        s.telegram_token = None;
        s.keet_seed_phrase = None;
        assert!(configured_channels(&s).is_empty());
    }

    #[test]
    fn wizard_state_keet_fields_excluded_from_freedom_yaml() {
        // K-3.5 split contract: state.keet_seed_phrase +
        // state.keet_bridge_bearer_token are #[serde(skip)] so they NEVER
        // surface in freedom.yaml. The serde wire pin: emitting a
        // WizardState carrying both fields produces YAML that does
        // NOT mention either key.
        let mut state = fixture_state();
        state.keet_seed_phrase = Some(crate::secret::SecretString::from("not_in_freedom_yaml"));
        state.keet_bridge_bearer_token = Some(crate::secret::SecretString::from(
            "token_not_in_freedom_yaml",
        ));
        let yaml = serde_yaml::to_string(&state).expect("serialize");
        assert!(
            !yaml.contains("keet_seed_phrase"),
            "keet_seed_phrase MUST be #[serde(skip)] — yaml: {yaml}"
        );
        assert!(
            !yaml.contains("keet_bridge_bearer_token"),
            "keet_bridge_bearer_token MUST be #[serde(skip)] — yaml: {yaml}"
        );
        assert!(!yaml.contains("not_in_freedom_yaml"));
        assert!(!yaml.contains("token_not_in_freedom_yaml"));
    }

    #[test]
    fn wizard_state_plugins_field_round_trips_through_yaml() {
        // D-102 wire-format pin: WizardState.plugins serialises into
        // the same bound activation-record shape FreedomConfig deserialises
        // from. A drift here would
        // mean the operator's wizard picks don't reach the daemon.
        let mut state = fixture_state();
        state.plugins.wasm.activations.insert(
            "indexer_v1".to_string(),
            crate::wasm_plugin::discovery::PluginActivationRecord {
                state: crate::wasm_plugin::discovery::PluginActivation::Active,
                approval: Some(crate::wasm_plugin::discovery::PluginApproval {
                    approved_permission:
                        crate::wasm_plugin::manifest::RequestedPermission::ReadOnly,
                    manifest_sha256: "manifest-hash".to_string(),
                    wasm_sha256: "wasm-hash".to_string(),
                }),
            },
        );
        state.plugins.wasm.activations.insert(
            "recall_rerank".to_string(),
            crate::wasm_plugin::discovery::PluginActivationRecord::from_state(
                crate::wasm_plugin::discovery::PluginActivation::Disabled,
            ),
        );
        let yaml = serde_yaml::to_string(&state).expect("serialize");
        assert!(yaml.contains("plugins:"));
        assert!(yaml.contains("wasm:"));
        assert!(yaml.contains("activations:"));
        assert!(yaml.contains("indexer_v1:"));
        assert!(yaml.contains("state: active"));
        assert!(yaml.contains("approved_permission: read_only"));
        assert!(yaml.contains("manifest_sha256: manifest-hash"));
        assert!(yaml.contains("wasm_sha256: wasm-hash"));
        assert!(yaml.contains("recall_rerank:"));
        assert!(yaml.contains("state: disabled"));
    }

    // ── Workstream B (Session 22) — 5 wizard step regressions ─────────────

    fn args_with_flag(set: impl FnOnce(&mut InitArgs)) -> InitArgs {
        let mut a = InitArgs {
            non_interactive: true,
            accept_license: true,
            ..Default::default()
        };
        set(&mut a);
        a
    }

    #[tokio::test]
    async fn step5c_non_interactive_no_op_when_provider_not_local_qwen() {
        // Cloud-only operator — no LocalQwen path. Step must skip
        // silently without recording opt-in.
        let mut state = fixture_state();
        state.provider_kind = Some(ProviderKind::ClaudeCli);
        let args = args_with_flag(|a| a.download_qwen_weights = true);
        step5c_qwen_weights(&args, false, &mut state).await.unwrap();
        assert!(!state.download_qwen_weights);
        assert!(
            state
                .steps_completed
                .contains(&(WizardStep::QwenWeights as u8))
        );
    }

    // The std::Mutex env-lock is intentional here: tests in this module
    // mutate process-global $HOME / $USERPROFILE so they MUST serialise
    // against each other. An async-aware Mutex would defeat the purpose
    // (tokio's mutex doesn't poison on panic, so a panicking test could
    // leave the env corrupted for the next test). The await inside the
    // critical section is bounded (`step5c_qwen_weights` does no
    // operator-blocking IO under #[non_interactive=false]).
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn step5c_non_interactive_records_when_flag_set_and_local_qwen() {
        let _env_lock = lock_home_env();
        // LocalQwen-using operator + --download-qwen-weights → opt-in
        // recorded. The probe lives under a synthetic HOME so the
        // "weights missing" branch is exercised.
        let temp = tempfile::tempdir().unwrap();
        let prev_home = std::env::var_os("HOME");
        let prev_userprofile = std::env::var_os("USERPROFILE");
        unsafe {
            std::env::set_var("HOME", temp.path());
            std::env::set_var("USERPROFILE", temp.path());
        }

        let mut state = fixture_state();
        state.provider_kind = Some(ProviderKind::LocalQwen);
        let args = args_with_flag(|a| a.download_qwen_weights = true);
        step5c_qwen_weights(&args, false, &mut state).await.unwrap();
        assert!(state.download_qwen_weights);
        assert!(
            state
                .steps_completed
                .contains(&(WizardStep::QwenWeights as u8))
        );

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

    #[tokio::test]
    async fn step6c_non_interactive_no_op_when_flag_absent() {
        let mut state = fixture_state();
        let args = args_with_flag(|_| {}); // no install_obsidian
        step6c_obsidian_install(&args, false, &mut state)
            .await
            .unwrap();
        // Whether install_obsidian was set depends on whether the host
        // happens to have Obsidian already installed (sets it true).
        // The flag-absent path either records "already present" or
        // does nothing — the marker MUST land either way.
        assert!(
            state
                .steps_completed
                .contains(&(WizardStep::Obsidian as u8))
        );
    }

    #[tokio::test]
    async fn step6c_non_interactive_records_when_flag_set() {
        let mut state = fixture_state();
        let args = args_with_flag(|a| a.install_obsidian = true);
        step6c_obsidian_install(&args, false, &mut state)
            .await
            .unwrap();
        assert!(state.install_obsidian);
        assert!(
            state
                .steps_completed
                .contains(&(WizardStep::Obsidian as u8))
        );
    }

    #[test]
    fn step6d_non_interactive_no_op_when_flag_absent() {
        let mut state = fixture_state();
        let args = args_with_flag(|_| {});
        step6d_obsidian_vault_bootstrap(&args, false, &mut state).unwrap();
        assert!(!state.bootstrap_vault);
        assert!(state.vault_path.is_none());
        assert!(
            state
                .steps_completed
                .contains(&(WizardStep::ObsidianVault as u8))
        );
    }

    #[test]
    fn step6d_non_interactive_bootstraps_vault_when_flag_set() {
        // Session 24 env-mutation refactor: use the explicit
        // `home_override` parameter instead of mutating the global
        // HOME / USERPROFILE env vars. No lock needed; tempdir
        // is fully isolated per test.
        let temp = tempfile::tempdir().unwrap();
        let mut state = fixture_state();
        let args = args_with_flag(|a| a.bootstrap_vault = true);
        step6d_obsidian_vault_bootstrap_with_home(&args, false, &mut state, Some(temp.path()))
            .unwrap();

        assert!(state.bootstrap_vault);
        let path = state.vault_path.as_ref().expect("vault_path recorded");
        assert!(path.exists());
        assert!(path.join("README.md").exists());
        assert!(path.join(".obsidian").join("app.json").exists());
        assert!(
            state
                .steps_completed
                .contains(&(WizardStep::ObsidianVault as u8))
        );
    }

    #[test]
    fn step6d_idempotent_skips_files_that_already_exist() {
        // Session 24 env-mutation refactor: explicit home_override.
        // Operator re-runs init with --force: existing vault files
        // must NOT be clobbered (operator edits win).
        let temp = tempfile::tempdir().unwrap();
        let vault = temp.path().join("Documents").join("NEOTH-Vault");
        std::fs::create_dir_all(&vault).unwrap();
        let sentinel = "OPERATOR EDIT — DO NOT OVERWRITE\n";
        std::fs::write(vault.join("README.md"), sentinel).unwrap();

        let mut state = fixture_state();
        let args = args_with_flag(|a| a.bootstrap_vault = true);
        step6d_obsidian_vault_bootstrap_with_home(&args, false, &mut state, Some(temp.path()))
            .unwrap();

        let body = std::fs::read_to_string(vault.join("README.md")).unwrap();
        assert_eq!(body, sentinel, "operator-edited README must be preserved");
    }

    #[tokio::test]
    async fn step6e_non_interactive_no_op_when_flag_absent() {
        let mut state = fixture_state();
        let args = args_with_flag(|_| {});
        step6e_n8n_install(&args, false, &mut state).await.unwrap();
        assert!(!state.install_n8n);
        assert!(state.steps_completed.contains(&(WizardStep::N8n as u8)));
    }

    #[tokio::test]
    async fn step6e_non_interactive_records_when_flag_set() {
        let mut state = fixture_state();
        let args = args_with_flag(|a| a.install_n8n = true);
        step6e_n8n_install(&args, false, &mut state).await.unwrap();
        assert!(state.install_n8n);
        assert!(state.steps_completed.contains(&(WizardStep::N8n as u8)));
    }

    #[test]
    fn step6f_non_interactive_no_op_when_flag_absent() {
        let mut state = fixture_state();
        let args = args_with_flag(|_| {});
        step6f_import_memory(&args, false, &mut state).unwrap();
        assert!(state.import_memory.is_none());
        assert!(
            state
                .steps_completed
                .contains(&(WizardStep::ImportMemory as u8))
        );
    }

    #[test]
    fn step6f_non_interactive_records_path_when_flag_set() {
        let temp = tempfile::tempdir().unwrap();
        let memory_path = temp.path().join("HIPPOCAMPUS_CORE.md");
        std::fs::write(&memory_path, "synthetic legacy-ai seed").unwrap();

        let mut state = fixture_state();
        let args = args_with_flag(|a| a.import_memory = Some(memory_path.clone()));
        step6f_import_memory(&args, false, &mut state).unwrap();
        assert_eq!(state.import_memory.as_ref(), Some(&memory_path));
        assert!(
            state
                .steps_completed
                .contains(&(WizardStep::ImportMemory as u8))
        );
    }

    // --- JV-IMP-08: import intent surfaces in freedom.yaml ---

    #[tokio::test]
    async fn step6f_import_intent_surfaces_in_freedom_yaml() {
        // Proves the full path:
        //   --import-memory flag
        //   → step6f records state.import_memory
        //   → write_config serialises it to freedom.yaml
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("my-manifest.yaml");
        std::fs::write(&manifest, "sources: []\n").unwrap();

        let mut state = fixture_state();
        // Clear import_memory so fixture_state's pre-populated value doesn't interfere.
        state.import_memory = None;
        let args = args_with_flag(|a| a.import_memory = Some(manifest.clone()));

        // Step records intent and pushes the step marker.
        step6f_import_memory(&args, false, &mut state).unwrap();
        assert_eq!(state.import_memory.as_ref(), Some(&manifest));
        assert!(
            state
                .steps_completed
                .contains(&(WizardStep::ImportMemory as u8)),
            "ImportMemory step marker must be pushed"
        );

        // write_config persists the path to freedom.yaml.
        let neoth_dir = dir.path().join(".neoth");
        std::fs::create_dir_all(&neoth_dir).unwrap();
        write_config(&neoth_dir, &state).await.unwrap();

        let yaml = std::fs::read_to_string(neoth_dir.join("freedom.yaml")).unwrap();
        assert!(
            yaml.contains("import_memory"),
            "freedom.yaml must contain the import_memory field; got:\n{yaml}"
        );
    }

    // --- GOLD-HON-10: step 1d onboarding mode (new vs migration) ---

    #[test]
    fn step1d_non_interactive_defaults_to_new_without_import_flag() {
        let mut state = WizardState::default();
        let args = args_with_flag(|_| {});
        step1d_onboarding_mode(&args, false, &mut state).unwrap();
        assert_eq!(state.onboarding_mode, OnboardingMode::New);
        assert!(
            state
                .steps_completed
                .contains(&(WizardStep::OnboardingMode as u8))
        );
    }

    #[test]
    fn step1d_non_interactive_infers_migration_from_import_flag() {
        let mut state = WizardState::default();
        let args = args_with_flag(|a| {
            a.import_memory = Some(std::path::PathBuf::from("import-manifest.yaml"));
        });
        step1d_onboarding_mode(&args, false, &mut state).unwrap();
        assert_eq!(state.onboarding_mode, OnboardingMode::Migration);
        assert!(
            state
                .steps_completed
                .contains(&(WizardStep::OnboardingMode as u8))
        );
    }

    #[test]
    fn step1d_onboarding_mode_recorded_before_identity_step() {
        // The HON-10 contract: the new-vs-migration question precedes the
        // identity (operator-id) step. Run both on a fresh state and assert
        // the 1d marker lands before the step-2 marker.
        let mut state = WizardState::default();
        let args = args_with_flag(|_| {});
        step1d_onboarding_mode(&args, false, &mut state).unwrap();
        step2_operator_id(&args, false, &mut state).unwrap();
        let idx_1d = state
            .steps_completed
            .iter()
            .position(|&m| m == WizardStep::OnboardingMode as u8)
            .expect("1d marker present");
        let idx_2 = state
            .steps_completed
            .iter()
            .position(|&m| m == WizardStep::OperatorId as u8)
            .expect("step-2 marker present");
        assert!(
            idx_1d < idx_2,
            "onboarding mode (1d) must be recorded before identity (step 2)"
        );
    }

    #[test]
    fn inference_uses_local_qwen_detects_default_slot() {
        use crate::config::inference::{HemisphereSlot, InferenceProvider};
        let mut topology = crate::config::inference::InferenceTopology::default();
        topology.default_slot = HemisphereSlot {
            provider: Some(InferenceProvider::LocalQwen),
            ..Default::default()
        };
        assert!(inference_uses_local_qwen(&topology, &None));
    }

    #[test]
    fn inference_uses_local_qwen_detects_hemisphere_override() {
        use crate::config::inference::{HemisphereSlot, InferenceProvider};
        let mut topology = crate::config::inference::InferenceTopology::default();
        topology.left = HemisphereSlot {
            provider: Some(InferenceProvider::LocalQwen),
            ..Default::default()
        };
        assert!(inference_uses_local_qwen(&topology, &None));
    }

    #[test]
    fn inference_uses_local_qwen_false_for_cloud_only_topology() {
        let topology = crate::config::inference::InferenceTopology::default();
        assert!(!inference_uses_local_qwen(
            &topology,
            &Some(ProviderKind::ClaudeCli)
        ));
    }

    // ── C-05 (Session 25) credential-import sidecar ────────────────────

    #[test]
    fn credential_import_sidecar_writes_redacted_payload_only() {
        // SC-17 invariant: the sidecar carries the redacted projection,
        // never the secrets. Test pins this contract for the wizard
        // step's disk shape.
        use crate::security::credential_redact::{ImportSource, RedactedCredentialImportPayload};
        let home = tempfile::tempdir().unwrap();
        let payload = RedactedCredentialImportPayload {
            source: ImportSource::Bitwarden,
            entry_count: 3,
            distinct_tags_sorted: vec!["banking".into(), "work".into()],
            services_hash: "deadbeefcafebabe".into(),
            target_vault_id: "primary".into(),
            ts_unix: 1_700_000_000,
            services_redacted: true,
        };
        let path = write_credential_import_sidecar(home.path(), 1_700_000_000, &payload).unwrap();
        assert!(path.exists());
        assert!(
            path.file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|name| name.starts_with("credentials_import_00000000001700000000_"))
        );
        let body = std::fs::read_to_string(&path).unwrap();
        // SC-17 keys present; no secret-bearing keys leaked.
        assert!(body.contains("\"services_redacted\""));
        assert!(body.contains("\"entry_count\""));
        assert!(body.contains("\"services_hash\""));
        assert!(!body.contains("password"));
        assert!(!body.contains("secret"));
    }

    #[test]
    fn credential_import_sidecar_preserves_same_second_events_atomically() {
        use crate::security::credential_redact::{ImportSource, RedactedCredentialImportPayload};
        let home = tempfile::tempdir().unwrap();
        let payload = RedactedCredentialImportPayload {
            source: ImportSource::Bitwarden,
            entry_count: 0,
            distinct_tags_sorted: Vec::new(),
            services_hash: "0000000000000000".into(),
            target_vault_id: "primary".into(),
            ts_unix: 100,
            services_redacted: true,
        };
        let first = write_credential_import_sidecar(home.path(), 100, &payload).unwrap();
        let second = write_credential_import_sidecar(home.path(), 100, &payload).unwrap();
        assert_ne!(first, second);
        assert!(first.exists());
        assert!(second.exists());
        assert!(!std::fs::read_dir(home.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
    }

    // ── Session 27: NOOB-UX experience-level gates for step5c/5d/6e/7 ──
    //
    // Pattern matches step5b (Session 26): Beginner short-circuits
    // dialoguer prompts and takes safe defaults silently. The tests
    // exercise the early-return branch — if it regresses, step6e_n8n /
    // step7_autonomy would block on stdin instead of completing, which
    // surfaces as the test hanging the suite. Better to fail fast.

    #[test]
    fn step5d_beginner_records_marker() {
        // Beginner sees the 1-line plain-English summary; the marker
        // still lands so the audit chain has the same shape across
        // experience levels.
        let mut state = fixture_state();
        state.experience_level = crate::wizard::recommend::ExperienceLevel::Beginner;
        step5d_profile_approval_gate(true, &mut state).expect("step5d Beginner");
        assert!(
            state
                .steps_completed
                .contains(&(WizardStep::ProfileGate as u8)),
            "step5d marker (60) must be recorded irrespective of experience level",
        );
    }

    #[test]
    fn step5d_intermediate_records_marker() {
        // Intermediate operators still get the 6-line technical
        // version; assert the marker still records so future drift
        // (e.g. early-return-without-marker) is caught.
        let mut state = fixture_state();
        state.experience_level = crate::wizard::recommend::ExperienceLevel::Intermediate;
        step5d_profile_approval_gate(true, &mut state).expect("step5d Intermediate");
        assert!(
            state
                .steps_completed
                .contains(&(WizardStep::ProfileGate as u8))
        );
    }

    #[tokio::test]
    async fn step6e_beginner_skips_n8n_silently() {
        // Beginner gate MUST short-circuit before dialoguer. If this
        // regresses, the test hangs on stdin — fail-fast is the goal.
        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            ..Default::default()
        };
        let mut state = fixture_state();
        state.experience_level = crate::wizard::recommend::ExperienceLevel::Beginner;
        // Interactive=true would normally prompt; the Beginner gate
        // hits FIRST and short-circuits the dialoguer call.
        step6e_n8n_install(&args, true, &mut state)
            .await
            .expect("step6e Beginner");
        assert!(
            !state.install_n8n,
            "Beginner default is don't-install n8n — operator opts in via settings later",
        );
        assert!(state.steps_completed.contains(&(WizardStep::N8n as u8)));
    }

    #[test]
    fn step7_beginner_takes_standard_silently() {
        // Beginner skips the 5-option autonomy matrix and lands on
        // Standard. The 5-option matrix uses jargon (paid-call
        // thresholds, policy.yaml::dangerous_targets) that scares
        // non-developers.
        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            ..Default::default()
        };
        let mut state = fixture_state();
        state.experience_level = crate::wizard::recommend::ExperienceLevel::Beginner;
        state.autonomy = crate::permissions::AutonomyLevel::Strict; // start non-default
        step7_autonomy(&args, true, &mut state).expect("step7 Beginner");
        assert_eq!(
            state.autonomy,
            crate::permissions::AutonomyLevel::Standard,
            "Beginner gate must land on Standard regardless of prior state",
        );
        assert!(
            state
                .steps_completed
                .contains(&(WizardStep::Autonomy as u8))
        );
    }

    // ── GOLD-ADAPT-OH-03: write_config sets onboarding_complete flag ──────────

    /// When at least one channel (telegram) is configured, write_config must
    /// emit `onboarding_complete: true` into freedom.yaml.
    #[tokio::test]
    async fn oh03_write_config_sets_flag_true_when_telegram_configured() {
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        // fixture_state() has telegram_token set → onboarding_complete = true.
        let state = fixture_state();
        write_config(&neoth_dir, &state)
            .await
            .expect("write_config");
        let body = std::fs::read_to_string(neoth_dir.join("freedom.yaml")).unwrap();
        assert!(
            body.contains("onboarding_complete: true"),
            "must be true when telegram configured; got:\n{body}"
        );
    }

    /// When no channel is configured, write_config must emit
    /// `onboarding_complete: false` into freedom.yaml.
    #[tokio::test]
    async fn oh03_write_config_sets_flag_false_when_no_channel() {
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        let mut state = fixture_state();
        // Strip both wizard-path channels.
        state.telegram_token = None;
        state.keet_seed_phrase = None;
        state.onboarding_complete = false;
        // Fresh state with no channel remains incomplete. A force-reconfigure
        // state that was already complete is intentionally preserved because
        // lossless credential RMW also preserves its existing channel token.
        write_config(&neoth_dir, &state)
            .await
            .expect("write_config");
        let body = std::fs::read_to_string(neoth_dir.join("freedom.yaml")).unwrap();
        assert!(
            body.contains("onboarding_complete: false"),
            "must be false when no wizard-path channel configured; got:\n{body}"
        );
    }
}
