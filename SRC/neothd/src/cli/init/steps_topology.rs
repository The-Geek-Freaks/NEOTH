//! Wizard inference-topology steps (GOLD-ARCH-05): step5b topology,
//! step5b2 ollama provisioning, step5c qwen weights, step5d profile
//! approval gate. Split out of `cli/init.rs`.

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

#[cfg(feature = "wizard")]
use super::apply_local_multi_preset_interactive;
use super::{
    InitArgs, WizardState, WizardStep, apply_local_only_preset, collect_ollama_model_refs,
    inference_uses_local_qwen, parse_topology_mode_arg, prompt_hemisphere_model,
    prompt_inference_provider, recommended_provider_for_role, render_council_depth_cost_warning,
    topology_default_idx_for_probe,
};

/// Step 5b — inference topology (D14b).
///
/// Operator picks:
///   1. **Mode** — single (one provider for all), triplet (same provider
///      on all three hemispheres but separate keys/models), or custom
///      (per-hemisphere provider).
///   2. **Accelerator** — auto-detected default, override allowed.
///   3. **Embedding provider** — local Qwen (uses the chosen accelerator)
///      or a cloud LLM with embedding endpoint.
///
/// Persists into `state.inference`. Non-interactive uses the
/// `--inference-mode` / `--accelerator-override` / `--embedding-provider`
/// flags and falls back to safe defaults (single mode, auto accelerator,
/// no embedding provider).
pub(crate) fn step5b_inference_topology(
    args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
    use crate::config::inference::{HemisphereSlot, InferenceProvider, TopologyMode};
    use crate::daemon::accelerator;

    debug!("wizard step 5b: inference topology");

    // Auto-detect runs in both interactive and non-interactive paths so we
    // log what we found. Cheap (<500ms total) — see daemon::accelerator.
    let probe = accelerator::probe();
    info!(
        picked = probe.picked.as_str(),
        cuda = probe.cuda,
        metal = probe.metal,
        openvino = probe.openvino,
        "accelerator probe complete"
    );

    // Mirror the operator's step-5 provider choice into default_slot so the
    // common single-mode case round-trips without re-asking the operator.
    state.inference.default_slot = HemisphereSlot {
        provider: state.provider_kind.map(|k| k.to_inference()),
        model: state.provider_model.clone(),
        key: state.provider_key.clone(),
        endpoint: state.provider_endpoint.clone(),
        region: None,
        api_version: None,
        // GOLD-WIRE-04: the single-mode default slot carries no council voice.
        voice: None,
    };

    // Non-interactive: honour CLI overrides, otherwise stay in single mode.
    if !interactive {
        let mode = parse_topology_mode_arg(args.inference_mode.as_deref())?;
        state.inference.mode = mode;
        if let Some(o) = args.accelerator_override.as_deref() {
            accelerator::Accelerator::from_str(o).ok_or_else(|| {
                anyhow::anyhow!(
                    "invalid --accelerator-override '{o}'. Expected: cuda | metal | openvino | cpu"
                )
            })?;
            state.inference.accelerator_override = Some(o.to_string());
        }
        if let Some(e) = args.embedding_provider.as_deref() {
            let parsed = InferenceProvider::from_str(e).ok_or_else(|| {
                anyhow::anyhow!(
                    "invalid --embedding-provider '{e}'. Expected: local_qwen | openai_api | anthropic_api | gemini_api"
                )
            })?;
            state.inference.embedding_provider = Some(parsed);
        }
        // E-2 Phase 4 (Session 14 Pick #23) — non-interactive depth
        // override. Clamp + stderr warning instead of the interactive
        // confirm screen (no TTY to draw it on).
        if let Some(raw) = args.council_depth {
            let (depth, clamped) =
                crate::config::inference::HemisphereCouncilDepth::new_clamped(raw);
            state.inference.hemisphere_council_depth = depth;
            if depth.get() > 1 {
                eprintln!(
                    "[neoth init] {}",
                    render_council_depth_cost_warning(depth.get()),
                );
            }
            if clamped {
                eprintln!(
                    "[neoth init] --council-depth={} exceeds MAX_HEMISPHERE_COUNCIL_DEPTH={}; clamped",
                    raw,
                    crate::config::inference::MAX_HEMISPHERE_COUNCIL_DEPTH,
                );
            }
        }
        state.steps_completed.push(WizardStep::Topology as u8); // marker for step 5b (kept separate)
        return Ok(());
    }

    #[cfg(feature = "wizard")]
    {
        // ─── 1. Topology mode ──────────────────────────────────────────
        // Finding 6 (Session 13) — Topology preset table with a new
        // `local-only` privacy-positive option that hard-binds all
        // three hemispheres to LocalQwen on operator hardware. Default
        // moves to `local-only` when an accelerator (CUDA / Metal /
        // OpenVino) is detected; on CPU-only systems the default stays
        // at `single` because CPU Qwen is too slow for daily-use Council
        // mode.
        let gpu_detected = probe.picked != accelerator::Accelerator::Cpu;
        let local_only_hint = if gpu_detected {
            "all 3 hemispheres = LocalQwen on operator hardware (RECOMMENDED — zero cloud exposure)"
        } else {
            "all 3 hemispheres = LocalQwen (CPU — slower; prefer `single` without a GPU)"
        };
        let single_hint = if gpu_detected {
            "one provider for everything (cloud or local)"
        } else {
            "one provider for everything (recommended)"
        };
        // GOLD-ADOPT-12 — multi-local preset: run up to 3 QUANTIZED abliterated
        // GGUFs (one per hemisphere) on the operator's own hardware via Ollama.
        let local_multi_hint = if gpu_detected {
            // GR-098 — the preset uses curated_or_nearest (verified repos sized to
            // VRAM), NOT a live "newest/best" lookup; say what it actually does.
            "1–3 local abliterated Q4/Q8 models across the hemispheres (Ollama — curated repos, VRAM-sized)"
        } else {
            "1–3 small local abliterated models (CPU — slow; prefer cloud without a GPU)"
        };
        // Topology preset table. `local-only` is a virtual preset — the
        // wizard expands it to Triplet mode + LocalQwen slots below so
        // freedom.yaml round-trips through the existing TopologyMode
        // enum without a new wire-format variant.
        let modes: [(TopologyMode, &str, String); 5] = [
            (TopologyMode::Single, "single", single_hint.to_string()),
            (
                TopologyMode::Triplet,
                "triplet",
                "same provider on all 3 hemispheres, separate keys/models allowed".to_string(),
            ),
            (
                TopologyMode::Custom,
                "custom",
                "fully custom — different provider per hemisphere".to_string(),
            ),
            (
                // local-only expands to Triplet mode at apply time.
                TopologyMode::Triplet,
                "local-only",
                local_only_hint.to_string(),
            ),
            (
                // local-multi expands to Triplet (all-local) or Custom (mixed)
                // at apply time; the real slots are set by the preset below.
                TopologyMode::Triplet,
                "local-multi",
                local_multi_hint.to_string(),
            ),
        ];
        let labels: Vec<String> = modes
            .iter()
            .map(|(_, n, hint)| format!("{n:<10}  {hint}"))
            .collect();
        let default_idx = topology_default_idx_for_probe(&probe);
        let pick = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("[5b/9] Hemisphere LLM topology")
            .items(&labels)
            .default(default_idx)
            .interact()
            .context("topology mode select")?;
        state.inference.mode = modes[pick].0;
        let is_local_only_preset = matches!(modes[pick].1, "local-only");
        println!("  [5b/9] mode: {}", modes[pick].1);
        // GOLD-HON-11 — explicit single-provider confirmation. `Single`
        // means ONE provider answers every turn: no council cross-check,
        // no hemisphere diversity, and that provider sees every prompt.
        // Surface the trade-off so it's a deliberate choice, not a silent
        // default. (The same label + note is shown by `neoth hemispheres
        // show`.)
        if matches!(state.inference.mode, TopologyMode::Single) {
            println!(
                "      → single-provider setup confirmed: one provider handles every \
                 turn — no council cross-check or hemisphere diversity, and that provider \
                 sees all prompts. Switch later with `neoth init` or `neoth hemispheres set`."
            );
        }
        // Apply the local-only preset BEFORE the per-hemisphere loop —
        // the loop's gate on `Triplet|Custom` would otherwise overwrite
        // these with the per-role prompts.
        if is_local_only_preset {
            apply_local_only_preset(&mut state.inference);
            println!("  [5b/9] hemispheres (local-only preset):");
            println!("      left        provider=local_qwen  model=(adapter default)");
            println!("      right       provider=local_qwen  model=(adapter default)");
            println!("      cerebellum  provider=local_qwen  model=(adapter default)");
        }
        // GOLD-ADOPT-12 — multi-local abliterated preset: VRAM-size the local
        // model(s), let the operator choose how many hemispheres run local, bind
        // them to Ollama, and print the `ollama pull` commands. Same early-apply
        // ordering as local-only (before the per-role loop's Triplet|Custom gate).
        let is_local_multi_preset = matches!(modes[pick].1, "local-multi");
        if is_local_multi_preset {
            apply_local_multi_preset_interactive(&mut state.inference)?;
        }

        // ─── 2. Accelerator (only matters when local_qwen is in play) ──
        let accel_options = [
            accelerator::Accelerator::Cpu,
            accelerator::Accelerator::Cuda,
            accelerator::Accelerator::Metal,
            accelerator::Accelerator::OpenVino,
        ];
        // Build a "(detected: X)" hint so the operator sees what auto-detect
        // picked and which alternatives compile.
        let accel_labels: Vec<String> = accel_options
            .iter()
            .map(|a| {
                let marker = if *a == probe.picked {
                    " (detected)"
                } else {
                    ""
                };
                format!("{:<9}{marker}  {}", a.as_str(), a.description())
            })
            .collect();
        let default_idx = accel_options
            .iter()
            .position(|a| *a == probe.picked)
            .unwrap_or(0);
        // NOOB-UX gate: Beginner-level operators don't see the
        // manual accelerator pick — auto-detection is almost always
        // right, and surfacing the choice scares non-developers
        // (see Session 26 UX review for the screenshot that flagged this).
        // Intermediate + Advanced still get the prompt with the
        // detected pick pre-selected as default.
        let chosen_accel = if matches!(
            state.experience_level,
            crate::wizard::recommend::ExperienceLevel::Beginner
        ) {
            println!(
                "  [5b/9] accelerator: {} (auto-detected, hidden in beginner mode)",
                probe.picked.as_str()
            );
            probe.picked
        } else {
            let accel_pick =
                dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
                    .with_prompt("    accelerator (used by local_qwen forward pass)")
                    .items(&accel_labels)
                    .default(default_idx)
                    .interact()
                    .context("accelerator select")?;
            accel_options[accel_pick]
        };
        // Only record an override when the operator picked something OTHER
        // than the detected default — auto-detection is preferred so portable
        // freedom.yaml files survive moving between hosts.
        state.inference.accelerator_override = if chosen_accel == probe.picked {
            None
        } else {
            Some(chosen_accel.as_str().to_string())
        };
        // Beginner-mode already printed the "auto-detected" line above;
        // re-print only for Intermediate/Advanced who actually picked.
        if !matches!(
            state.experience_level,
            crate::wizard::recommend::ExperienceLevel::Beginner
        ) {
            println!("  [5b/9] accelerator: {}", chosen_accel.as_str());
        }

        // ─── 3. Per-hemisphere providers (only Triplet + Custom) ───────
        // SPEC_hemisphere_provider_selection.md §3: surface a recommended
        // provider per role (claude_cli/gemini/local_qwen) without
        // enforcing it. Custom mode additionally asks for a per-role
        // model so left=opus-4-7 + right=gemini-3.1-pro + cerebellum=Qwen3
        // can coexist without further CLI edits.
        if !is_local_only_preset
            && !is_local_multi_preset
            && matches!(
                state.inference.mode,
                TopologyMode::Triplet | TopologyMode::Custom
            )
        {
            let is_custom = matches!(state.inference.mode, TopologyMode::Custom);
            for role in ["left", "right", "cerebellum"] {
                let recommended = recommended_provider_for_role(role);
                let chosen = prompt_inference_provider(
                    &format!(
                        "    {role} hemisphere provider (recommended: {})",
                        recommended.as_str()
                    ),
                    Some(recommended),
                )?;
                // In Triplet mode model/key/endpoint inherit from default so
                // the operator isn't asked 3× for the same value. In Custom
                // mode prompt for the model — the most common reason to
                // pick per-role providers in the first place.
                let model = if is_custom {
                    prompt_hemisphere_model(role, chosen, &state.inference.default_slot.model)?
                } else {
                    state.inference.default_slot.model.clone()
                };
                let slot = HemisphereSlot {
                    provider: Some(chosen),
                    model,
                    key: state.inference.default_slot.key.clone(),
                    endpoint: state.inference.default_slot.endpoint.clone(),
                    region: state.inference.default_slot.region.clone(),
                    api_version: state.inference.default_slot.api_version.clone(),
                    // GOLD-WIRE-04: mirror the default slot's voice onto each
                    // per-role slot so a wizard-set voice survives role split.
                    voice: state.inference.default_slot.voice,
                };
                match role {
                    "left" => state.inference.left = slot,
                    "right" => state.inference.right = slot,
                    "cerebellum" => state.inference.cerebellum = slot,
                    _ => {}
                }
            }
            // Render summary so the operator confirms what they just
            // bound. Matches `neoth hemispheres show` table format.
            println!("  [5b/9] hemispheres:");
            for (label, slot) in [
                ("left      ", &state.inference.left),
                ("right     ", &state.inference.right),
                ("cerebellum", &state.inference.cerebellum),
            ] {
                let prov = slot
                    .provider
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_else(|| "(default)".into());
                let model = slot.model.as_deref().unwrap_or("(default)");
                println!("      {label}  provider={prov}  model={model}");
            }
        }

        // ─── 4. Embedding provider (independent of chat) ───────────────
        // NOOB-UX gate: Beginner skips. Embedding provider is an
        // optional speed-up for the skill router + ctx-mode re-rank;
        // operators who don't know what either of those is get a
        // sensible no-op default.
        if !matches!(
            state.experience_level,
            crate::wizard::recommend::ExperienceLevel::Beginner
        ) {
            let want_emb = dialoguer::Confirm::with_theme(
                &dialoguer::theme::ColorfulTheme::default(),
            )
            .with_prompt(
                "    configure an embedding provider (used by skill router + ctx-mode re-rank)?",
            )
            .default(false)
            .interact()
            .context("embedding-yes/no confirm")?;
            if want_emb {
                let emb = prompt_inference_provider(
                    "    embedding provider",
                    Some(InferenceProvider::LocalQwen),
                )?;
                state.inference.embedding_provider = Some(emb);
                println!("  [5b/9] embeddings via {}", emb.as_str());
            }
        }

        // ─── E-2 Phase 4 (Session 14 Pick #23) — Council recursion depth
        //     + one-screen cost warning. Wizard never asked about this
        //     before; operators only saw depth>1 if they hand-edited
        //     freedom.yaml, which silently produced 3^depth leaf calls
        //     per message. Now they pick it explicitly with the math
        //     spelled out + a confirm that defaults to "no".
        let depth_choice = if let Some(raw) = args.council_depth {
            // Operator passed --council-depth on the CLI even though
            // we're in the interactive path. Honour it without re-asking.
            let (d, _) = crate::config::inference::HemisphereCouncilDepth::new_clamped(raw);
            d.get()
        } else if matches!(
            state.experience_level,
            crate::wizard::recommend::ExperienceLevel::Beginner
        ) {
            // NOOB-UX gate: Beginner gets the safe flat default
            // silently. Depth>1 is a 3^N cost multiplier — surfacing
            // it to non-developers risks accidental 81-leaf-call
            // councils that burn provider quota.
            1u8
        } else {
            let raw: u8 = dialoguer::Input::with_theme(
                &dialoguer::theme::ColorfulTheme::default(),
            )
            .with_prompt(
                "[5b/9] Council recursion depth (1=flat default, 2..=4 enables fractal sub-councils)",
            )
            .default(1u8)
            .validate_with(|v: &u8| {
                if *v <= crate::config::inference::MAX_HEMISPHERE_COUNCIL_DEPTH {
                    Ok(())
                } else {
                    Err(format!(
                        "must be 0..={}",
                        crate::config::inference::MAX_HEMISPHERE_COUNCIL_DEPTH,
                    ))
                }
            })
            .interact_text()
            .context("council depth input")?;
            raw
        };
        let depth_choice = if depth_choice > 1 {
            // One-screen cost warning + confirm — default no, so a
            // distracted Enter-spammer doesn't accidentally opt in to
            // 81 leaf calls per message.
            println!("{}", render_council_depth_cost_warning(depth_choice));
            let proceed =
                dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
                    .with_prompt(format!(
                        "[5b/9] Proceed with hemisphere_council_depth={depth_choice}?"
                    ))
                    .default(false)
                    .interact()
                    .context("council depth confirm")?;
            if proceed {
                depth_choice
            } else {
                println!("  [5b/9] reverted to depth=1 (flat council)");
                1
            }
        } else {
            depth_choice
        };
        let (clamped_depth, was_clamped) =
            crate::config::inference::HemisphereCouncilDepth::new_clamped(depth_choice);
        state.inference.hemisphere_council_depth = clamped_depth;
        if was_clamped {
            println!(
                "  [5b/9] depth clamped to MAX_HEMISPHERE_COUNCIL_DEPTH={}",
                crate::config::inference::MAX_HEMISPHERE_COUNCIL_DEPTH,
            );
        }
        println!("  [5b/9] hemisphere_council_depth: {}", clamped_depth.get(),);
    }
    #[cfg(not(feature = "wizard"))]
    {
        // No dialoguer build → leave defaults from non-interactive path.
    }

    state.steps_completed.push(WizardStep::Topology as u8);
    Ok(())
}

/// GOLD-ADOPT-13 — wizard step 5b₂: provision the Ollama runtime for any
/// local-multi hemispheres. Offers to install Ollama (if absent) and pull each
/// model. Non-interactive just prints the commands (no surprise multi-GB network
/// pulls in CI / scripted installs). No-op when no Ollama models are configured.
pub(crate) async fn step5b2_ollama_provision(
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
    let refs = collect_ollama_model_refs(&state.inference);
    if refs.is_empty() {
        return Ok(());
    }

    if !interactive {
        for r in &refs {
            println!(
                "[neoth init] local model configured — run: {}",
                crate::installers::ollama::pull_command(r).join(" ")
            );
        }
        return Ok(());
    }

    #[cfg(feature = "wizard")]
    {
        use crate::cli::device_profile::{detect_device_profile, recommend_tier, LocalAiTier};
        use crate::installers::ollama;

        // OH-04 tier gate — suppress the Ollama install offer on machines where
        // RAM <8 GB and no GPU is detected (CloudFirst tier). Hybrid (8–15 GB,
        // no GPU) still gets the offer: small quantized models are viable at 8 GB.
        let profile = detect_device_profile();
        let tier = recommend_tier(profile.total_ram_gb, profile.gpu_present);
        if matches!(tier, LocalAiTier::CloudFirst) {
            println!(
                "  [OH-04] RAM {:.1} GB, no GPU detected — local Ollama install skipped (cloud-first tier).",
                profile.total_ram_gb
            );
            println!(
                "    Switch a hemisphere to a cloud provider, or re-run `neoth init` on a machine \
                 with ≥8 GB RAM (Hybrid) or a GPU (LocalCapable) to enable local models."
            );
            return Ok(());
        }

        println!("\n[5b/9] Ollama runtime — serves your local abliterated model(s).");

        // Install Ollama if it isn't already reachable (multi-path probe).
        if ollama::check_ollama_available().await.is_none() {
            let install =
                dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
                    .with_prompt(format!(
                        // GR-086 — show the ACTUAL command (e.g. `curl … | sh`), not
                        // the terse `upstream_script` tag, so consent is informed.
                        "Ollama not found. Install it now? This runs:  {}",
                        ollama::InstallPath::for_host().display_command()
                    ))
                    .default(true)
                    .interact()
                    .context("ollama install confirm")?;
            if install {
                match ollama::install_for_host().await {
                    Ok(()) => {
                        println!("  ✓ Ollama installed");
                        // OH-05 — post-install binary probe: /CURRENTUSER puts the
                        // binary in %LOCALAPPDATA%\Programs\Ollama\ which is NOT on PATH
                        // until the next shell restart. Locate it explicitly so the pull
                        // calls below work in the same wizard session.
                        match ollama::find_ollama_binary() {
                            Some(ref p) => println!("  ✓ binary located: {}", p.display()),
                            None => println!(
                                "  ! binary not found on known paths after install — \
                                 restart your shell then run pulls manually."
                            ),
                        }
                    }
                    Err(e) => println!(
                        "  ! Ollama install failed: {e}\n    Install manually from {} then re-run the pulls below.",
                        ollama::OLLAMA_DOWNLOAD_URL
                    ),
                }
            } else {
                println!("  → skipped Ollama install. Pull commands are printed below.");
            }
        } else {
            // Already installed — still log the resolved path for operator visibility.
            if let Some(ref p) = ollama::find_ollama_binary() {
                println!("  ✓ Ollama already installed ({})", p.display());
            } else {
                println!("  ✓ Ollama already installed");
            }
        }

        // Offer to pull each configured model.
        let pull = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt(format!(
                "Pull the {} local model(s) now (multi-GB download)?",
                refs.len()
            ))
            .default(true)
            .interact()
            .context("ollama pull confirm")?;
        for r in &refs {
            let cmd = ollama::pull_command(r);
            if pull {
                println!("  ⏬ {}", cmd.join(" "));
                // OH-05 — use find_ollama_binary() for the pull so that a
                // /CURRENTUSER fresh-install binary (not yet on PATH) is used
                // directly rather than failing with "ollama: command not found".
                let pull_result = match ollama::find_ollama_binary() {
                    Some(bin) => {
                        // pull_command returns ["ollama", "pull", "<ref>"] —
                        // drop the first token (binary name) and pass the rest.
                        let rest: Vec<String> = cmd[1..].to_vec();
                        ollama::run_command_at(&bin, &rest).await
                    }
                    None => ollama::run_command(&cmd).await,
                };
                if let Err(e) = pull_result {
                    println!("  ! pull failed: {e} (re-run `{}` later)", cmd.join(" "));
                }
            } else {
                println!("  later: $ {}", cmd.join(" "));
            }
        }
    }
    Ok(())
}

/// Step 5e — GOLD-ADAPT-CBM-02: offer the OPTIONAL codebase-memory-mcp
/// code-intelligence rail (indexes repos into a knowledge-graph MCP server).
/// Default NO — a third-party-binary install is opt-in. On accept: show the
/// full consent text, run the platform installer, then print the
/// mcp_servers.yaml registration hint (NEOTH never guesses the serve
/// invocation — the operator wires it from CBM's README). Non-interactive
/// (or with the `wizard` feature off): print the install command + skip; never
/// auto-install a third-party binary without an interactive confirm.
pub(crate) async fn step5e_cbm_offer(interactive: bool) -> Result<()> {
    use crate::installers::cbm;
    if !interactive {
        println!(
            "[neoth init] optional code-intelligence rail (codebase-memory-mcp) — install later with:  {}",
            cbm::InstallPath::for_host().display_command()
        );
        return Ok(());
    }
    #[cfg(feature = "wizard")]
    {
        println!(
            "\n[5e/9] Code-intelligence rail (optional) — codebase-memory-mcp indexes your repos \
             into a knowledge-graph MCP server."
        );
        let want = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt(format!(
                "Install the optional codebase-memory-mcp now? This runs:  {}",
                cbm::InstallPath::for_host().display_command()
            ))
            .default(false)
            .interact()
            .context("cbm install offer")?;
        if !want {
            println!(
                "  → skipped (install later: {} )",
                cbm::InstallPath::for_host().display_command()
            );
            return Ok(());
        }
        // Informed consent: the full third-party-binary disclosure before running.
        println!("\n{}", cbm::InstallPath::for_host().consent_text());
        let confirm = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("Proceed with the install?")
            .default(false)
            .interact()
            .context("cbm consent confirm")?;
        if !confirm {
            println!("  → skipped.");
            return Ok(());
        }
        match cbm::install_for_host().await {
            Ok(()) => {
                println!("  ✓ codebase-memory-mcp installed");
                // GOLD-ADAPT-CBM-02 — verify the binary is on PATH, then auto-register
                // its hardened MCP-server entry so the operator doesn't have to hand-edit
                // mcp_servers.yaml. Idempotent + best-effort (a failure falls back to the
                // manual hint).
                match cbm::auto_register() {
                    Ok(true) => println!(
                        "  ✓ registered + enabled `codebase-memory` in ~/.neoth/mcp_servers.yaml"
                    ),
                    Ok(false) => println!(
                        "  → not on PATH yet — restart your shell then run `neoth doctor`, or add \
                         the stdio entry manually (see {})",
                        cbm::CBM_DOWNLOAD_URL
                    ),
                    Err(e) => println!(
                        "  ! auto-register failed: {e}\n    Add the stdio entry manually (see {}).",
                        cbm::CBM_DOWNLOAD_URL
                    ),
                }
            }
            Err(e) => println!(
                "  ! install failed: {e}\n    Install manually from {} then register it in \
                 mcp_servers.yaml.",
                cbm::CBM_DOWNLOAD_URL
            ),
        }
    }
    Ok(())
}

/// Step 6i — GOLD-ADAPT-TUDU-01: optional tududi self-hosted task manager MCP rail.
///
/// tududi is a self-hosted Node.js task manager
/// (<https://github.com/chrisvel/tududi>). Its MCP server exposes 8 task tools
/// (`list_tasks`, `get_task`, `create_task`, `update_task`, `complete_task`,
/// `delete_task`, `add_subtask`, `get_task_metrics`) over a stdio
/// `StdioServerTransport` — the same JSON-RPC 2.0 framing NEOTH already uses
/// for all MCP servers. The wizard collects the absolute path to
/// `backend/modules/mcp/server.js` inside the operator's tududi installation
/// and the API token, then calls [`crate::installers::tududi::auto_register`].
///
/// Non-interactive: print a registration hint and skip. The wizard step is
/// an offer — no unattended install of a third-party service.
pub(crate) async fn step6i_tududi_offer(interactive: bool) -> Result<()> {
    use crate::installers::tududi;
    if !interactive {
        println!(
            "[neoth init] optional tududi task-manager MCP rail — skip for now. \
             To register later, run `neoth mcp register --id tududi` or re-run \
             `neoth init --force`. See https://github.com/chrisvel/tududi"
        );
        return Ok(());
    }
    #[cfg(feature = "wizard")]
    {
        println!(
            "\n[6i/9] tududi task-manager MCP rail (optional) — exposes 8 task tools \
             (list/get/create/update/complete/delete/subtask/metrics) from your \
             self-hosted tududi instance."
        );
        let want = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt(
                "Do you self-host tududi and want to register its MCP server now?",
            )
            .default(false)
            .interact()
            .context("tududi offer confirm")?;
        if !want {
            println!(
                "  → skipped (register later: https://github.com/chrisvel/tududi)"
            );
            return Ok(());
        }

        // Collect the absolute path to server.js.
        println!(
            "  Enter the absolute path to tududi's MCP server script.\n  \
             Example: /home/op/tududi/backend/modules/mcp/server.js"
        );
        let server_js: String = dialoguer::Input::with_theme(
            &dialoguer::theme::ColorfulTheme::default(),
        )
        .with_prompt("Path to server.js")
        .validate_with(|s: &String| {
            if s.trim().is_empty() {
                Err("path cannot be empty")
            } else {
                Ok(())
            }
        })
        .interact_text()
        .context("tududi server.js path input")?;
        let server_js = server_js.trim().to_string();

        // Validate the file exists before asking for the token.
        if !tududi::is_server_file_present(&server_js) {
            println!(
                "  ! `{server_js}` is not a regular file.\n  \
                 Skipping registration — check the path and re-run `neoth init --force` \
                 or `neoth mcp register --id tududi` to register manually."
            );
            return Ok(());
        }

        // Collect the API token (masked input).
        let api_token: String = dialoguer::Password::with_theme(
            &dialoguer::theme::ColorfulTheme::default(),
        )
        .with_prompt("tududi API token")
        .validate_with(|s: &String| {
            if s.trim().is_empty() {
                Err("API token cannot be empty")
            } else {
                Ok(())
            }
        })
        .interact()
        .context("tududi API token input")?;
        let api_token = api_token.trim().to_string();

        let neoth_home = crate::cli::init::dirs_home().join(".neoth");
        match tududi::auto_register(&server_js, &api_token, &neoth_home) {
            Ok(true) => {
                println!(
                    "  ✓ tududi registered + enabled in ~/.neoth/mcp_servers.yaml\n  \
                     ✓ API token written to ~/.neoth/credentials.yaml (mode 0600)\n  \
                     → Start NEOTH and try: \"list my tasks\""
                );
            }
            Ok(false) => {
                // Should not be reachable (we already checked is_server_file_present),
                // but guard defensively.
                println!(
                    "  ! server.js not found at `{server_js}` — registration skipped.\n  \
                     Verify the path and re-run the wizard."
                );
            }
            Err(e) => {
                println!(
                    "  ! registration failed: {e}\n  \
                     Add the entry manually (see https://github.com/chrisvel/tududi)."
                );
            }
        }
    }
    Ok(())
}

/// Step 6j — GOLD-ADAPT-SYS-01: optional mobile-mcp iOS/Android device control rail.
///
/// mobile-mcp (`@mobilenext/mobile-mcp`) is an MCP server that drives real iOS
/// and Android devices (and iOS Simulator) via WebDriverAgent + ADB. It exposes
/// 24 local-device tools (`mobile_take_screenshot`, `mobile_click`,
/// `mobile_type_text`, etc.) and is launched via `npx -y @mobilenext/mobile-mcp@latest`
/// — no global install step required.
///
/// Prerequisites (NEOTH cannot install these; operator-supplied):
/// - Node ≥ 18 + npx on PATH.
/// - iOS real device: Xcode CLI tools + WebDriverAgent signed with a valid Apple
///   Developer account. iOS Simulator requires no WDA signing.
/// - Android: `adb` in PATH and USB debugging enabled on the target device.
///
/// Telemetry disclosure: mobile-mcp fires PostHog events unless
/// `MOBILEMCP_DISABLE_TELEMETRY=1` is set. NEOTH forces this off automatically
/// in the subprocess environment — the operator is informed before opting in.
///
/// Non-interactive: print a registration hint and skip. Device prerequisites
/// require human setup; no unattended install is performed.
pub(crate) async fn step6j_mobile_mcp_offer(interactive: bool) -> Result<()> {
    use crate::installers::mobile_mcp;
    if !interactive {
        println!(
            "[neoth init] optional mobile-mcp iOS/Android device control rail — skip for now. \
             Prerequisites: Node ≥18 on PATH + Xcode/ADB for real devices. \
             Re-run `neoth init --force` after installing Node, or add the entry manually \
             to ~/.neoth/mcp_servers.yaml. See https://github.com/mobile-next/mobile-mcp"
        );
        return Ok(());
    }
    #[cfg(feature = "wizard")]
    {
        println!(
            "\n[6j/9] mobile-mcp iOS/Android device control rail (optional) — drives real \
             devices and simulators via WebDriverAgent (iOS) + ADB (Android). Exposes 24 \
             local-device tools (screenshot, tap, swipe, type, app control, …).\n\
             \n\
             Prerequisites:\n\
               • Node ≥18 + npx on PATH (mobile-mcp is launched via npx; no global install)\n\
               • iOS real device: Xcode CLI tools + WebDriverAgent installed + Apple Developer \
             account for WDA signing. iOS Simulator works without WDA signing.\n\
               • Android: `adb` in PATH + USB debugging enabled on the target device.\n\
             \n\
             Telemetry note: mobile-mcp sends anonymous usage events to PostHog. \
             NEOTH disables this automatically by setting \
             MOBILEMCP_DISABLE_TELEMETRY=1 in the subprocess environment.\n\
             \n\
             Security note: Elevated autonomy floor (same as chrome-devtools-mcp) — \
             mobile device control is inert on Strict/Standard operators. The 3 cloud \
             remote-device allocation tools are excluded from the default allowlist."
        );
        let want = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt(
                "Register mobile-mcp now? (requires Node ≥18 + device prerequisites above)",
            )
            .default(false)
            .interact()
            .context("mobile-mcp offer confirm")?;
        if !want {
            println!(
                "  → skipped (register later: https://github.com/mobile-next/mobile-mcp)"
            );
            return Ok(());
        }

        let neoth_home = crate::cli::init::dirs_home().join(".neoth");
        match mobile_mcp::auto_register(&neoth_home).await {
            Ok(true) => {
                println!(
                    "  ✓ mobile-mcp registered + enabled in ~/.neoth/mcp_servers.yaml\n  \
                     ✓ MOBILEMCP_DISABLE_TELEMETRY=1 forced in subprocess env (PostHog off)\n  \
                     → Autonomy floor: Elevated (inert on Strict/Standard)\n  \
                     → Start NEOTH and try: \"tap the login button on my phone\""
                );
            }
            Ok(false) => {
                println!(
                    "  ! Node/npx not found on PATH — install Node first:\n  \
                     \n  \
                     Windows: https://nodejs.org/en/download  (use the LTS installer)\n  \
                     macOS:   brew install node\n  \
                     Linux:   sudo apt install nodejs npm\n  \
                     \n  \
                     Then re-run: neoth init --force"
                );
            }
            Err(e) => {
                println!(
                    "  ! registration failed: {e}\n  \
                     Add the entry manually to ~/.neoth/mcp_servers.yaml \
                     (see https://github.com/mobile-next/mobile-mcp)."
                );
            }
        }
    }
    Ok(())
}

/// Step 5c — NOOB-UX-6 (Workstream B): Qwen weights pre-download.
///
/// Only meaningful when the operator's inference topology pulls in
/// `LocalQwen` somewhere (default_slot or any hemisphere or the
/// embedding provider). The probe is sync + ~1ms (file_exists); when
/// weights are already cached the step is a no-op log line.
///
/// GOLD-ADOPT-10 — this step deliberately pre-downloads the FIXED
/// [`qwen_weights::DEFAULT_QWEN_MODEL_ID`] (Qwen2.5-3B), the single curated
/// candle weight + the always-available lightweight `LocalQwen` baseline. It is
/// VRAM-INDEPENDENT by design: VRAM-aware local-model sizing is a SEPARATE path
/// — the Ollama multi-local preset (`models::hemisphere_preset::build_local_preset`
/// → `selector::quantized_shortlist(vram)` → `gguf_variants::curated_or_nearest`),
/// which scales the GGUF size to the detected VRAM. `recommended_model_tier()`
/// feeds the operator-facing recommendation (`wizard::recommend`), not this
/// candle pre-download.
///
/// Non-interactive: honours `--download-qwen-weights`. With the flag
/// the step records the intent + surfaces the `huggingface-cli` line
/// the operator runs. Without the flag the step is a silent no-op
/// for hosts that don't touch LocalQwen.
pub(crate) async fn step5c_qwen_weights(
    args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
    use crate::installers::qwen_weights;

    debug!("wizard step 5c: qwen weights");

    if !inference_uses_local_qwen(&state.inference, &state.provider_kind) {
        // Operator picked cloud-only — no LocalQwen path = nothing to
        // pre-download. Mark step run + return.
        state.steps_completed.push(WizardStep::QwenWeights as u8);
        return Ok(());
    }

    let cached = qwen_weights::check_weights_cached(qwen_weights::DEFAULT_QWEN_MODEL_ID);

    if !interactive {
        let opted_in = args.download_qwen_weights;
        let action = qwen_weights::recommend_action(cached, opted_in);
        match action {
            qwen_weights::WeightsAction::AlreadyCached => {
                info!(
                    model = qwen_weights::DEFAULT_QWEN_MODEL_ID,
                    "qwen weights cached"
                );
            }
            qwen_weights::WeightsAction::DownloadNeeded => {
                state.download_qwen_weights = true;
                let cmd =
                    qwen_weights::weights_download_command(qwen_weights::DEFAULT_QWEN_MODEL_ID);
                info!(
                    cmd = %cmd.join(" "),
                    gb = qwen_weights::DEFAULT_QWEN_DOWNLOAD_GB,
                    "operator opted into Qwen weights pre-download"
                );
            }
            qwen_weights::WeightsAction::OperatorSkipped => {
                warn!(
                    model = qwen_weights::DEFAULT_QWEN_MODEL_ID,
                    "LocalQwen configured but weights not cached + operator did not pass --download-qwen-weights; \
                     first chat will lazy-download"
                );
            }
        }
        state.steps_completed.push(WizardStep::QwenWeights as u8);
        return Ok(());
    }

    #[cfg(feature = "wizard")]
    {
        println!();
        if cached {
            println!("[5c/9] Qwen weights already cached (~/.cache/huggingface/hub/). Skipping.");
            state.steps_completed.push(WizardStep::QwenWeights as u8);
            return Ok(());
        }
        // NOOB-UX gate: Beginner skips the pre-download prompt. The
        // jargon ("Pre-download", "lazy-download", `huggingface-cli`)
        // scares non-developers and the safe default (lazy-fetch on
        // first chat with operator-visible progress) is already the
        // right answer for the "non-technical operator" cliff. Intermediate and
        // Advanced still see the prompt + the download recipe.
        if matches!(
            state.experience_level,
            crate::wizard::recommend::ExperienceLevel::Beginner
        ) {
            println!(
                "[5c/9] Qwen weights will download automatically on your first chat (~{} GB, progress shown).",
                qwen_weights::DEFAULT_QWEN_DOWNLOAD_GB,
            );
            state.steps_completed.push(WizardStep::QwenWeights as u8);
            return Ok(());
        }
        println!(
            "[5c/9] LocalQwen is wired but the {} weights aren't cached yet (~{} GB download).",
            qwen_weights::DEFAULT_QWEN_MODEL_ID,
            qwen_weights::DEFAULT_QWEN_DOWNLOAD_GB,
        );
        let opt_in = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("Pre-download the Qwen weights now? (skip = lazy-download on first chat)")
            .default(false)
            .interact()
            .context("qwen weights opt-in")?;
        if !opt_in {
            println!(
                "  Skipped — weights will lazy-download on first chat (operator-visible progress)."
            );
            state.steps_completed.push(WizardStep::QwenWeights as u8);
            return Ok(());
        }
        state.download_qwen_weights = true;
        let cmd = qwen_weights::weights_download_command(qwen_weights::DEFAULT_QWEN_MODEL_ID);
        println!();
        println!("  To download the weights, run:");
        println!("      $ {}", cmd.join(" "));
        println!(
            "  (`huggingface-cli` ships with the `huggingface_hub` pip package; \
             `pip install -U huggingface_hub` if missing.)"
        );
    }

    state.steps_completed.push(WizardStep::QwenWeights as u8);
    Ok(())
}

/// ADV-03 item 4 Phase 7 (Session 24): operator-awareness step for
/// the profile-claim approval gate. The actual persistence happens
/// via serde default on `ProfileConfig::require_approval` (true on
/// fresh installs + missing-field migrations) AND via the
/// `neoth profile migrate-require-approval [--disable]` CLI — this
/// step exists so fresh-install operators KNOW the gate is on
/// before their first chat triggers a profile extraction.
///
/// Non-interactive: silent no-op (the marker still records the step
/// completed for the audit trail).
///
/// Interactive: print a 3-line summary + the disable command, then
/// continue. No prompt — operator can opt out later via
/// `neoth profile migrate-require-approval --disable` if they
/// genuinely want auto-apply.
pub(crate) fn step5d_profile_approval_gate(
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
    debug!("wizard step 5d: profile approval gate awareness");
    if interactive {
        println!();
        // NOOB-UX gate: Beginner gets a 1-line plain-English summary.
        // The 6-line technical version ("prompt-injection attacks",
        // "multi-turn slow-poison chains", "daemon mode no tty",
        // `neoth profile pending`) is jargon dense — Intermediate +
        // Advanced still see it so they know the disable command.
        if matches!(
            state.experience_level,
            crate::wizard::recommend::ExperienceLevel::Beginner
        ) {
            println!(
                "[5d/9] NEOTH will ask before saving facts about you (e.g. 'you live in Berlin')."
            );
        } else {
            println!("[5d/9] Profile-claim approval gate is ON by default.");
            println!(
                "  When NEOTH extracts a profile claim ('you live in Berlin', \
                 'your editor is vim'),"
            );
            println!(
                "  it asks you to confirm before writing — protects against \
                 prompt-injection attacks"
            );
            println!("  via channel inbound + multi-turn slow-poison chains.");
            println!(
                "  Daemon mode (no tty) parks pending claims in \
                 `neoth profile pending` for review."
            );
            println!("  Opt out anytime with: `neoth profile migrate-require-approval --disable`");
        }
    }
    state.steps_completed.push(WizardStep::ProfileGate as u8);
    Ok(())
}

/// Step 6k — GOLD-ADAPT-ODY-24: companion LAN pairing offer.
///
/// Detects the operative LAN IP via a UDP-connect probe (no packet sent),
/// renders a QR code to stdout, and prompts the operator to enable the
/// companion server in freedom.yaml. On acceptance, sets
/// `state.companion.enabled = true` (port defaults to 9745) so
/// `write_config` serialises `companion.enabled: true` into freedom.yaml.
///
/// Non-interactive: prints a skip notice and returns.
/// Interactive (wizard feature): shows QR + Confirm prompt.
///
/// The QR payload is `http://<LAN-IP>:9745/pair` — the companion app
/// scans this and immediately calls `POST /api/v1/companion/pair` with a
/// `session_id` to mint a bearer token.
pub(crate) async fn step6k_companion_pairing_offer(
    interactive: bool,
    state: &mut crate::cli::init::types::WizardState,
) -> Result<()> {
    if !interactive {
        println!(
            "[neoth init] optional companion LAN pairing — skip for now. \
             Enable later by setting `companion.enabled: true` in ~/.neoth/freedom.yaml \
             (port: 9745). The companion app scans a QR code to mint a bearer token."
        );
        return Ok(());
    }

    #[cfg(feature = "wizard")]
    {
        use crate::daemon::companion::{detect_lan_ip, render_pairing_qr};

        // Detect LAN IP. Falls back to 127.0.0.1 when offline/VPN.
        let lan_ip = detect_lan_ip().await;
        let pairing_url = format!("http://{}:{}/pair", lan_ip, state.companion.port);

        println!(
            "\n[6k/9] companion LAN pairing (optional) — lets a phone scan a QR code \
             to mint a chat-scoped bearer token, enabling companion-app access to this \
             NEOTH session over your local network.\n\
             \n\
             The companion server binds to 127.0.0.1 (loopback only — your phone \
             connects via the LAN IP listed in the QR). The bearer token is minted \
             per-session and expires after 24h.\n\
             \n\
             Pairing URL: {pairing_url}\n"
        );

        // Render QR code. Falls back gracefully if generation fails.
        let qr = render_pairing_qr(&pairing_url);
        if !qr.is_empty() {
            println!("{qr}");
        } else {
            println!("  (QR render unavailable — use the URL above directly)");
        }
        println!("  Raw URL: {pairing_url}\n");

        let want = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt(format!(
                "Enable companion LAN pairing server at {pairing_url}? (port {})",
                state.companion.port
            ))
            .default(false)
            .interact()
            .context("companion pairing offer confirm")?;

        if want {
            state.companion.enabled = true;
            println!(
                "  ✓ companion server enabled (port {})\n  \
                 → Start NEOTH and scan the QR with your companion app.",
                state.companion.port
            );
        } else {
            println!(
                "  → skipped (enable later: set `companion.enabled: true` \
                 in ~/.neoth/freedom.yaml)"
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// OH-05 integration test — non-interactive path with one Ollama-endpoint
    /// slot configured. Proves that step5b2_ollama_provision is reachable,
    /// collect_ollama_model_refs fires, and the non-interactive branch returns
    /// Ok(()) without panicking or hitting a live Ollama daemon.
    #[tokio::test]
    async fn step5b2_non_interactive_prints_pull_command_for_ollama_slot() {
        use crate::config::inference::{HemisphereSlot, InferenceProvider};

        let mut state = WizardState::default();

        // Wire one hemisphere to the Ollama OpenAI-compat endpoint with an hf.co model ref.
        let slot = HemisphereSlot {
            provider: Some(InferenceProvider::OpenAiCompat),
            model: Some("hf.co/unsloth/Qwen2.5-7B-Instruct-GGUF:Q4_K_M".to_string()),
            endpoint: Some(
                crate::installers::ollama::openai_compat_endpoint(
                    crate::installers::ollama::DEFAULT_OLLAMA_PORT,
                )
            ),
            key: None,
            region: None,
            api_version: None,
            voice: None,
        };
        state.inference.left = slot;

        // Non-interactive — must return Ok(()) with no panic.
        // collect_ollama_model_refs sees the slot; the non-interactive branch
        // prints the pull command to stdout and returns without touching Ollama.
        let result = step5b2_ollama_provision(false, &mut state).await;
        assert!(result.is_ok(), "step5b2_ollama_provision non-interactive must be Ok: {result:?}");
    }

    /// OH-05 — step5b2 with an empty topology returns Ok(()) immediately
    /// (no Ollama slots configured).
    #[tokio::test]
    async fn step5b2_non_interactive_noop_when_no_ollama_slots() {
        let mut state = WizardState::default();
        // Default topology has no OpenAiCompat Ollama slots.
        let result = step5b2_ollama_provision(false, &mut state).await;
        assert!(result.is_ok(), "step5b2 must be Ok with empty topology: {result:?}");
    }
}
