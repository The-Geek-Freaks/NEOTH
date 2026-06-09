//! GOLD-ADOPT-12 — build a multi-local hemisphere preset.
//!
//! Turns the VRAM-fitting plan from [`crate::models::selector`] into concrete
//! per-hemisphere local models served by Ollama (OpenAI-compatible). The
//! operator's ask: run 1, 2, or 3 LOCAL quantized GGUFs across the
//! left / right / cerebellum slots (the rest stay cloud).
//!
//! This builder is **pure + sync** (verified curated GGUF repos, no network) so
//! the synchronous `neoth init` wizard step can call it directly. The async
//! `neoth models recommend` CLI does the live "newest/best" HuggingFace upgrade;
//! the wizard ships a verified-good default that also works air-gapped.

use crate::installers::ollama;
use crate::models::gguf_variants::{curated_fallback, VariantClass};
use crate::models::selector::plan_local_hemispheres;

/// The three hemisphere roles, in the order the wizard binds them.
pub const ROLES: [&str; 3] = ["left", "right", "cerebellum"];

/// One local hemisphere: a quantized GGUF served by Ollama, with the exact
/// `ollama pull` command + the model ref to put in the hemisphere's slot.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalHemisphere {
    /// `left` | `right` | `cerebellum`.
    pub role: &'static str,
    pub param_b: f32,
    /// GGUF quant tag, e.g. `Q4_K_M`.
    pub quant_tag: &'static str,
    /// HuggingFace repo id backing the model.
    pub repo: String,
    /// Ollama model ref (`hf.co/<repo>:<tag>`) — goes into the hemisphere slot's
    /// `model` field; Ollama serves it under exactly this name.
    pub ollama_model_ref: String,
    /// `["ollama", "pull", "<ollama_model_ref>"]`.
    pub pull_command: Vec<String>,
}

/// A resolved multi-local preset: the Ollama OpenAI-compat endpoint every local
/// hemisphere points at, plus the per-role local models (role order, `len <= 3`).
/// Roles beyond `locals.len()` keep their existing (typically cloud) slot.
#[derive(Debug, Clone, PartialEq)]
pub struct HemispherePreset {
    /// `http://127.0.0.1:<port>/v1`.
    pub endpoint: String,
    pub locals: Vec<LocalHemisphere>,
}

impl HemispherePreset {
    /// True when all three hemispheres are local (→ Triplet topology); a mix of
    /// local + cloud is Custom topology.
    pub fn is_all_local(&self) -> bool {
        self.locals.len() == ROLES.len()
    }
}

/// Build the preset for `n_local` local hemispheres at the operator's VRAM, in
/// `class` lineage (abliterated by default), served by Ollama on `port`. Returns
/// an empty `locals` when nothing fits (caller falls back to cloud).
pub fn build_local_preset(
    vram_mib: Option<u32>,
    n_local: u8,
    class: VariantClass,
    port: u16,
) -> HemispherePreset {
    let plan = plan_local_hemispheres(vram_mib, n_local);
    let endpoint = ollama::openai_compat_endpoint(port);
    let locals = plan
        .iter()
        .enumerate()
        .map(|(i, opt)| {
            let variant = curated_fallback(opt.param_b, class)
                .or_else(|| curated_fallback(7.0, VariantClass::Standard))
                .expect("7B standard is always curated");
            let ollama_model_ref = variant.pull_ref(opt.quant);
            LocalHemisphere {
                role: ROLES[i.min(ROLES.len() - 1)],
                param_b: opt.param_b,
                quant_tag: opt.quant.gguf_tag(),
                repo: variant.repo,
                pull_command: ollama::pull_command(&ollama_model_ref),
                ollama_model_ref,
            }
        })
        .collect();
    HemispherePreset { endpoint, locals }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installers::ollama::DEFAULT_OLLAMA_PORT;

    #[test]
    fn three_local_abliterated_on_a_24gib_gpu() {
        let p = build_local_preset(
            Some(24 * 1024),
            3,
            VariantClass::Abliterated,
            DEFAULT_OLLAMA_PORT,
        );
        assert!(p.is_all_local());
        assert_eq!(p.endpoint, "http://127.0.0.1:11434/v1");
        assert_eq!(
            p.locals.iter().map(|l| l.role).collect::<Vec<_>>(),
            vec!["left", "right", "cerebellum"]
        );
        // Every slot is a verified abliterated GGUF served via hf.co ref.
        for l in &p.locals {
            assert!(l.ollama_model_ref.starts_with("hf.co/mradermacher/"), "{l:?}");
            assert!(l.ollama_model_ref.contains("abliterated-GGUF"));
            assert_eq!(l.pull_command[0], "ollama");
            assert_eq!(l.pull_command[2], l.ollama_model_ref);
        }
    }

    #[test]
    fn mixed_local_plus_cloud_is_not_all_local() {
        // 1 local hemisphere; the other two roles stay on the existing slot.
        let p = build_local_preset(
            Some(24 * 1024),
            1,
            VariantClass::Abliterated,
            DEFAULT_OLLAMA_PORT,
        );
        assert_eq!(p.locals.len(), 1);
        assert!(!p.is_all_local());
        assert_eq!(p.locals[0].role, "left");
        // The single fat slot gets the biggest model (32B-Q4 on 24 GiB).
        assert_eq!(p.locals[0].param_b, 32.0);
        assert_eq!(p.locals[0].quant_tag, "Q4_K_M");
    }

    #[test]
    fn standard_class_uses_bartowski_refs() {
        let p = build_local_preset(Some(8 * 1024), 2, VariantClass::Standard, DEFAULT_OLLAMA_PORT);
        for l in &p.locals {
            assert!(l.ollama_model_ref.starts_with("hf.co/bartowski/"), "{l:?}");
        }
    }

    #[test]
    fn nothing_fits_yields_empty_locals() {
        let p = build_local_preset(Some(512), 3, VariantClass::Abliterated, DEFAULT_OLLAMA_PORT);
        assert!(p.locals.is_empty());
        assert!(!p.is_all_local());
    }
}
