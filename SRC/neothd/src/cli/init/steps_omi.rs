//! OMI-MULTIMODAL-01 onboarding.
//!
//! The terminal wizard owns the same operator-facing controls as the desktop
//! wizard. Public configuration is checkpointed; credentials stay only in
//! `SecretString` memory until the final credential-store write.

use anyhow::{Context, Result, bail};
use tracing::debug;

use crate::config::OmiIngestMode;
use crate::config::credentials::Credentials;
use crate::secret::SecretString;

use super::{InitArgs, WizardState, WizardStep};
use crate::cli::omi::OmiCredentialUpdate;

const OMI_DEVELOPER_KEY_ENV: &str = "NEOTH_OMI_DEVELOPER_API_KEY";
const OMI_INGEST_TOKEN_ENV: &str = "NEOTH_OMI_INGEST_TOKEN";

fn parse_omi_mode(raw: &str) -> Result<OmiIngestMode> {
    let normalized = raw.trim().to_ascii_lowercase().replace('-', "_");
    match normalized.as_str() {
        "developer_api" | "developer" => Ok(OmiIngestMode::DeveloperApi),
        "native_ingest" | "native" => Ok(OmiIngestMode::NativeIngest),
        "both" => Ok(OmiIngestMode::Both),
        "legacy_memories" | "legacy" => Ok(OmiIngestMode::LegacyMemories),
        _ => bail!(
            "invalid --omi-mode {raw:?}; expected developer_api, native_ingest, both, or legacy_memories"
        ),
    }
}

#[cfg(feature = "wizard")]
fn mode_index(mode: OmiIngestMode) -> usize {
    match mode {
        OmiIngestMode::DeveloperApi => 0,
        OmiIngestMode::NativeIngest => 1,
        OmiIngestMode::Both => 2,
        OmiIngestMode::LegacyMemories => 3,
    }
}

fn normalize_explicit_mode_change(state: &mut WizardState) {
    if !state.omi.mode.listens() {
        state.omi.audio_enabled = false;
        state.omi.visual_enabled = false;
        state.omi.video_enabled = false;
        state.omi.allow_cloud_summary = false;
        state.omi.allowed_uids.clear();
    }
    if !matches!(
        state.omi.mode,
        OmiIngestMode::DeveloperApi | OmiIngestMode::Both
    ) {
        state.omi.allow_cloud_api = false;
    }
}

fn apply_non_interactive_args(args: &InitArgs, state: &mut WizardState) -> Result<()> {
    if args.omi {
        state.omi.enabled = true;
    } else if args.no_omi {
        state.omi.enabled = false;
    }

    if let Some(raw) = args.omi_mode.as_deref() {
        state.omi.mode = parse_omi_mode(raw)?;
        normalize_explicit_mode_change(state);
    }
    if let Some(value) = args.omi_endpoint.as_ref() {
        state.omi.endpoint = value.clone();
    }
    if let Some(value) = args.omi_listen_addr.as_ref() {
        state.omi.listen_addr = value.clone();
    }
    if let Some(value) = args.omi_allow_cloud_api {
        state.omi.allow_cloud_api = value;
    }
    if let Some(value) = args.omi_retention_days {
        state.omi.retention_days = value;
    }
    if let Some(value) = args.omi_retain_transcripts {
        state.omi.retain_transcripts = value;
    }
    if let Some(value) = args.omi_audio {
        state.omi.audio_enabled = value;
    }
    if let Some(value) = args.omi_images {
        state.omi.visual_enabled = value;
    }
    if let Some(value) = args.omi_video {
        state.omi.video_enabled = value;
    }
    if let Some(value) = args.omi_create_actions {
        state.omi.create_actions = value;
    }
    if let Some(value) = args.omi_seed_groundtruth {
        state.omi.seed_groundtruth = value;
    }
    if let Some(value) = args.omi_summary {
        state.omi.summary_enabled = value;
    }
    if let Some(value) = args.omi_allow_cloud_summary {
        state.omi.allow_cloud_summary = value;
    }
    Ok(())
}

fn read_secret_env(name: &str) -> Result<Option<SecretString>> {
    let Some(raw) = std::env::var_os(name) else {
        return Ok(None);
    };
    let value = raw
        .into_string()
        .map_err(|_| anyhow::anyhow!("{name} is not valid UTF-8"))?;
    Ok(Some(SecretString::from(value.as_str())))
}

fn apply_environment_credentials(state: &mut WizardState) -> Result<()> {
    if let Some(value) = read_secret_env(OMI_DEVELOPER_KEY_ENV)? {
        state.omi_developer_api_key = Some(value);
    }
    if let Some(value) = read_secret_env(OMI_INGEST_TOKEN_ENV)? {
        state.omi_ingest_token = Some(value);
    }
    validate_supplied_credentials(state)
}

fn validate_supplied_credentials(state: &WizardState) -> Result<()> {
    if state.omi_developer_api_key.is_none() && state.omi_ingest_token.is_none() {
        return Ok(());
    }
    OmiCredentialUpdate {
        developer_api_key: state.omi_developer_api_key.clone(),
        native_ingest_token: state.omi_ingest_token.clone(),
    }
    .validate()
}

fn effective_credentials(neoth_dir: &std::path::Path, state: &WizardState) -> Result<Credentials> {
    let path = neoth_dir.join("credentials.yaml");
    let mut credentials = Credentials::load_effective(&path, state.secrets_backend)
        .with_context(|| format!("load existing OMI credentials from {}", path.display()))?;
    if let Some(value) = state.omi_developer_api_key.as_ref() {
        credentials.omi_developer_api_key = Some(value.clone());
    }
    if let Some(value) = state.omi_ingest_token.as_ref() {
        credentials.omi_ingest_token = Some(value.clone());
    }
    Ok(credentials)
}

fn validate_complete_omi_state(neoth_dir: &std::path::Path, state: &WizardState) -> Result<()> {
    let credentials = effective_credentials(neoth_dir, state)?;
    state
        .omi
        .validate_with_credentials(&credentials)
        .map_err(anyhow::Error::msg)
        .with_context(|| {
            format!(
                "invalid OMI onboarding configuration; non-interactive credentials must use {OMI_DEVELOPER_KEY_ENV} and/or {OMI_INGEST_TOKEN_ENV}"
            )
        })
}

#[cfg(feature = "wizard")]
fn configure_interactively(neoth_dir: &std::path::Path, state: &mut WizardState) -> Result<()> {
    use dialoguer::{Confirm, Input, Password, Select, theme::ColorfulTheme};

    let theme = ColorfulTheme::default();
    println!();
    let enabled = Confirm::with_theme(&theme)
        .with_prompt("Enable private OMI ingest? (disabled is recommended until configured)")
        .default(state.omi.enabled)
        .interact()
        .context("OMI enable prompt")?;
    state.omi.enabled = enabled;
    if !enabled {
        return validate_complete_omi_state(neoth_dir, state);
    }

    let modes = [
        "Developer API conversation import (recommended)",
        "Native authenticated audio/media ingest",
        "Both (import conversations and export completed native transcripts)",
        "Legacy local /v1/memories compatibility",
    ];
    let picked = Select::with_theme(&theme)
        .with_prompt("OMI ingest mode")
        .items(&modes)
        .default(mode_index(state.omi.mode))
        .interact()
        .context("OMI mode prompt")?;
    state.omi.mode = match picked {
        0 => OmiIngestMode::DeveloperApi,
        1 => OmiIngestMode::NativeIngest,
        2 => OmiIngestMode::Both,
        _ => OmiIngestMode::LegacyMemories,
    };
    normalize_explicit_mode_change(state);

    if state.omi.mode.polls() {
        state.omi.endpoint = Input::<String>::with_theme(&theme)
            .with_prompt("OMI API/backend endpoint (loopback is recommended)")
            .default(state.omi.endpoint.clone())
            .interact_text()
            .context("OMI endpoint prompt")?;
        if matches!(
            state.omi.mode,
            OmiIngestMode::DeveloperApi | OmiIngestMode::Both
        ) {
            state.omi.allow_cloud_api = Confirm::with_theme(&theme)
                .with_prompt(
                    "Allow OMI cloud API reads and, in both mode, completed native transcript exports? (no is recommended)",
                )
                .default(state.omi.allow_cloud_api)
                .interact()
                .context("OMI cloud API consent prompt")?;
        }
    }

    if state.omi.mode.listens() {
        state.omi.listen_addr = Input::<String>::with_theme(&theme)
            .with_prompt("Native OMI listener IP:port (loopback is recommended)")
            .default(state.omi.listen_addr.clone())
            .interact_text()
            .context("OMI listener prompt")?;
    }

    state.omi.retention_days = Input::<u64>::with_theme(&theme)
        .with_prompt("OMI retention days (30 recommended)")
        .default(state.omi.retention_days)
        .interact_text()
        .context("OMI retention prompt")?;
    state.omi.retain_transcripts = Confirm::with_theme(&theme)
        .with_prompt("Retain verbatim transcripts locally? (no is recommended)")
        .default(state.omi.retain_transcripts)
        .interact()
        .context("OMI transcript retention prompt")?;

    if state.omi.mode.listens() {
        state.omi.audio_enabled = Confirm::with_theme(&theme)
            .with_prompt("Accept OMI audio? (no is recommended until needed)")
            .default(state.omi.audio_enabled)
            .interact()
            .context("OMI audio consent prompt")?;
        state.omi.visual_enabled = Confirm::with_theme(&theme)
            .with_prompt("Accept OMI images? (no is recommended until needed)")
            .default(state.omi.visual_enabled)
            .interact()
            .context("OMI image consent prompt")?;
        state.omi.video_enabled = if state.omi.visual_enabled {
            Confirm::with_theme(&theme)
                .with_prompt("Accept OMI video frames? (no is recommended until needed)")
                .default(state.omi.video_enabled)
                .interact()
                .context("OMI video consent prompt")?
        } else {
            false
        };
    }

    state.omi.create_actions = Confirm::with_theme(&theme)
        .with_prompt("Create local tasks from OMI action items? (yes is recommended)")
        .default(state.omi.create_actions)
        .interact()
        .context("OMI action promotion prompt")?;
    state.omi.seed_groundtruth = Confirm::with_theme(&theme)
        .with_prompt("Seed corroborated OMI statements into ground truth? (yes is recommended)")
        .default(state.omi.seed_groundtruth)
        .interact()
        .context("OMI ground-truth prompt")?;
    state.omi.summary_enabled = Confirm::with_theme(&theme)
        .with_prompt("Produce bounded local OMI summaries? (yes is recommended)")
        .default(state.omi.summary_enabled)
        .interact()
        .context("OMI summary prompt")?;
    state.omi.allow_cloud_summary = if state.omi.mode.listens() && state.omi.summary_enabled {
        Confirm::with_theme(&theme)
            .with_prompt("Allow OMI summary text to use a cloud model? (no is recommended)")
            .default(state.omi.allow_cloud_summary)
            .interact()
            .context("OMI cloud summary consent prompt")?
    } else {
        false
    };

    let existing = effective_credentials(neoth_dir, state)?;
    if matches!(
        state.omi.mode,
        OmiIngestMode::DeveloperApi | OmiIngestMode::Both
    ) && existing.omi_developer_api_key.is_none()
    {
        let key = Password::with_theme(&theme)
            .with_prompt("OMI Developer API key (omi_dev_*, input hidden)")
            .with_confirmation(
                "Repeat OMI Developer API key",
                "OMI Developer API keys differ",
            )
            .interact()
            .context("OMI Developer API key prompt")?;
        state.omi_developer_api_key = Some(SecretString::from(key.as_str()));
    }
    let existing = effective_credentials(neoth_dir, state)?;
    if state.omi.mode.listens() && existing.omi_ingest_token.is_none() {
        let token = Password::with_theme(&theme)
            .with_prompt("Native OMI bearer token (at least 32 characters, input hidden)")
            .with_confirmation("Repeat native OMI bearer token", "native OMI tokens differ")
            .interact()
            .context("native OMI token prompt")?;
        state.omi_ingest_token = Some(SecretString::from(token.as_str()));
    }

    validate_supplied_credentials(state)?;
    validate_complete_omi_state(neoth_dir, state)
}

pub(crate) fn step6_omi(
    args: &InitArgs,
    interactive: bool,
    neoth_dir: &std::path::Path,
    state: &mut WizardState,
) -> Result<()> {
    debug!("wizard step 6 OMI: private conversation/media ingest");
    apply_environment_credentials(state)?;

    if interactive {
        #[cfg(feature = "wizard")]
        configure_interactively(neoth_dir, state)?;
        #[cfg(not(feature = "wizard"))]
        bail!("interactive OMI onboarding requires the `wizard` feature");
    } else {
        apply_non_interactive_args(args, state)?;
        validate_complete_omi_state(neoth_dir, state)?;
    }

    if !state.steps_completed.contains(&(WizardStep::Omi as u8)) {
        state.steps_completed.push(WizardStep::Omi as u8);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_and_cli_friendly_omi_modes() {
        assert_eq!(
            parse_omi_mode("developer_api").unwrap(),
            OmiIngestMode::DeveloperApi
        );
        assert_eq!(
            parse_omi_mode("native-ingest").unwrap(),
            OmiIngestMode::NativeIngest
        );
        assert_eq!(parse_omi_mode("both").unwrap(), OmiIngestMode::Both);
        assert_eq!(
            parse_omi_mode("legacy_memories").unwrap(),
            OmiIngestMode::LegacyMemories
        );
        assert!(parse_omi_mode("private_backend_socket").is_err());
    }

    #[test]
    fn non_interactive_omi_args_cover_every_wizard_privacy_control() {
        let args = InitArgs {
            omi: true,
            omi_mode: Some("both".to_string()),
            omi_endpoint: Some("https://api.omi.me".to_string()),
            omi_listen_addr: Some("127.0.0.1:9555".to_string()),
            omi_allow_cloud_api: Some(true),
            omi_retention_days: Some(7),
            omi_retain_transcripts: Some(true),
            omi_audio: Some(true),
            omi_images: Some(true),
            omi_video: Some(true),
            omi_create_actions: Some(false),
            omi_seed_groundtruth: Some(false),
            omi_summary: Some(true),
            omi_allow_cloud_summary: Some(true),
            ..InitArgs::default()
        };
        let mut state = WizardState::default();
        apply_non_interactive_args(&args, &mut state).unwrap();
        assert!(state.omi.enabled);
        assert_eq!(state.omi.mode, OmiIngestMode::Both);
        assert_eq!(state.omi.endpoint, "https://api.omi.me");
        assert_eq!(state.omi.listen_addr, "127.0.0.1:9555");
        assert!(state.omi.allow_cloud_api);
        assert_eq!(state.omi.retention_days, 7);
        assert!(state.omi.retain_transcripts);
        assert!(state.omi.audio_enabled);
        assert!(state.omi.visual_enabled);
        assert!(state.omi.video_enabled);
        assert!(!state.omi.create_actions);
        assert!(!state.omi.seed_groundtruth);
        assert!(state.omi.summary_enabled);
        assert!(state.omi.allow_cloud_summary);
    }

    #[test]
    fn fresh_non_interactive_init_keeps_omi_and_every_media_consent_off() {
        let args = InitArgs::default();
        let mut state = WizardState::default();
        apply_non_interactive_args(&args, &mut state).unwrap();
        assert!(!state.omi.enabled);
        assert!(!state.omi.retain_transcripts);
        assert!(!state.omi.audio_enabled);
        assert!(!state.omi.visual_enabled);
        assert!(!state.omi.video_enabled);
        assert!(!state.omi.allow_cloud_api);
        assert!(!state.omi.allow_cloud_summary);
    }

    #[test]
    fn explicit_developer_mode_clears_inapplicable_native_consents() {
        let mut state = WizardState::default();
        state.omi.mode = OmiIngestMode::Both;
        state.omi.audio_enabled = true;
        state.omi.visual_enabled = true;
        state.omi.video_enabled = true;
        state.omi.allow_cloud_summary = true;
        state.omi.allowed_uids.push("device-1".to_string());
        let args = InitArgs {
            omi_mode: Some("developer_api".to_string()),
            ..InitArgs::default()
        };
        apply_non_interactive_args(&args, &mut state).unwrap();
        assert!(!state.omi.audio_enabled);
        assert!(!state.omi.visual_enabled);
        assert!(!state.omi.video_enabled);
        assert!(!state.omi.allow_cloud_summary);
        assert!(state.omi.allowed_uids.is_empty());
    }

    #[test]
    fn supplied_omi_credentials_are_validated_without_exposure() {
        let mut state = WizardState::default();
        state.omi_developer_api_key = Some(SecretString::from("omi_dev_init_test"));
        state.omi_ingest_token = Some(SecretString::from("0123456789abcdef0123456789abcdef"));
        validate_supplied_credentials(&state).unwrap();
        assert_eq!(
            state
                .omi_developer_api_key
                .as_ref()
                .unwrap()
                .expose_secret(),
            "omi_dev_init_test"
        );
    }
}
