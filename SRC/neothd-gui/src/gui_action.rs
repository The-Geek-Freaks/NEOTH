//! Fail-closed subprocess boundary for GUI-triggered CLI actions.
//!
//! GUI callbacks must not infer success from human-readable stdout. Every
//! mutation crosses this boundary, which requires both a successful process
//! exit and a typed JSON acknowledgement before the UI may report success or
//! refresh dependent state.

use std::process::{Command, Output};

use serde::Deserialize;
use serde::de::DeserializeOwned;

const MAX_DIAGNOSTIC_CHARS: usize = 400;

pub struct JsonReceipt<T> {
    pub acknowledgement: T,
    pub stderr: Option<String>,
}

pub fn run_json<T>(command: &mut Command, action: &str) -> Result<T, String>
where
    T: DeserializeOwned,
{
    run_json_receipt(command, action).map(|receipt| receipt.acknowledgement)
}

pub fn run_json_receipt<T>(command: &mut Command, action: &str) -> Result<JsonReceipt<T>, String>
where
    T: DeserializeOwned,
{
    let output = command
        .output()
        .map_err(|error| format!("could not start {action}: {error}"))?;
    let acknowledgement = decode_json_output(&output, action)?;
    let stderr = bounded_text(&output.stderr, MAX_DIAGNOSTIC_CHARS * 2);
    Ok(JsonReceipt {
        acknowledgement,
        stderr,
    })
}

fn decode_json_output<T>(output: &Output, action: &str) -> Result<T, String>
where
    T: DeserializeOwned,
{
    if !output.status.success() {
        let exit = output
            .status
            .code()
            .map(|code| code.to_string())
            .unwrap_or_else(|| "?".to_string());
        return Err(format!(
            "{action} failed (exit {exit}): {}",
            diagnostic(output)
        ));
    }
    if output.stdout.iter().all(u8::is_ascii_whitespace) {
        return Err(format!(
            "{action} returned no acknowledgement; state was not assumed"
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("{action} returned an invalid acknowledgement: {error}"))
}

fn diagnostic(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    stderr
        .lines()
        .chain(stdout.lines())
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| line.chars().take(MAX_DIAGNOSTIC_CHARS).collect())
        .unwrap_or_else(|| "NEOTH CLI returned no diagnostic".to_string())
}

fn bounded_text(bytes: &[u8], max_chars: usize) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.chars().take(max_chars).collect())
}

fn require_action(actual: &str, expected: &str) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "acknowledged action `{actual}`, expected `{expected}`"
        ))
    }
}

fn require_id(actual: &str, expected: &str) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("acknowledged id `{actual}`, expected `{expected}`"))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CronMutationAck {
    pub ok: bool,
    pub action: String,
    pub id: String,
}

impl CronMutationAck {
    pub fn verify(&self, action: &str, id: &str) -> Result<(), String> {
        if !self.ok {
            return Err("Cron mutation did not acknowledge success".to_string());
        }
        require_action(&self.action, action)?;
        require_id(&self.id, id)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // Retain the complete wire contract even when the current toast uses a subset.
pub struct CronRunAck {
    pub job_id: String,
    pub success: bool,
    pub duration_ms: u64,
    pub output_bytes: u64,
    pub delivery_queued: bool,
    pub delivery_id: Option<String>,
    pub delivery_status: Option<String>,
    pub error: Option<String>,
}

impl CronRunAck {
    pub fn verify(&self, id: &str) -> Result<(), String> {
        require_id(&self.job_id, id)?;
        if self.success {
            Ok(())
        } else {
            Err(self
                .error
                .clone()
                .unwrap_or_else(|| "Cron run acknowledged failure".to_string()))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToggleAck {
    pub ok: bool,
    pub action: String,
    pub enabled: bool,
}

impl ToggleAck {
    pub fn verify(&self, action: &str, enabled: bool) -> Result<(), String> {
        if !self.ok {
            return Err(format!("{action} did not acknowledge success"));
        }
        require_action(&self.action, action)?;
        if self.enabled == enabled {
            Ok(())
        } else {
            Err(format!(
                "acknowledged enabled={}, expected {enabled}",
                self.enabled
            ))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuddySelfActivationAck {
    pub ok: bool,
    pub action: String,
    pub self_activation_enabled: bool,
}

impl BuddySelfActivationAck {
    pub fn verify(&self, enabled: bool) -> Result<(), String> {
        if !self.ok {
            return Err("Buddy self-activation did not acknowledge success".to_string());
        }
        require_action(&self.action, "set_self_activation")?;
        if self.self_activation_enabled == enabled {
            Ok(())
        } else {
            Err(format!(
                "acknowledged self_activation_enabled={}, expected {enabled}",
                self.self_activation_enabled
            ))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuddyProactiveAck {
    pub ok: bool,
    pub action: String,
    pub proactive_enabled: bool,
}

impl BuddyProactiveAck {
    pub fn verify(&self, enabled: bool) -> Result<(), String> {
        if !self.ok {
            return Err("Buddy proactive mode did not acknowledge success".to_string());
        }
        require_action(&self.action, "set_proactive")?;
        if self.proactive_enabled == enabled {
            Ok(())
        } else {
            Err(format!(
                "acknowledged proactive_enabled={}, expected {enabled}",
                self.proactive_enabled
            ))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmartApproveAck {
    pub ok: bool,
    pub action: String,
    pub smart_approve: bool,
    pub changed: bool,
}

impl SmartApproveAck {
    pub fn verify(&self, enabled: bool) -> Result<(), String> {
        if !self.ok {
            return Err("Smart-Approve mutation did not acknowledge success".to_string());
        }
        require_action(&self.action, "set_smart_approve")?;
        if self.smart_approve != enabled {
            return Err(format!(
                "acknowledged smart_approve={}, expected {enabled}",
                self.smart_approve
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SovereignDisableAck {
    pub mode: String,
    pub sovereign_buddy: bool,
    pub previous_autonomy: String,
}

impl SovereignDisableAck {
    pub fn verify(&self) -> Result<(), String> {
        if self.sovereign_buddy {
            return Err("Sovereign disable acknowledgement kept the mode enabled".to_string());
        }
        if self.mode.trim().is_empty() || self.previous_autonomy.trim().is_empty() {
            return Err("Sovereign disable acknowledgement is incomplete".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfImproveToggleAck {
    pub ok: bool,
    pub action: String,
    pub enabled: bool,
    pub auto: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfImproveDryRunAck {
    pub ok: bool,
    pub action: String,
    pub enabled: bool,
    pub staged: bool,
    pub persona: String,
    pub skill_path: Option<String>,
    pub diff: String,
    pub message: String,
}

impl SelfImproveDryRunAck {
    pub fn verify(&self) -> Result<(), String> {
        if !self.ok {
            return Err("Self-Improve dry-run did not acknowledge success".to_string());
        }
        require_action(&self.action, "dry_run")?;
        if self.staged {
            return Err("Self-Improve dry-run unexpectedly staged a proposal".to_string());
        }
        if self.persona.trim().is_empty() || self.message.trim().is_empty() {
            return Err("Self-Improve dry-run acknowledgement is incomplete".to_string());
        }
        if self.enabled && self.skill_path.as_deref().is_none_or(str::is_empty) {
            return Err("enabled Self-Improve dry-run did not bind its skill path".to_string());
        }
        Ok(())
    }
}

impl SelfImproveToggleAck {
    pub fn verify(&self, action: &str, enabled: bool, auto: bool) -> Result<(), String> {
        if !self.ok {
            return Err("Self-Improve toggle did not acknowledge success".to_string());
        }
        require_action(&self.action, action)?;
        if self.enabled != enabled || self.auto != auto {
            return Err(format!(
                "acknowledged enabled={} auto={}, expected enabled={enabled} auto={auto}",
                self.enabled, self.auto
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalMutationAck {
    pub ok: bool,
    pub action: String,
    pub id: String,
    pub status: String,
    #[serde(default)]
    pub upstream_pr_available: Option<bool>,
}

impl ProposalMutationAck {
    pub fn verify(&self, action: &str, id: &str, status: &str) -> Result<(), String> {
        if !self.ok {
            return Err(format!("{action} did not acknowledge success"));
        }
        require_action(&self.action, action)?;
        require_id(&self.id, id)?;
        if self.status == status {
            Ok(())
        } else {
            Err(format!(
                "acknowledged status `{}`, expected `{status}`",
                self.status
            ))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfDevScanAck {
    pub ok: bool,
    pub action: String,
    pub signals: usize,
    pub proposals_staged: usize,
    pub proposals_skipped_deployed: usize,
    pub proposals_skipped_not_auto_safe: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfEditAck {
    pub status: String,
    pub paths: Vec<String>,
    pub diff_hash: String,
    pub dry_run: bool,
}

impl SelfEditAck {
    pub fn verify_applied(&self, expected_hash: &str) -> Result<(), String> {
        if self.status != "applied" || self.dry_run {
            return Err(format!(
                "Self-Edit acknowledged status `{}` with dry_run={}",
                self.status, self.dry_run
            ));
        }
        if self.diff_hash != expected_hash {
            return Err(format!(
                "Self-Edit acknowledged hash `{}`, expected `{expected_hash}`",
                self.diff_hash
            ));
        }
        if self.paths.is_empty() {
            return Err("Self-Edit acknowledgement contains no target paths".to_string());
        }
        Ok(())
    }
}

impl SelfDevScanAck {
    pub fn verify(&self) -> Result<(), String> {
        if !self.ok {
            return Err("Self-Dev scan did not acknowledge success".to_string());
        }
        require_action(&self.action, "scan")
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarAddAck {
    pub ok: bool,
    pub action: String,
    pub outcome: String,
    pub uid: String,
}

impl CalendarAddAck {
    pub fn verify(&self) -> Result<(), String> {
        if !self.ok {
            return Err("Calendar add did not acknowledge success".to_string());
        }
        require_action(&self.action, "add")?;
        if !matches!(self.outcome.as_str(), "created" | "already_exists") {
            return Err(format!(
                "Calendar add returned unknown outcome `{}`",
                self.outcome
            ));
        }
        if self.uid.trim().is_empty() {
            return Err("Calendar add acknowledgement is missing `uid`".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // The typed sync receipt intentionally mirrors every CLI field.
pub struct ObsidianSyncAck {
    pub considered: usize,
    pub copied: usize,
    pub skipped_identical: usize,
    pub skipped_dry_run: usize,
    pub blocked_sync_conflict: bool,
    pub conflict_files: usize,
    pub core_sync_enabled: bool,
}

impl ObsidianSyncAck {
    pub fn verify(&self) -> Result<(), String> {
        if self.blocked_sync_conflict {
            Err(format!(
                "Obsidian sync was blocked by {} conflict(s)",
                self.conflict_files
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // The typed wiki receipt intentionally mirrors every CLI field.
pub struct WikiBuildAck {
    pub sources: usize,
    pub pages_planned: usize,
    pub pages_written: usize,
    pub dry_run: bool,
    pub out_dir: String,
    pub pages: Vec<String>,
}

impl WikiBuildAck {
    pub fn verify(&self) -> Result<(), String> {
        if self.dry_run {
            return Err("Obsidian wiki build unexpectedly acknowledged a dry-run".to_string());
        }
        if self.pages_written == self.pages_planned {
            Ok(())
        } else {
            Err(format!(
                "Obsidian wiki wrote {} of {} planned pages",
                self.pages_written, self.pages_planned
            ))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DreamNowAck {
    pub day: String,
    pub events_considered: usize,
    pub dreams_written: usize,
    pub path: String,
    pub path_taken: String,
}

impl DreamNowAck {
    pub fn verify(&self) -> Result<(), String> {
        if self.day.trim().is_empty()
            || self.path.trim().is_empty()
            || self.path_taken.trim().is_empty()
        {
            Err("Dream acknowledgement is missing required fields".to_string())
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReflectionAck {
    pub kind: String,
    pub tag: String,
    pub written: bool,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub topics: Vec<String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub obsidian: Option<String>,
}

impl ReflectionAck {
    pub fn verify_daily(&self) -> Result<(), String> {
        if self.kind != "daily" {
            return Err(format!(
                "reflection acknowledged kind `{}`, expected `daily`",
                self.kind
            ));
        }
        if self.tag.trim().is_empty() {
            return Err("reflection acknowledgement is missing `tag`".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompanionInviteAck {
    pub ok: bool,
    pub action: String,
    pub pair_url: String,
    pub expires_in_secs: u64,
    pub handed_to_daemon: bool,
}

impl CompanionInviteAck {
    pub fn verify(&self) -> Result<(), String> {
        if !self.ok {
            return Err("Companion invite did not acknowledge success".to_string());
        }
        require_action(&self.action, "pair_phone")?;
        if !self.handed_to_daemon {
            return Err("Companion invite was not handed to the daemon".to_string());
        }
        if self.expires_in_secs == 0 {
            return Err("Companion invite has no usable lifetime".to_string());
        }
        let Some(payload) = self.pair_url.strip_prefix("neoth://companion/pair?") else {
            return Err("Companion invite URL has an unexpected route".to_string());
        };
        if payload.trim().is_empty() {
            return Err("Companion invite URL is missing its payload".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::process::{ExitStatus, Output};

    use super::*;

    #[cfg(windows)]
    fn status(code: i32) -> ExitStatus {
        use std::os::windows::process::ExitStatusExt;
        ExitStatus::from_raw(code as u32)
    }

    #[cfg(unix)]
    fn status(code: i32) -> ExitStatus {
        use std::os::unix::process::ExitStatusExt;
        ExitStatus::from_raw(code << 8)
    }

    fn output(code: i32, stdout: &str, stderr: &str) -> Output {
        Output {
            status: status(code),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn failed_exit_never_parses_success_looking_stdout() {
        let error = decode_json_output::<ToggleAck>(
            &output(
                7,
                r#"{"ok":true,"action":"enable","enabled":true}"#,
                "permission denied",
            ),
            "Babel enable",
        )
        .unwrap_err();
        assert!(error.contains("exit 7"));
        assert!(error.contains("permission denied"));
    }

    #[test]
    fn successful_exit_without_ack_fails_closed() {
        let error =
            decode_json_output::<ToggleAck>(&output(0, "  \n", ""), "Babel enable").unwrap_err();
        assert!(error.contains("no acknowledgement"));
    }

    #[test]
    fn malformed_or_extended_ack_is_rejected() {
        assert!(decode_json_output::<ToggleAck>(&output(0, "not json", ""), "Babel").is_err());
        assert!(
            decode_json_output::<ToggleAck>(
                &output(
                    0,
                    r#"{"ok":true,"action":"enable","enabled":true,"surprise":1}"#,
                    "",
                ),
                "Babel",
            )
            .is_err()
        );
    }

    #[test]
    fn typed_toggle_ack_binds_action_and_state() {
        let ack = decode_json_output::<ToggleAck>(
            &output(0, r#"{"ok":true,"action":"enable","enabled":true}"#, ""),
            "Babel enable",
        )
        .unwrap();
        ack.verify("enable", true).unwrap();
        assert!(ack.verify("disable", true).is_err());
        assert!(ack.verify("enable", false).is_err());
    }

    #[test]
    fn buddy_policy_acks_bind_exact_action_and_target_state() {
        let self_activation: BuddySelfActivationAck = serde_json::from_str(
            r#"{"ok":true,"action":"set_self_activation","self_activation_enabled":true}"#,
        )
        .unwrap();
        self_activation.verify(true).unwrap();
        assert!(self_activation.verify(false).is_err());

        let proactive: BuddyProactiveAck = serde_json::from_str(
            r#"{"ok":true,"action":"set_proactive","proactive_enabled":false}"#,
        )
        .unwrap();
        proactive.verify(false).unwrap();
        assert!(proactive.verify(true).is_err());

        let wrong_action: BuddyProactiveAck = serde_json::from_str(
            r#"{"ok":true,"action":"set_self_activation","proactive_enabled":true}"#,
        )
        .unwrap();
        assert!(wrong_action.verify(true).is_err());
        assert!(
            serde_json::from_str::<BuddySelfActivationAck>(
                r#"{"ok":true,"action":"set_self_activation","self_activation_enabled":true,"surprise":1}"#,
            )
            .is_err(),
            "Buddy ACKs must reject uncontracted fields"
        );
    }

    #[test]
    fn bounded_text_preserves_success_warnings_without_changing_the_ack() {
        assert_eq!(
            bounded_text(b" warn [collision]: overlaps morning\n", 400).as_deref(),
            Some("warn [collision]: overlaps morning")
        );
        assert_eq!(bounded_text(b" \n", 400), None);
    }

    #[test]
    fn proposal_ack_binds_id_and_final_status() {
        let ack: ProposalMutationAck =
            serde_json::from_str(r#"{"ok":true,"action":"accept","id":"p42","status":"accepted"}"#)
                .unwrap();
        ack.verify("accept", "p42", "accepted").unwrap();
        assert!(ack.verify("accept", "p41", "accepted").is_err());
    }

    #[test]
    fn companion_ack_requires_exact_neoth_pair_route() {
        let good: CompanionInviteAck = serde_json::from_str(
            r#"{"ok":true,"action":"pair_phone","pair_url":"neoth://companion/pair?invite=abc","expires_in_secs":300,"handed_to_daemon":true}"#,
        )
        .unwrap();
        good.verify().unwrap();

        let bad: CompanionInviteAck = serde_json::from_str(
            r#"{"ok":true,"action":"pair_phone","pair_url":"https://example.test/pair?invite=abc","expires_in_secs":300,"handed_to_daemon":true}"#,
        )
        .unwrap();
        assert!(bad.verify().is_err());
    }

    #[test]
    fn targeted_action_receipts_are_typed_and_verified() {
        let cron: CronMutationAck =
            serde_json::from_str(r#"{"ok":true,"action":"add","id":"morning"}"#).unwrap();
        cron.verify("add", "morning").unwrap();

        let calendar: CalendarAddAck = serde_json::from_str(
            r#"{"ok":true,"action":"add","outcome":"created","uid":"neoth-a1"}"#,
        )
        .unwrap();
        calendar.verify().unwrap();

        let smart_approve: SmartApproveAck = serde_json::from_str(
            r#"{"ok":true,"action":"set_smart_approve","smart_approve":true,"changed":true}"#,
        )
        .unwrap();
        smart_approve.verify(true).unwrap();
        assert!(smart_approve.verify(false).is_err());

        let sovereign: SovereignDisableAck = serde_json::from_str(
            r#"{"mode":"full-auto","sovereign_buddy":false,"previous_autonomy":"full"}"#,
        )
        .unwrap();
        sovereign.verify().unwrap();

        let scan: SelfDevScanAck = serde_json::from_str(
            r#"{"ok":true,"action":"scan","signals":2,"proposals_staged":1,"proposals_skipped_deployed":0,"proposals_skipped_not_auto_safe":1}"#,
        )
        .unwrap();
        scan.verify().unwrap();

        let edit: SelfEditAck = serde_json::from_str(
            r#"{"status":"applied","paths":["src/lib.rs"],"diff_hash":"abc","dry_run":false}"#,
        )
        .unwrap();
        edit.verify_applied("abc").unwrap();

        let dream: DreamNowAck = serde_json::from_str(
            r#"{"day":"2026-07-15","events_considered":3,"dreams_written":1,"path":"dreams/2026-07-15.jsonl","path_taken":"Local"}"#,
        )
        .unwrap();
        dream.verify().unwrap();

        let reflection: ReflectionAck = serde_json::from_str(
            r#"{"kind":"daily","tag":"2026-07-15","written":false,"reason":"already_done"}"#,
        )
        .unwrap();
        reflection.verify_daily().unwrap();
    }

    #[test]
    fn targeted_gui_mutations_cannot_regress_to_the_unchecked_probe() {
        let source = include_str!("main.rs");
        let start = source.find("GAP-01 Automation / Cron CRUD panel").unwrap();
        let end = source
            .find("Wave 4b — Mesh & Cluster panel callbacks")
            .unwrap();
        let callbacks = &source[start..end];

        // The sole raw probe in this region is the read-only Dream-day view.
        assert_eq!(callbacks.matches("run_neothd_probe(").count(), 1);
        assert!(callbacks.contains("run_neothd_probe(&[\"dream\", \"show\""));
        // Baseline: Cron 4, Babel 2, Calendar 1, Self-Improve 5,
        // Self-Dev 4, Obsidian 2, Dream 1, Reflect 1, Buddy policy 4,
        // Companion 1.
        // New actions may increase this count; removing any existing checked
        // action requires an explicit contract-test update.
        assert!(callbacks.matches("run_neothd_json_action").count() >= 25);
        for action in [
            "Cron add",
            "Cron run",
            "Cron toggle",
            "Cron remove",
            "Babel enable",
            "Babel disable",
            "Calendar add",
            "Self-Improve enable",
            "Self-Improve disable",
            "Self-Improve dry-run",
            "Self-Improve accept",
            "Self-Improve rollback",
            "Self-Dev scan",
            "Self-Dev accept",
            "Self-Dev decline",
            "Self-Dev source apply",
            "Obsidian sync",
            "Obsidian wiki build",
            "Dream now",
            "Daily reflection",
            "Buddy self-activation update",
            "Buddy proactive update",
            "Sovereign disable",
            "Smart-Approve update",
            "Companion invite",
        ] {
            assert!(
                callbacks.contains(&format!("\"{action}\"")),
                "missing typed GUI action: {action}"
            );
        }
        assert!(callbacks.contains("&[\"reflect\", \"digest\", \"daily\"]"));
    }
}
