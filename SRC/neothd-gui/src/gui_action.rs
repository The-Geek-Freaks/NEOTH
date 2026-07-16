//! Fail-closed subprocess boundary for GUI-triggered CLI actions.
//!
//! GUI callbacks must not infer success from human-readable stdout. Every
//! mutation crosses this boundary, which requires both a successful process
//! exit and a typed JSON acknowledgement before the UI may report success or
//! refresh dependent state.

use std::path::Path;
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

fn require_task_id(actual: i64, expected: &str) -> Result<(), String> {
    let expected = expected
        .parse::<i64>()
        .map_err(|_| format!("expected task id `{expected}` is not an integer"))?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "acknowledged task id `{actual}`, expected `{expected}`"
        ))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionMutationAck {
    pub operation: String,
    pub action: String,
    pub decision: Option<String>,
    pub path: String,
}

impl PermissionMutationAck {
    pub fn verify_set(
        &self,
        action: &str,
        decision: &str,
        expected_path: &Path,
    ) -> Result<(), String> {
        require_action(&self.operation, "set")?;
        require_id(&self.action, action)?;
        if self.decision.as_deref() != Some(decision) {
            return Err(format!(
                "acknowledged decision `{:?}`, expected `{decision}`",
                self.decision
            ));
        }
        self.require_path(expected_path)
    }

    pub fn verify_clear(&self, action: &str, expected_path: &Path) -> Result<(), String> {
        require_action(&self.operation, "cleared")?;
        require_id(&self.action, action)?;
        if self.decision.is_some() {
            return Err("clear acknowledgement unexpectedly retained a decision".to_string());
        }
        self.require_path(expected_path)
    }

    fn require_path(&self, expected_path: &Path) -> Result<(), String> {
        if self.path.trim().is_empty() {
            return Err("permission acknowledgement is missing its config path".to_string());
        }
        let actual = std::path::absolute(&self.path).map_err(|error| {
            format!(
                "could not normalize acknowledged config path `{}`: {error}",
                self.path
            )
        })?;
        let expected = std::path::absolute(expected_path).map_err(|error| {
            format!(
                "could not normalize expected config path `{}`: {error}",
                expected_path.display()
            )
        })?;
        #[cfg(windows)]
        let matches = actual
            .to_string_lossy()
            .eq_ignore_ascii_case(&expected.to_string_lossy());
        #[cfg(not(windows))]
        let matches = actual == expected;
        if matches {
            Ok(())
        } else {
            Err(format!(
                "acknowledged config path `{}`, expected `{}`",
                actual.display(),
                expected.display()
            ))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KanbanMoveAck {
    pub ok: bool,
    pub action: String,
    pub task_id: i64,
    pub status: String,
}

impl KanbanMoveAck {
    pub fn verify(&self, task_id: &str, status: &str) -> Result<(), String> {
        if !self.ok {
            return Err("Kanban move did not acknowledge success".to_string());
        }
        require_action(&self.action, "move")?;
        require_task_id(self.task_id, task_id)?;
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
pub struct KanbanAssignAck {
    pub ok: bool,
    pub action: String,
    pub task_id: i64,
    pub hemisphere: String,
    pub worker: Option<String>,
}

impl KanbanAssignAck {
    pub fn verify(
        &self,
        task_id: &str,
        hemisphere: &str,
        worker: Option<&str>,
    ) -> Result<(), String> {
        if !self.ok {
            return Err("Kanban assignment did not acknowledge success".to_string());
        }
        require_action(&self.action, "assign")?;
        require_task_id(self.task_id, task_id)?;
        if self.hemisphere != hemisphere {
            return Err(format!(
                "acknowledged hemisphere `{}`, expected `{hemisphere}`",
                self.hemisphere
            ));
        }
        if self.worker.as_deref() != worker {
            return Err(format!(
                "acknowledged worker `{:?}`, expected `{worker:?}`",
                self.worker
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KanbanAddAck {
    pub ok: bool,
    pub action: String,
    pub task_id: i64,
    pub session_id: i64,
    pub status: String,
    pub title: String,
    pub task_type: String,
}

impl KanbanAddAck {
    pub fn verify(&self, title: &str, task_type: &str) -> Result<(), String> {
        if !self.ok {
            return Err("Kanban add did not acknowledge success".to_string());
        }
        require_action(&self.action, "add")?;
        if self.task_id <= 0 || self.session_id <= 0 {
            return Err("Kanban add acknowledgement is missing task/session ids".to_string());
        }
        if self.status != "backlog" {
            return Err(format!(
                "acknowledged status `{}`, expected `backlog`",
                self.status
            ));
        }
        if self.title != title {
            return Err(format!(
                "acknowledged title `{}`, expected `{title}`",
                self.title
            ));
        }
        if self.task_type != task_type {
            return Err(format!(
                "acknowledged task type `{}`, expected `{task_type}`",
                self.task_type
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KanbanCommentAck {
    pub ok: bool,
    pub action: String,
    pub task_id: i64,
    pub comment_id: i64,
    pub author: String,
}

impl KanbanCommentAck {
    pub fn verify(&self, task_id: &str, author: &str) -> Result<(), String> {
        if !self.ok {
            return Err("Kanban comment did not acknowledge success".to_string());
        }
        require_action(&self.action, "comment")?;
        require_task_id(self.task_id, task_id)?;
        if self.comment_id <= 0 {
            return Err("Kanban comment acknowledgement is missing its id".to_string());
        }
        if self.author != author {
            return Err(format!(
                "acknowledged author `{}`, expected `{author}`",
                self.author
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KanbanFinishAck {
    pub ok: bool,
    pub action: String,
    pub task_id: i64,
    pub status: String,
    pub verified_tests: bool,
}

impl KanbanFinishAck {
    pub fn verify(&self, task_id: &str, verified_tests: bool) -> Result<(), String> {
        if !self.ok {
            return Err("Kanban finish did not acknowledge success".to_string());
        }
        require_action(&self.action, "finish")?;
        require_task_id(self.task_id, task_id)?;
        if self.status != "done" {
            return Err(format!(
                "acknowledged status `{}`, expected `done`",
                self.status
            ));
        }
        if self.verified_tests != verified_tests {
            return Err(format!(
                "acknowledged verified-tests `{}`, expected `{verified_tests}`",
                self.verified_tests
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KanbanPromoteAck {
    pub ok: bool,
    pub action: String,
    pub task_id: i64,
    pub from_status: String,
    pub status: String,
    pub promoted: bool,
    pub blocker: Option<String>,
}

impl KanbanPromoteAck {
    pub fn verify(&self, task_id: &str) -> Result<(), String> {
        if !self.ok {
            return Err(self
                .blocker
                .clone()
                .unwrap_or_else(|| "Kanban promote did not acknowledge success".to_string()));
        }
        require_action(&self.action, "promote")?;
        require_task_id(self.task_id, task_id)?;
        if self.from_status != "review" || self.status != "done" || !self.promoted {
            return Err(format!(
                "Kanban promote acknowledged {} -> {} (promoted={})",
                self.from_status, self.status, self.promoted
            ));
        }
        if self.blocker.is_some() {
            return Err("successful Kanban promote unexpectedly included a blocker".to_string());
        }
        Ok(())
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
    fn permission_and_kanban_receipts_fail_closed_on_process_or_schema_errors() {
        let success_looking = r#"{"ok":true,"action":"move","task_id":42,"status":"done"}"#;
        assert!(
            decode_json_output::<KanbanMoveAck>(
                &output(9, success_looking, "database is locked"),
                "Kanban move",
            )
            .unwrap_err()
            .contains("exit 9")
        );
        assert!(
            decode_json_output::<KanbanMoveAck>(&output(0, "not-json", ""), "Kanban move",)
                .unwrap_err()
                .contains("invalid acknowledgement")
        );
        assert!(
            decode_json_output::<PermissionMutationAck>(&output(0, "", ""), "Permission set",)
                .unwrap_err()
                .contains("no acknowledgement")
        );
    }

    #[test]
    fn permission_receipts_bind_operation_action_and_decision() {
        let expected_path = std::env::current_dir().unwrap().join("freedom.yaml");
        let set: PermissionMutationAck = serde_json::from_str(
            r#"{"operation":"set","action":"shell_exec","decision":"confirm","path":"freedom.yaml"}"#,
        )
        .unwrap();
        set.verify_set("shell_exec", "confirm", &expected_path)
            .unwrap();
        assert!(
            set.verify_set("file_write", "confirm", &expected_path)
                .is_err()
        );
        assert!(
            set.verify_set("shell_exec", "allow", &expected_path)
                .is_err()
        );
        assert!(
            set.verify_set(
                "shell_exec",
                "confirm",
                &expected_path.with_file_name("other.yaml"),
            )
            .is_err()
        );

        let wrong_operation: PermissionMutationAck = serde_json::from_str(
            r#"{"operation":"cleared","action":"shell_exec","decision":null,"path":"freedom.yaml"}"#,
        )
        .unwrap();
        assert!(
            wrong_operation
                .verify_set("shell_exec", "confirm", &expected_path)
                .is_err()
        );
        wrong_operation
            .verify_clear("shell_exec", &expected_path)
            .unwrap();
        assert!(
            wrong_operation
                .verify_clear("file_write", &expected_path)
                .is_err()
        );
    }

    #[test]
    fn kanban_receipts_bind_action_task_and_target() {
        let added: KanbanAddAck = serde_json::from_str(
            r#"{"ok":true,"action":"add","task_id":42,"session_id":7,"status":"backlog","title":"Ship it","task_type":"feature"}"#,
        )
        .unwrap();
        added.verify("Ship it", "feature").unwrap();
        assert!(added.verify("Wrong title", "feature").is_err());
        assert!(added.verify("Ship it", "bug").is_err());

        let missing_session: KanbanAddAck = serde_json::from_str(
            r#"{"ok":true,"action":"add","task_id":42,"session_id":0,"status":"backlog","title":"Ship it","task_type":"feature"}"#,
        )
        .unwrap();
        assert!(missing_session.verify("Ship it", "feature").is_err());

        let moved: KanbanMoveAck = serde_json::from_str(
            r#"{"ok":true,"action":"move","task_id":42,"status":"in_progress"}"#,
        )
        .unwrap();
        moved.verify("42", "in_progress").unwrap();
        assert!(moved.verify("41", "in_progress").is_err());
        assert!(moved.verify("42", "done").is_err());

        let wrong_action: KanbanMoveAck = serde_json::from_str(
            r#"{"ok":true,"action":"assign","task_id":42,"status":"in_progress"}"#,
        )
        .unwrap();
        assert!(wrong_action.verify("42", "in_progress").is_err());

        let assigned: KanbanAssignAck = serde_json::from_str(
            r#"{"ok":true,"action":"assign","task_id":42,"hemisphere":"left","worker":null}"#,
        )
        .unwrap();
        assigned.verify("42", "left", None).unwrap();
        assert!(assigned.verify("42", "right", None).is_err());
        assert!(assigned.verify("42", "left", Some("worker-a")).is_err());

        let comment: KanbanCommentAck = serde_json::from_str(
            r#"{"ok":true,"action":"comment","task_id":42,"comment_id":9,"author":"operator"}"#,
        )
        .unwrap();
        comment.verify("42", "operator").unwrap();
        assert!(comment.verify("41", "operator").is_err());
        assert!(comment.verify("42", "buddy").is_err());

        let finished: KanbanFinishAck = serde_json::from_str(
            r#"{"ok":true,"action":"finish","task_id":42,"status":"done","verified_tests":false}"#,
        )
        .unwrap();
        finished.verify("42", false).unwrap();
        assert!(finished.verify("41", false).is_err());
        assert!(finished.verify("42", true).is_err());

        let promoted: KanbanPromoteAck = serde_json::from_str(
            r#"{"ok":true,"action":"promote","task_id":42,"from_status":"review","status":"done","promoted":true,"blocker":null}"#,
        )
        .unwrap();
        promoted.verify("42").unwrap();
        assert!(promoted.verify("41").is_err());

        let blocked: KanbanPromoteAck = serde_json::from_str(
            r#"{"ok":false,"action":"promote","task_id":42,"from_status":"review","status":"review","promoted":false,"blocker":"tests failing"}"#,
        )
        .unwrap();
        assert_eq!(blocked.verify("42").unwrap_err(), "tests failing");
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

        // Raw probes in this region are read-only views: Dream day,
        // Permissions matrix, Memory graph, and two WAL inspectors.
        assert_eq!(callbacks.matches("run_neothd_probe(").count(), 5);
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

        let wave8_start = source
            .find("Wave 8 — C2 permissions matrix + A4 kanban context menu")
            .unwrap();
        let wave8_end = source[wave8_start..]
            .find("H2 — Memory graph callbacks")
            .map(|offset| wave8_start + offset)
            .unwrap();
        let wave8 = &source[wave8_start..wave8_end];
        assert_eq!(
            wave8.matches("run_neothd_probe(").count(),
            1,
            "only the read-only permissions matrix may use the probe boundary"
        );
        assert!(wave8.contains("run_neothd_probe(&[\"permissions\", \"show\""));
        for action in [
            "Permission set",
            "Permission clear",
            "Kanban move",
            "Kanban assign",
        ] {
            assert!(
                wave8.contains(&format!("\"{action}\"")),
                "missing typed Wave 8 action: {action}"
            );
        }
        assert_eq!(wave8.matches("run_neothd_json_action::<").count(), 4);
    }

    #[test]
    fn every_kanban_mutation_callback_uses_a_typed_receipt() {
        let source = include_str!("main.rs");
        assert_eq!(
            source.matches("window.on_kanban_").count(),
            11,
            "new Kanban callbacks must be classified as read-only or typed mutations"
        );
        for read_only in [
            "window.on_kanban_refresh_clicked",
            "window.on_kanban_copy_task_id",
            "window.on_kanban_task_selected",
            "window.on_kanban_session_selected",
        ] {
            assert!(
                source.contains(read_only),
                "missing read-only callback {read_only}"
            );
        }

        let spec_start = source.find("GOLD-ADAPT-AOS-06 — New-Spec pane").unwrap();
        let spec_end = source[spec_start..]
            .find("GOLD-ADAPT-ODY-03 — attach/remove handlers")
            .map(|offset| spec_start + offset)
            .unwrap();
        let spec = &source[spec_start..spec_end];
        assert!(spec.contains("run_neothd_json_action::<gui_action::KanbanAddAck>"));
        assert!(spec.contains("ack.verify(&title, \"feature\")"));
        assert!(spec.contains("request_kanban_refresh(&weak)"));
        for unchecked in ["spawn_neothd_plain", ".output()", "run_neothd_probe("] {
            assert!(
                !spec.contains(unchecked),
                "spec-create regressed to unchecked boundary: {unchecked}"
            );
        }

        let wave8_start = source
            .find("Wave 8 — C2 permissions matrix + A4 kanban context menu")
            .unwrap();
        let wave8_end = source[wave8_start..]
            .find("H2 — Memory graph callbacks")
            .map(|offset| wave8_start + offset)
            .unwrap();
        let wave8 = &source[wave8_start..wave8_end];
        for receipt in ["KanbanMoveAck", "KanbanAssignAck"] {
            assert!(wave8.contains(receipt), "missing Wave 8 receipt {receipt}");
        }

        let legacy_start = source
            .find("Step 6 (2026-05-20): operator action handlers")
            .unwrap();
        let legacy_end = source[legacy_start..]
            .find("Step 5 (2026-05-20): task-card click handler")
            .map(|offset| legacy_start + offset)
            .unwrap();
        let legacy = &source[legacy_start..legacy_end];
        assert_eq!(legacy.matches("run_neothd_json_action::<").count(), 5);
        assert_eq!(legacy.matches("request_kanban_refresh(&weak)").count(), 5);
        for receipt in [
            "KanbanMoveAck",
            "KanbanPromoteAck",
            "KanbanCommentAck",
            "KanbanAssignAck",
            "KanbanFinishAck",
        ] {
            assert!(legacy.contains(receipt), "missing legacy receipt {receipt}");
        }
        for unchecked in ["spawn_neothd_plain", ".output()", "run_neothd_probe("] {
            assert!(
                !legacy.contains(unchecked),
                "legacy Kanban mutation regressed to unchecked boundary: {unchecked}"
            );
        }
    }
}
