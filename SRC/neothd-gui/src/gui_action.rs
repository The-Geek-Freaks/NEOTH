//! Fail-closed subprocess boundary for GUI-triggered CLI actions.
//!
//! GUI callbacks must not infer success from human-readable stdout. Every
//! mutation crosses this boundary, which requires both a successful process
//! exit and a typed JSON acknowledgement before the UI may report success or
//! refresh dependent state.

use std::path::Path;
use std::process::{Command, Output};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

const MAX_DIAGNOSTIC_CHARS: usize = 400;

pub struct JsonReceipt<T> {
    pub acknowledgement: T,
    pub stderr: Option<String>,
}

/// Exact `neoth mcp call --output json` wire acknowledgement. MCP reports
/// tool-level failures inside an otherwise valid JSON-RPC response, so the GUI
/// must verify `isError` in addition to the child process exit status.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpToolCallAck {
    pub content: Vec<serde_json::Value>,
    #[serde(rename = "isError")]
    pub is_error: bool,
}

impl McpToolCallAck {
    pub fn verify_success(&self) -> Result<(), String> {
        if self.is_error {
            return Err("MCP tool reported an execution failure".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // Keep the complete status wire shape fail-closed as it evolves.
pub struct ClusterStatusAck {
    pub mode: String,
    pub policy: String,
    pub peer_count: usize,
    pub conflict_count: usize,
    pub operator_id: String,
    pub node_id: String,
    pub cluster_name: Option<String>,
    pub cluster_passphrase_set: bool,
    pub cluster_identity_configured: bool,
    pub cluster_enabled: bool,
    pub restart_required: bool,
    pub transport_active: bool,
    pub transport: String,
    pub listen_port: u16,
    pub mdns_enabled: bool,
    pub trusted_ssids: Vec<String>,
    pub peers: Vec<ClusterPeerAck>,
    pub gossip: ClusterGossipAck,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterPeerAck {
    pub id: String,
    pub label: String,
    pub last_seen: String,
    pub last_seen_unix: i64,
    pub reachable: bool,
}

impl ClusterStatusAck {
    pub fn verify(&self) -> Result<(), String> {
        if self.peer_count != self.peers.len() {
            return Err(format!(
                "cluster status reports {} peers but returned {} peer rows",
                self.peer_count,
                self.peers.len()
            ));
        }
        let mut peer_ids = std::collections::HashSet::with_capacity(self.peers.len());
        for peer in &self.peers {
            if peer.id.trim().is_empty()
                || peer.label.trim().is_empty()
                || peer.last_seen.trim().is_empty()
            {
                return Err("cluster status returned an incomplete peer identity".into());
            }
            if !peer_ids.insert(peer.id.as_str()) {
                return Err(format!(
                    "cluster status returned duplicate peer `{}`",
                    peer.id
                ));
            }
            if peer.reachable && peer.last_seen_unix <= 0 {
                return Err(format!(
                    "cluster status marked peer `{}` reachable without a durable last-seen time",
                    peer.id
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterConflictListAck {
    pub unresolved_count: usize,
    pub include_resolved: bool,
    pub conflicts: Vec<ClusterConflictAck>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterConflictAck {
    pub id: i64,
    pub content_id: String,
    pub incumbent_origin: String,
    pub incoming_origin: String,
    pub incumbent_sha256: String,
    pub incoming_sha256: String,
    pub policy: String,
    pub observed_at: i64,
    pub resolved_at: Option<i64>,
    pub preferred_origin: Option<String>,
}

impl ClusterConflictListAck {
    pub fn verify_unresolved(&self) -> Result<(), String> {
        if self.include_resolved {
            return Err("cluster returned forensic history instead of unresolved conflicts".into());
        }
        if self.unresolved_count < self.conflicts.len() {
            return Err("cluster unresolved count is smaller than its returned rows".into());
        }
        let mut row_ids = std::collections::HashSet::with_capacity(self.conflicts.len());
        for conflict in &self.conflicts {
            if conflict.id <= 0 || !row_ids.insert(conflict.id) {
                return Err("cluster returned a missing or duplicate conflict row id".into());
            }
            if conflict.resolved_at.is_some() || conflict.preferred_origin.is_some() {
                return Err(format!(
                    "cluster returned resolved state for unresolved conflict `{}`",
                    conflict.content_id
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterConflictResolveAck {
    pub operation: String,
    pub content_id: String,
    pub preferred_origin: String,
    pub resolved_count: usize,
    pub unresolved_remaining: usize,
}

impl ClusterConflictResolveAck {
    pub fn verify(&self, content_id: &str, preferred_origin: &str) -> Result<(), String> {
        if self.operation != "cluster.conflicts.resolve"
            || self.content_id != content_id
            || self.preferred_origin != preferred_origin
            || self.resolved_count == 0
        {
            return Err("cluster conflict receipt does not match the requested decision".into());
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterMdnsAck {
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterPolicyAck {
    pub announce_on_untrusted_wifi: bool,
    pub trusted_ssids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterGossipAck {
    pub replicate_raw_ingress: bool,
    pub replay_budget_days: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterSnapshotAck {
    pub name: Option<String>,
    pub enabled: bool,
    pub transport: String,
    pub peers: Vec<String>,
    pub mdns: ClusterMdnsAck,
    pub policy: ClusterPolicyAck,
    pub gossip: ClusterGossipAck,
    pub listen_port: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterConfigureAck {
    pub operation: String,
    pub path: String,
    pub reload_requested: bool,
    pub reload_error: Option<String>,
    pub restart_required: bool,
    pub cluster_passphrase_set: bool,
    pub cluster: ClusterSnapshotAck,
}

pub struct ExpectedClusterConfig<'a> {
    pub name: Option<&'a str>,
    pub enabled: bool,
    pub transport: &'a str,
    pub peers: &'a [String],
    pub mdns_enabled: bool,
    pub announce_on_untrusted_wifi: bool,
    pub trusted_ssids: &'a [String],
    pub replicate_raw_ingress: bool,
    pub replay_budget_days: u32,
    pub listen_port: u16,
    /// `Some(true)` when the submitted operation requires a usable secret;
    /// `None` when the GUI intentionally left the existing store untouched.
    pub cluster_passphrase_set: Option<bool>,
}

impl ClusterConfigureAck {
    pub fn verify(
        &self,
        expected: &ExpectedClusterConfig<'_>,
        expected_path: &Path,
    ) -> Result<(), String> {
        require_action(&self.operation, "cluster.configure")?;
        require_config_path(&self.path, expected_path)?;
        if self.reload_requested == self.reload_error.is_some() {
            return Err(
                "cluster acknowledgement has inconsistent reload_requested/reload_error fields"
                    .to_string(),
            );
        }
        let checks = [
            (
                self.cluster.name.as_deref() == expected.name,
                "cluster.name",
            ),
            (self.cluster.enabled == expected.enabled, "cluster.enabled"),
            (
                self.cluster.transport == expected.transport,
                "cluster.transport",
            ),
            (
                self.cluster.peers.as_slice() == expected.peers,
                "cluster.peers",
            ),
            (
                self.cluster.mdns.enabled == expected.mdns_enabled,
                "cluster.mdns.enabled",
            ),
            (
                self.cluster.policy.announce_on_untrusted_wifi
                    == expected.announce_on_untrusted_wifi,
                "cluster.policy.announce_on_untrusted_wifi",
            ),
            (
                self.cluster.policy.trusted_ssids.as_slice() == expected.trusted_ssids,
                "cluster.policy.trusted_ssids",
            ),
            (
                self.cluster.gossip.replicate_raw_ingress == expected.replicate_raw_ingress,
                "cluster.gossip.replicate_raw_ingress",
            ),
            (
                self.cluster.gossip.replay_budget_days == expected.replay_budget_days,
                "cluster.gossip.replay_budget_days",
            ),
            (
                self.cluster.listen_port == expected.listen_port,
                "cluster.listen_port",
            ),
        ];
        if let Some((_, field)) = checks.into_iter().find(|(matches, _)| !matches) {
            return Err(format!(
                "cluster acknowledgement does not match submitted `{field}`"
            ));
        }
        if let Some(expected_set) = expected.cluster_passphrase_set
            && self.cluster_passphrase_set != expected_set
        {
            return Err(
                "cluster acknowledgement does not match required `cluster_passphrase_set`"
                    .to_string(),
            );
        }
        Ok(())
    }
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

/// Execute a typed mutation while sending secret material only over the
/// child's private stdin. The caller-owned buffer is zeroed immediately after
/// the write attempt, before waiting for or decoding the acknowledgement.
pub fn run_json_with_private_stdin<T>(
    command: &mut Command,
    action: &str,
    stdin_body: &mut [u8],
) -> Result<T, String>
where
    T: DeserializeOwned,
{
    use std::io::Write as _;
    use std::process::Stdio;

    let child_result = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child_result {
        Ok(child) => child,
        Err(error) => {
            stdin_body.fill(0);
            return Err(format!("could not start {action}: {error}"));
        }
    };
    let write_result = child
        .stdin
        .take()
        .ok_or_else(|| format!("could not open private stdin for {action}"))
        .and_then(|mut stdin| {
            stdin
                .write_all(stdin_body)
                .map_err(|error| format!("could not send private input for {action}: {error}"))
        });
    stdin_body.fill(0);
    if let Err(error) = write_result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("could not wait for {action}: {error}"))?;
    decode_json_output(&output, action)
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
    // R4-09 error-UX: pick the first line that is meaningful to a NON-technical
    // operator after scrubbing internal noise (panic headers, anyhow chain
    // continuations, absolute file paths, redundant "Error:" prefixes). If
    // nothing survives, point at Doctor instead of dumping a stack trace.
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    stderr
        .lines()
        .chain(stdout.lines())
        .filter_map(scrub_diagnostic)
        .next()
        .unwrap_or_else(|| "NEOTH reported an error — run neoth doctor for details.".to_string())
}

/// Turn one raw CLI stderr/stdout line into an operator-safe message, or `None`
/// if the line is pure internal noise (panic header, anyhow "caused by:" chain
/// continuation, or empty after scrubbing).
fn scrub_diagnostic(line: &str) -> Option<String> {
    let mut s = line.trim();
    // The caller's format string already names the action → drop the prefix.
    for p in ["Error: ", "error: ", "ERROR: "] {
        if let Some(rest) = s.strip_prefix(p) {
            s = rest.trim();
        }
    }
    // A Rust panic header / anyhow chain continuation is never user-actionable.
    if (s.starts_with("thread '") && s.contains("panicked"))
        || s.starts_with("caused by:")
        || s.is_empty()
    {
        return None;
    }
    let scrubbed = redact_windows_paths(s);
    let scrubbed = scrubbed.trim();
    if scrubbed.is_empty() {
        None
    } else {
        Some(scrubbed.chars().take(MAX_DIAGNOSTIC_CHARS).collect())
    }
}

/// Replace absolute Windows paths (`X:\…` / `X:/…`) with `<path>` so the GUI
/// never leaks internal file layout into a user-facing toast.
fn redact_windows_paths(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        if i + 2 < chars.len()
            && chars[i].is_ascii_alphabetic()
            && chars[i + 1] == ':'
            && (chars[i + 2] == '\\' || chars[i + 2] == '/')
        {
            out.push_str("<path>");
            i += 3;
            while i < chars.len() && !chars[i].is_whitespace() {
                i += 1;
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
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

fn require_config_path(actual: &str, expected_path: &Path) -> Result<(), String> {
    if actual.trim().is_empty() {
        return Err("acknowledgement is missing its config path".to_string());
    }
    let actual = std::path::absolute(actual).map_err(|error| {
        format!("could not normalize acknowledged config path `{actual}`: {error}")
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
        require_config_path(&self.path, expected_path)
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

/// I13 — `neoth jobs --run "<command>" --label <l> --output json` ack.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BgRunAck {
    pub action: String,
    pub started: bool,
    pub id: String,
    pub pid: u32,
    pub log_path: String,
}

impl BgRunAck {
    pub fn verify(&self) -> Result<(), String> {
        if self.action != "jobs_run" {
            Err(format!(
                "Background-run acknowledgement has wrong action `{}`",
                self.action
            ))
        } else if !self.started || self.id.trim().is_empty() {
            Err("Background job did not confirm a started id".to_string())
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
    fn mcp_tool_error_is_a_failed_typed_receipt() {
        let success = decode_json_output::<McpToolCallAck>(
            &output(
                0,
                r#"{"content":[{"type":"text","text":"done"}],"isError":false}"#,
                "",
            ),
            "MCP call",
        )
        .unwrap();
        success.verify_success().unwrap();

        let tool_error = decode_json_output::<McpToolCallAck>(
            &output(
                0,
                r#"{"content":[{"type":"text","text":"denied"}],"isError":true}"#,
                "",
            ),
            "MCP call",
        )
        .unwrap();
        assert!(tool_error.verify_success().is_err());
        assert!(
            decode_json_output::<McpToolCallAck>(&output(0, r#"{"content":[]}"#, ""), "MCP call",)
                .is_err(),
            "missing isError must fail closed"
        );
        assert!(
            decode_json_output::<McpToolCallAck>(
                &output(0, r#"{"content":[],"isError":false,"unexpected":true}"#, "",),
                "MCP call",
            )
            .is_err(),
            "uncontracted MCP fields must fail closed"
        );
    }

    #[test]
    fn mcp_gui_callback_cannot_infer_success_from_exit_status() {
        let source = include_str!("main.rs");
        let start = source.find("C4 — MCP call:").expect("MCP callback marker");
        let end = source[start..]
            .find("Research P0 — hooks probe")
            .map(|offset| start + offset)
            .expect("MCP callback end marker");
        let callback = &source[start..end];
        assert!(callback.contains("run_neothd_json_action::<gui_action::McpToolCallAck>"));
        assert!(callback.contains("acknowledgement.verify_success()?"));
        for unchecked in ["spawn_neothd_plain", ".output()", "status.success()"] {
            assert!(
                !callback.contains(unchecked),
                "MCP callback regressed to unchecked boundary: {unchecked}"
            );
        }
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

    #[test]
    fn cluster_configure_receipt_binds_every_submitted_field_and_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        let peers = vec!["peer,one".to_string(), " peer two ".to_string()];
        let ssids = vec!["home,lab".to_string(), "  exact wifi  ".to_string()];
        let raw = format!(
            r#"{{"operation":"cluster.configure","path":{},"reload_requested":true,"reload_error":null,"restart_required":true,"cluster_passphrase_set":true,"cluster":{{"name":"studio","enabled":true,"transport":"peeroxide","peers":["peer,one"," peer two "],"mdns":{{"enabled":false}},"policy":{{"announce_on_untrusted_wifi":false,"trusted_ssids":["home,lab","  exact wifi  "]}},"gossip":{{"replicate_raw_ingress":true,"replay_budget_days":14}},"listen_port":49738}}}}"#,
            serde_json::to_string(&path.display().to_string()).unwrap()
        );
        let ack: ClusterConfigureAck = serde_json::from_str(&raw).unwrap();
        let expected = ExpectedClusterConfig {
            name: Some("studio"),
            enabled: true,
            transport: "peeroxide",
            peers: &peers,
            mdns_enabled: false,
            announce_on_untrusted_wifi: false,
            trusted_ssids: &ssids,
            replicate_raw_ingress: true,
            replay_budget_days: 14,
            listen_port: 49738,
            cluster_passphrase_set: Some(true),
        };
        ack.verify(&expected, &path).unwrap();

        let mut wrong = expected;
        wrong.listen_port = 49739;
        assert!(ack.verify(&wrong, &path).is_err());
        assert!(
            serde_json::from_str::<ClusterConfigureAck>(&raw.replacen(
                "\"cluster\":{",
                "\"unexpected\":1,\"cluster\":{",
                1,
            ))
            .is_err(),
            "cluster receipts must reject uncontracted fields"
        );
    }

    #[test]
    fn cluster_conflict_resolution_receipt_is_exact_and_fail_closed() {
        let raw = r#"{"operation":"cluster.conflicts.resolve","content_id":"memory:abc","preferred_origin":"peer-a","resolved_count":2,"unresolved_remaining":0}"#;
        let ack: ClusterConflictResolveAck = serde_json::from_str(raw).unwrap();
        ack.verify("memory:abc", "peer-a").unwrap();
        assert!(ack.verify("memory:other", "peer-a").is_err());
        assert!(ack.verify("memory:abc", "peer-b").is_err());
        assert!(
            serde_json::from_str::<ClusterConflictResolveAck>(&raw.replacen(
                "\"resolved_count\":2",
                "\"resolved_count\":0",
                1
            ))
            .unwrap()
            .verify("memory:abc", "peer-a")
            .is_err()
        );
        assert!(
            serde_json::from_str::<ClusterConflictResolveAck>(&raw.replacen(
                "}",
                ",\"unexpected\":true}",
                1
            ))
            .is_err()
        );
    }

    #[test]
    fn cluster_read_receipts_reject_inconsistent_peer_and_conflict_rows() {
        let status_raw = r#"{
            "mode":"cluster","policy":"trusted","peer_count":1,"conflict_count":1,
            "operator_id":"operator","node_id":"node","cluster_name":"studio",
            "cluster_passphrase_set":true,"cluster_identity_configured":true,
            "cluster_enabled":true,"restart_required":false,"transport_active":true,
            "transport":"peeroxide","listen_port":49738,"mdns_enabled":true,
            "trusted_ssids":[],
            "peers":[{"id":"peer-a","label":"A","last_seen":"1s ago","last_seen_unix":1,"reachable":true}],
            "gossip":{"replicate_raw_ingress":false,"replay_budget_days":14}
        }"#;
        let status: ClusterStatusAck = serde_json::from_str(status_raw).unwrap();
        status.verify().unwrap();
        let wrong_count: ClusterStatusAck =
            serde_json::from_str(&status_raw.replacen("\"peer_count\":1", "\"peer_count\":2", 1))
                .unwrap();
        assert!(wrong_count.verify().is_err());
        let impossible_reachable: ClusterStatusAck = serde_json::from_str(&status_raw.replacen(
            "\"last_seen_unix\":1",
            "\"last_seen_unix\":0",
            1,
        ))
        .unwrap();
        assert!(impossible_reachable.verify().is_err());

        let conflicts_raw = r#"{
            "unresolved_count":1,"include_resolved":false,
            "conflicts":[{"id":7,"content_id":"memory:abc","incumbent_origin":"peer-a",
            "incoming_origin":"peer-b","incumbent_sha256":"aa","incoming_sha256":"bb",
            "policy":"manual","observed_at":1,"resolved_at":null,"preferred_origin":null}]
        }"#;
        let conflicts: ClusterConflictListAck = serde_json::from_str(conflicts_raw).unwrap();
        conflicts.verify_unresolved().unwrap();
        let resolved: ClusterConflictListAck = serde_json::from_str(&conflicts_raw.replacen(
            "\"resolved_at\":null",
            "\"resolved_at\":2",
            1,
        ))
        .unwrap();
        assert!(resolved.verify_unresolved().is_err());
    }

    #[test]
    fn cluster_gui_apply_has_no_direct_yaml_mutation_escape_hatch() {
        let source = include_str!("main.rs");
        let start = source
            .find("C6 — complete cluster desired state")
            .expect("cluster callback marker");
        let end = source[start..]
            .find("C3 — operator identity")
            .map(|offset| start + offset)
            .expect("cluster callback end marker");
        let callback = &source[start..end];
        assert!(callback.contains("ClusterConfigureAck"));
        assert!(callback.contains("acknowledgement.verify(&expected, &expected_path)"));
        assert!(callback.contains("run_json_with_private_stdin"));
        assert!(callback.contains("gui_action::run_json(&mut command"));
        assert!(callback.contains("FREEDOM_WRITE_LOCK"));
        assert!(callback.contains("CLUSTER_UI_REVISION.fetch_add"));
        for unchecked in [
            "set_nested_in_freedom",
            "set_cluster_mdns_enabled_in_freedom",
            "std::fs::write",
            "run_neothd_probe(",
        ] {
            assert!(
                !callback.contains(unchecked),
                "cluster mutation regressed to unchecked boundary: {unchecked}"
            );
        }
    }

    #[test]
    fn scrub_diagnostic_strips_noise_and_paths() {
        // Panic header + anyhow chain continuation + empty → dropped.
        assert_eq!(
            super::scrub_diagnostic("thread 'main' panicked at 'boom'"),
            None
        );
        assert_eq!(super::scrub_diagnostic("caused by: io error"), None);
        assert_eq!(super::scrub_diagnostic("   "), None);
        // "Error:" prefix dropped; a real message survives.
        assert_eq!(
            super::scrub_diagnostic("Error: provider timeout"),
            Some("provider timeout".to_string())
        );
        // Absolute Windows path redacted so internal layout never reaches a toast.
        assert_eq!(
            super::scrub_diagnostic("failed to read C:\\Users\\x\\.neoth\\freedom.yaml now"),
            Some("failed to read <path> now".to_string())
        );
    }
}
