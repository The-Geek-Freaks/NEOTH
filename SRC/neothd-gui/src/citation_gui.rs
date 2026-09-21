//! W155 — fail-closed GUI boundary for explicit citation lookups.
//!
//! This module owns no provider, URL, cache, or browser capability.  Its only
//! input is the JSON result from `neoth citation lookup` for a frozen operator
//! claim.  It reconstructs the core result and asks the core to validate the
//! claim-to-record binding again before a chip or detail can reach Slint.
//!
//! `main.rs` deliberately registers this module only after the W153 child
//! command contract is published.  Keeping this boundary standalone prevents
//! an unverified Markdown link, an old turn, or a late child result from being
//! treated as citation authority in the meantime.

use neothd::tools::citation_lookup::{
    CitationDisplay, CitationLookupResult, CitationLookupState, CitationProvider, CitationQuery,
    CitationRecord, ClaimCitationBinding, LookupSource, MAX_CLAIM_BYTES, RecordProvenance,
    RecordSource,
};
use serde::Deserialize;
use std::{
    io::{Read as _, Write as _},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroize as _;

const MAX_STATUS_CHARS: usize = 240;
const MAX_GUI_REQUEST_ID_BYTES: usize = 128;
const MAX_GUI_TOKEN_BYTES: usize = 256;
const CITATION_CHILD_TIMEOUT: Duration = Duration::from_secs(10);
const CITATION_CHILD_STDOUT_CAP_BYTES: usize = 512 * 1024;
const CITATION_CHILD_STDERR_CAP_BYTES: usize = 32 * 1024;
const CITATION_CHILD_DRAIN_GRACE: Duration = Duration::from_millis(250);

/// Cancellation is retained by the citation callback flow. It owns only the
/// direct GUI child lifecycle; platform process-tree containment belongs to
/// the general trusted-probe supervisor, whose fixed dashboard argv contract
/// deliberately cannot accept citation commands.
#[derive(Clone, Debug, Default)]
pub struct CitationGuiChildCancellation {
    cancelled: Arc<AtomicBool>,
}

impl CitationGuiChildCancellation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// The only three provider choices exposed by the native panel.  The index is
/// converted to this closed enum before a child command is constructed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CitationGuiProvider {
    Crossref,
    OpenAlex,
    SemanticScholar,
}

impl CitationGuiProvider {
    pub const LABELS: [&str; 3] = ["Crossref", "OpenAlex", "Semantic Scholar"];

    pub fn from_index(index: i32) -> Result<Self, String> {
        match index {
            0 => Ok(Self::Crossref),
            1 => Ok(Self::OpenAlex),
            2 => Ok(Self::SemanticScholar),
            _ => Err("citation provider selection is invalid".into()),
        }
    }

    pub const fn as_core(self) -> CitationProvider {
        match self {
            Self::Crossref => CitationProvider::Crossref,
            Self::OpenAlex => CitationProvider::OpenAlex,
            Self::SemanticScholar => CitationProvider::SemanticScholar,
        }
    }

    pub const fn wire_name(self) -> &'static str {
        self.as_core().wire_name()
    }

    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Crossref => "Crossref",
            Self::OpenAlex => "OpenAlex",
            Self::SemanticScholar => "Semantic Scholar",
        }
    }
}

/// A frozen explicit request.  The caller builds the CLI arguments from this
/// exact object; it must never derive `claim` from a chat transcript or model
/// Markdown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CitationGuiRequest {
    pub claim: String,
    pub doi: String,
    pub provider: CitationGuiProvider,
    pub offline: bool,
}

impl CitationGuiRequest {
    pub fn new(
        claim: String,
        doi: String,
        provider_index: i32,
        offline: bool,
    ) -> Result<Self, String> {
        validate_explicit_claim(&claim)?;
        let provider = CitationGuiProvider::from_index(provider_index)?;
        // Share the core DOI normalization/rejection path before launching a
        // child.  This only validates input; it neither authorizes nor starts
        // any provider request.
        let query = CitationQuery::new(provider.as_core(), &doi)
            .map_err(|_| "citation DOI is invalid".to_string())?;
        Ok(Self {
            claim,
            doi: query.doi,
            provider,
            offline,
        })
    }

    /// Stable, argument-safe child command fragment for the existing
    /// `neothd_json_command` helper.  There is intentionally no URL argument.
    pub fn command_args(&self) -> Vec<&str> {
        let mut args = vec![
            "citation",
            "lookup",
            "--claim",
            self.claim.as_str(),
            "--doi",
            self.doi.as_str(),
            "--provider",
            self.provider.wire_name(),
        ];
        if self.offline {
            args.push("--offline");
        }
        args
    }

    /// Exact hidden preflight command. The opaque id is bound by Core to this
    /// normalized request; no secret material is included in argv.
    pub fn preflight_command_args<'a>(
        &'a self,
        request_id: &'a str,
    ) -> Result<Vec<&'a str>, String> {
        validate_gui_request_id(request_id)?;
        let mut args = vec![
            "citation",
            "gui-preflight",
            "--claim",
            self.claim.as_str(),
            "--doi",
            self.doi.as_str(),
            "--provider",
            self.provider.wire_name(),
            "--request-id",
            request_id,
        ];
        if self.offline {
            args.push("--offline");
        }
        Ok(args)
    }

    /// Exact hidden one-use decision command. Its challenge is written only
    /// through the caller's private stdin pipe.
    pub fn decision_command_args<'a>(
        &'a self,
        request_id: &'a str,
        approve: bool,
    ) -> Result<Vec<&'a str>, String> {
        validate_gui_request_id(request_id)?;
        Ok(vec![
            "citation",
            "gui-decide",
            "--claim",
            self.claim.as_str(),
            "--doi",
            self.doi.as_str(),
            "--provider",
            self.provider.wire_name(),
            "--request-id",
            request_id,
            "--decision",
            if approve { "approve" } else { "deny" },
            "--approval-stdin",
        ])
    }

    /// Exact GUI final-lookup command. A Ready preflight uses the no-proof
    /// route; a confirmation-bound live miss consumes its proof only through
    /// private stdin, never through this argument vector.
    pub fn approved_lookup_command_args<'a>(
        &'a self,
        request_id: &'a str,
        requires_proof: bool,
    ) -> Result<Vec<&'a str>, String> {
        validate_gui_request_id(request_id)?;
        let mut args = vec![
            "citation",
            "lookup",
            "--claim",
            self.claim.as_str(),
            "--doi",
            self.doi.as_str(),
            "--provider",
            self.provider.wire_name(),
            "--request-id",
            request_id,
        ];
        if requires_proof {
            args.push("--gui-approval-stdin");
        }
        Ok(args)
    }
}

/// A parsed GUI-only preflight. Challenge/proof values remain zeroizing and
/// never become Slint state, a status string, debug output, or an argv item.
pub enum CitationGuiPreflight {
    CacheHit,
    Offline,
    Ready,
    Denied,
    ConfirmationRequired {
        challenge_token: zeroize::Zeroizing<String>,
        expires_unix: u64,
        request_key_sha256: String,
    },
}

pub enum CitationGuiDecision {
    Approved {
        proof_token: zeroize::Zeroizing<String>,
    },
    Denied,
}

pub fn parse_gui_preflight(
    json: &str,
    request: &CitationGuiRequest,
    request_id: &str,
) -> Result<CitationGuiPreflight, String> {
    validate_gui_request_id(request_id)?;
    let mut wire: CitationGuiPreflightWire = serde_json::from_str(json)
        .map_err(|_| "citation preflight returned an invalid typed result".to_string())?;
    if wire.kind != "citation_gui_preflight" {
        zeroize_optional_token(&mut wire.challenge_token);
        return Err("citation preflight returned another receipt kind".into());
    }
    let query = core_query(request)?;
    if wire.request_key_sha256 != query.request_key_sha256()
        || !is_lower_sha256(&wire.request_key_sha256)
    {
        zeroize_optional_token(&mut wire.challenge_token);
        return Err("citation preflight does not bind the current DOI/provider".into());
    }
    match wire.status.as_str() {
        "cache_hit" => {
            if wire.cache_read == CitationCacheReadStateWire::Hit
                && wire.challenge_token.is_none()
                && wire.expires_unix.is_none()
                && wire.result.is_some()
            {
                Ok(CitationGuiPreflight::CacheHit)
            } else {
                zeroize_optional_token(&mut wire.challenge_token);
                Err("citation cache preflight has an invalid terminal shape".into())
            }
        }
        "offline" => {
            if request.offline
                && wire.cache_read != CitationCacheReadStateWire::Hit
                && wire.challenge_token.is_none()
                && wire.expires_unix.is_none()
                && wire.result.is_some()
            {
                Ok(CitationGuiPreflight::Offline)
            } else {
                zeroize_optional_token(&mut wire.challenge_token);
                Err("citation offline preflight has an invalid terminal shape".into())
            }
        }
        "ready" => {
            if wire.cache_read != CitationCacheReadStateWire::Hit
                && wire.challenge_token.is_none()
                && wire.expires_unix.is_none()
                && wire.result.is_none()
            {
                Ok(CitationGuiPreflight::Ready)
            } else {
                zeroize_optional_token(&mut wire.challenge_token);
                Err("citation ready preflight has an invalid consent shape".into())
            }
        }
        "denied" => {
            if wire.cache_read != CitationCacheReadStateWire::Hit
                && wire.challenge_token.is_none()
                && wire.expires_unix.is_none()
                && wire.result.is_none()
            {
                Ok(CitationGuiPreflight::Denied)
            } else {
                zeroize_optional_token(&mut wire.challenge_token);
                Err("citation denied preflight has an invalid consent shape".into())
            }
        }
        "confirmation_required" => {
            let mut token = wire.challenge_token.take().ok_or_else(|| {
                "citation preflight omitted a bounded private challenge".to_string()
            })?;
            if !valid_private_token(&token) {
                token.zeroize();
                return Err("citation preflight omitted a bounded private challenge".into());
            }
            let expires_unix = wire
                .expires_unix
                .filter(|expires| *expires > 0)
                .ok_or_else(|| {
                    token.zeroize();
                    "citation preflight omitted the approval expiry".to_string()
                })?;
            if wire.cache_read == CitationCacheReadStateWire::Hit || wire.result.is_some() {
                token.zeroize();
                return Err("citation approval preflight carried a terminal lookup result".into());
            }
            Ok(CitationGuiPreflight::ConfirmationRequired {
                challenge_token: zeroize::Zeroizing::new(token),
                expires_unix,
                request_key_sha256: wire.request_key_sha256,
            })
        }
        _ => {
            zeroize_optional_token(&mut wire.challenge_token);
            Err("citation preflight returned an unknown status".into())
        }
    }
}

pub fn parse_gui_decision(json: &str) -> Result<CitationGuiDecision, String> {
    let mut wire: CitationGuiDecisionWire = serde_json::from_str(json)
        .map_err(|_| "citation decision returned an invalid typed result".to_string())?;
    if wire.kind != "citation_gui_decision" {
        zeroize_optional_token(&mut wire.proof_token);
        return Err("citation decision returned another receipt kind".into());
    }
    match wire.status.as_str() {
        "approved" => {
            let mut proof_token = wire.proof_token.take().ok_or_else(|| {
                "citation approval did not return a bounded private proof".to_string()
            })?;
            if !valid_private_token(&proof_token) {
                proof_token.zeroize();
                return Err("citation approval did not return a bounded private proof".into());
            }
            Ok(CitationGuiDecision::Approved {
                proof_token: zeroize::Zeroizing::new(proof_token),
            })
        }
        "denied" if wire.proof_token.is_none() => Ok(CitationGuiDecision::Denied),
        "denied" => {
            zeroize_optional_token(&mut wire.proof_token);
            Err("citation denial returned a private proof".into())
        }
        _ => {
            zeroize_optional_token(&mut wire.proof_token);
            Err("citation decision returned an unknown status".into())
        }
    }
}

pub fn parse_gui_preflight_child_output(
    output: &mut CitationGuiChildOutput,
    request: &CitationGuiRequest,
    request_id: &str,
) -> Result<CitationGuiPreflight, String> {
    if !output.success {
        output.json.zeroize();
        return Err("citation preflight did not complete".into());
    }
    let parsed = parse_gui_preflight(output.json.as_str(), request, request_id);
    output.json.zeroize();
    parsed
}

pub fn parse_gui_decision_child_output(
    output: &mut CitationGuiChildOutput,
) -> Result<CitationGuiDecision, String> {
    if !output.success {
        output.json.zeroize();
        return Err("citation decision did not complete".into());
    }
    let parsed = parse_gui_decision(output.json.as_str());
    output.json.zeroize();
    parsed
}

/// A display-safe chip.  It has no executable URL and carries only the opaque
/// core-issued binding digest used by the detail callback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CitationGuiChip {
    pub claim: String,
    pub provider: String,
    pub source: String,
    pub provider_record_id: String,
    pub binding_sha256: String,
    pub available: bool,
}

/// Detail data stays in-app.  No method in this module opens a browser or
/// copies a provider response/metadata payload to the clipboard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CitationGuiDetail {
    pub claim: String,
    pub provider: String,
    pub provider_record_id: String,
    pub canonical_doi: Option<String>,
    pub title: String,
    pub authors: Vec<String>,
    pub year: Option<u16>,
    pub venue: Option<String>,
    pub source: String,
    pub fetched_at_unix: u64,
    pub binding_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CitationGuiOutcome {
    Found {
        chip: CitationGuiChip,
        detail: CitationGuiDetail,
    },
    Unavailable {
        provider: String,
        state: String,
    },
}

/// Private child output retained only until the UI event loop applies the
/// typed receipt.  The stdout carrier is zeroized after every terminal path.
pub struct CitationGuiChildOutput {
    success: bool,
    json: zeroize::Zeroizing<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CitationGuiPreflightWire {
    kind: String,
    status: String,
    request_key_sha256: String,
    cache_read: CitationCacheReadStateWire,
    result: Option<CitationResultWire>,
    expires_unix: Option<u64>,
    challenge_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CitationGuiDecisionWire {
    kind: String,
    status: String,
    proof_token: Option<String>,
}

/// Retains at most one result for the active explicit request.  A caller must
/// increment the revision and clear the visible chip before spawning a new
/// child.  A result may be applied only once for that exact revision.
#[derive(Default)]
pub struct CitationGuiBindingStore {
    revision: u64,
    historical: bool,
    pending: Option<CitationGuiRequest>,
    active: Option<ActiveCitation>,
}

#[derive(Clone)]
struct ActiveCitation {
    request: CitationGuiRequest,
    result: CitationLookupResult,
    display: CitationDisplay,
}

impl CitationGuiBindingStore {
    /// Starts a fresh explicit lookup and invalidates all former detail chips.
    pub fn begin_lookup(&mut self, request: CitationGuiRequest) -> u64 {
        self.revision = self.revision.wrapping_add(1).max(1);
        self.historical = false;
        self.pending = Some(request);
        self.active = None;
        self.revision
    }

    /// Marks the current chat surface read-only and removes the active binding.
    pub fn set_historical(&mut self, historical: bool) {
        // A surface transition is a generation boundary even when no new
        // lookup starts.  Otherwise a worker released after history selection
        // would still match `revision` and could replace its read-only status.
        self.revision = self.revision.wrapping_add(1).max(1);
        self.historical = historical;
        self.pending = None;
        self.active = None;
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Parse, reconstruct, and apply a child JSON result.  Unknown fields,
    /// stale generations, unavailable-with-display responses, and changed
    /// claims are rejected before any UI state is returned.
    pub fn apply_child_json(
        &mut self,
        revision: u64,
        request: CitationGuiRequest,
        json: &str,
    ) -> Result<CitationGuiOutcome, String> {
        if self.historical {
            return Err("citation lookup is unavailable in retained history".into());
        }
        if revision == 0 || revision != self.revision {
            return Err("citation lookup result is stale".into());
        }
        if self.pending.as_ref() != Some(&request) {
            return Err("citation lookup result does not match the frozen request".into());
        }
        let receipt: CitationLookupReceipt = serde_json::from_str(json)
            .map_err(|_| "citation lookup returned an invalid typed result".to_string())?;
        let outcome = receipt.verify_for(&request)?;
        match &outcome {
            CitationGuiOutcome::Found { .. } => {
                let (result, display) = receipt.into_verified_core(&request)?;
                self.active = Some(ActiveCitation {
                    request,
                    result,
                    display,
                });
            }
            CitationGuiOutcome::Unavailable { .. } => self.active = None,
        }
        // A child result is one-shot.  A replay must start a new explicit
        // lookup rather than mutating the previously bound display.
        self.pending = None;
        Ok(outcome)
    }

    /// Return the retained in-app detail only when the exact active binding can
    /// still be recomputed by core.  No navigation capability is returned.
    pub fn detail_for_click(
        &self,
        revision: u64,
        binding_sha256: &str,
    ) -> Result<CitationGuiDetail, String> {
        if self.historical || revision == 0 || revision != self.revision {
            return Err("citation detail is stale or read-only".into());
        }
        let active = self
            .active
            .as_ref()
            .ok_or_else(|| "citation detail has no active binding".to_string())?;
        if binding_sha256 != active.display.binding_sha256 || !is_lower_sha256(binding_sha256) {
            return Err("citation detail binding does not match the active claim".into());
        }
        let query = core_query(&active.request)?;
        if !active
            .result
            .validate_for_claim(&query, &active.request.claim)
            || active
                .result
                .display_for_claim(&query, &active.request.claim)
                .as_ref()
                != Some(&active.display)
        {
            return Err("citation detail binding no longer validates".into());
        }
        detail_from_display(&active.display)
    }

    /// Execute the already-authorized child command.  A found citation must
    /// exit zero; the W153 CLI deliberately emits a structured unavailable
    /// result with a non-zero exit, which is accepted only for that exact
    /// typed outcome.  This prevents `gui_action::run_json`'s success-only
    /// helper from discarding a useful offline miss while still refusing every
    /// other non-zero child result.
    pub fn run_child(
        &mut self,
        revision: u64,
        request: CitationGuiRequest,
        command: &mut Command,
        cancellation: &CitationGuiChildCancellation,
    ) -> Result<CitationGuiOutcome, String> {
        let mut output = execute_citation_child(command, cancellation)?;
        self.apply_child_output(revision, request, &mut output)
    }

    /// Applies an already-completed child.  Keeping process execution outside
    /// the store lock lets a newer lookup invalidate this revision while an
    /// older child is still blocked.
    pub fn apply_child_output(
        &mut self,
        revision: u64,
        request: CitationGuiRequest,
        output: &mut CitationGuiChildOutput,
    ) -> Result<CitationGuiOutcome, String> {
        let parsed = self.apply_child_json(revision, request, output.json.as_str());
        output.json.zeroize();
        let outcome = parsed?;
        match (&outcome, output.success) {
            (CitationGuiOutcome::Found { .. }, true)
            | (CitationGuiOutcome::Unavailable { .. }, false) => Ok(outcome),
            (CitationGuiOutcome::Found { .. }, false) => {
                self.active = None;
                Err("citation child returned a found result with a failing exit".into())
            }
            (CitationGuiOutcome::Unavailable { .. }, true) => {
                Err("citation child returned unavailable with a successful exit".into())
            }
        }
    }
}

/// Execute one explicit CLI command with a short wall-clock budget and bounded
/// concurrent stream drains. A cancellation, timeout, or stream cap kills and
/// reaps the direct child before this function returns. The caller's flow
/// identity still decides whether a completed receipt may reach the UI.
pub fn execute_citation_child(
    command: &mut Command,
    cancellation: &CitationGuiChildCancellation,
) -> Result<CitationGuiChildOutput, String> {
    execute_citation_child_bounded(command, cancellation, None)
}

/// Send one private challenge/proof only through stdin while retaining the
/// same bounded child lifecycle. The token is zeroized immediately after its
/// write attempt, before any wait or receipt decode.
pub fn execute_citation_child_with_private_stdin(
    command: &mut Command,
    cancellation: &CitationGuiChildCancellation,
    token: &mut zeroize::Zeroizing<String>,
) -> Result<CitationGuiChildOutput, String> {
    execute_citation_child_bounded(command, cancellation, Some(token))
}

struct CitationChildCapture {
    bytes: Vec<u8>,
    exceeded: bool,
}

impl Drop for CitationChildCapture {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

fn execute_citation_child_bounded(
    command: &mut Command,
    cancellation: &CitationGuiChildCancellation,
    mut private_token: Option<&mut zeroize::Zeroizing<String>>,
) -> Result<CitationGuiChildOutput, String> {
    if cancellation.is_cancelled() {
        if let Some(token) = private_token.as_deref_mut() {
            token.zeroize();
        }
        return Err("citation lookup was cancelled".into());
    }
    command
        .stdin(if private_token.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = Instant::now();
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            if let Some(token) = private_token.as_deref_mut() {
                token.zeroize();
            }
            return Err("could not start citation lookup".into());
        }
    };
    if let Some(token) = private_token {
        let write_result = child
            .stdin
            .take()
            .ok_or_else(|| "could not open private citation stdin".to_string())
            .and_then(|mut stdin| {
                stdin
                    .write_all(token.as_bytes())
                    .map_err(|_| "could not send private citation input".to_string())
            });
        token.zeroize();
        if let Err(error) = write_result {
            terminate_and_reap_citation_child(&mut child);
            return Err(error);
        }
    }
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            terminate_and_reap_citation_child(&mut child);
            return Err("could not open citation stdout".into());
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            terminate_and_reap_citation_child(&mut child);
            return Err("could not open citation stderr".into());
        }
    };
    let exceeded = Arc::new(AtomicU8::new(0));
    let (stdout_tx, stdout_rx) = mpsc::sync_channel(1);
    let stdout_exceeded = Arc::clone(&exceeded);
    let stdout_reader = match thread::Builder::new()
        .name("neoth-citation-stdout".into())
        .spawn(move || {
            let _ = stdout_tx.send(drain_capped_citation_stream(
                stdout,
                CITATION_CHILD_STDOUT_CAP_BYTES,
                1,
                stdout_exceeded,
            ));
        }) {
        Ok(reader) => reader,
        Err(_) => {
            terminate_and_reap_citation_child(&mut child);
            return Err("could not start citation stdout reader".into());
        }
    };
    let (stderr_tx, stderr_rx) = mpsc::sync_channel(1);
    let stderr_exceeded = Arc::clone(&exceeded);
    let stderr_reader = match thread::Builder::new()
        .name("neoth-citation-stderr".into())
        .spawn(move || {
            let _ = stderr_tx.send(drain_capped_citation_stream(
                stderr,
                CITATION_CHILD_STDERR_CAP_BYTES,
                2,
                stderr_exceeded,
            ));
        }) {
        Ok(reader) => reader,
        Err(_) => {
            terminate_and_reap_citation_child(&mut child);
            drop(stdout_reader);
            return Err("could not start citation stderr reader".into());
        }
    };

    let status = loop {
        if cancellation.is_cancelled() {
            terminate_and_reap_citation_child(&mut child);
            discard_citation_capture(&stdout_rx);
            discard_citation_capture(&stderr_rx);
            drop(stdout_reader);
            drop(stderr_reader);
            return Err("citation lookup was cancelled".into());
        }
        match exceeded.load(Ordering::Acquire) {
            1 | 2 => {
                terminate_and_reap_citation_child(&mut child);
                discard_citation_capture(&stdout_rx);
                discard_citation_capture(&stderr_rx);
                drop(stdout_reader);
                drop(stderr_reader);
                return Err("citation lookup output exceeded its bounded limit".into());
            }
            _ => {}
        }
        if started.elapsed() >= CITATION_CHILD_TIMEOUT {
            terminate_and_reap_citation_child(&mut child);
            discard_citation_capture(&stdout_rx);
            discard_citation_capture(&stderr_rx);
            drop(stdout_reader);
            drop(stderr_reader);
            return Err("citation lookup timed out".into());
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(_) => {
                terminate_and_reap_citation_child(&mut child);
                discard_citation_capture(&stdout_rx);
                discard_citation_capture(&stderr_rx);
                drop(stdout_reader);
                drop(stderr_reader);
                return Err("could not wait for citation lookup".into());
            }
        }
    };
    let mut stdout = receive_citation_capture(&stdout_rx)?;
    let mut stderr = match receive_citation_capture(&stderr_rx) {
        Ok(capture) => capture,
        Err(error) => {
            stdout.bytes.zeroize();
            return Err(error);
        }
    };
    let _ = stdout_reader.join();
    let _ = stderr_reader.join();
    if stdout.exceeded || stderr.exceeded {
        stdout.bytes.zeroize();
        stderr.bytes.zeroize();
        return Err("citation lookup output exceeded its bounded limit".into());
    }
    citation_child_output(
        status,
        std::mem::take(&mut stdout.bytes),
        std::mem::take(&mut stderr.bytes),
    )
}

fn drain_capped_citation_stream<R: std::io::Read>(
    mut stream: R,
    cap: usize,
    exceeded_stream: u8,
    exceeded: Arc<AtomicU8>,
) -> std::io::Result<CitationChildCapture> {
    let mut bytes = Vec::with_capacity(cap.min(4096));
    let mut buffer = [0_u8; 4096];
    let mut was_exceeded = false;
    loop {
        let read = match stream.read(&mut buffer) {
            Ok(read) => read,
            Err(error) => {
                bytes.zeroize();
                buffer.zeroize();
                return Err(error);
            }
        };
        if read == 0 {
            buffer.zeroize();
            return Ok(CitationChildCapture {
                bytes,
                exceeded: was_exceeded,
            });
        }
        let retained = cap.saturating_sub(bytes.len()).min(read);
        bytes.extend_from_slice(&buffer[..retained]);
        if retained != read {
            was_exceeded = true;
            let _ =
                exceeded.compare_exchange(0, exceeded_stream, Ordering::AcqRel, Ordering::Acquire);
        }
    }
}

fn terminate_and_reap_citation_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn discard_citation_capture(rx: &mpsc::Receiver<std::io::Result<CitationChildCapture>>) {
    if let Ok(Ok(mut capture)) = rx.recv_timeout(CITATION_CHILD_DRAIN_GRACE) {
        capture.bytes.zeroize();
    }
}

fn receive_citation_capture(
    rx: &mpsc::Receiver<std::io::Result<CitationChildCapture>>,
) -> Result<CitationChildCapture, String> {
    match rx.recv_timeout(CITATION_CHILD_DRAIN_GRACE) {
        Ok(Ok(capture)) => Ok(capture),
        Ok(Err(_)) => Err("could not read citation output".into()),
        Err(_) => Err("citation lookup output did not finish".into()),
    }
}

fn citation_child_output(
    status: ExitStatus,
    mut stdout: Vec<u8>,
    mut stderr: Vec<u8>,
) -> Result<CitationGuiChildOutput, String> {
    let success = status.success();
    let json = match String::from_utf8(std::mem::take(&mut stdout)) {
        Ok(json) => zeroize::Zeroizing::new(json),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            stdout.zeroize();
            stderr.zeroize();
            return Err("citation lookup returned non-UTF-8 output".to_string());
        }
    };
    stdout.zeroize();
    stderr.zeroize();
    Ok(CitationGuiChildOutput { success, json })
}

fn validate_explicit_claim(claim: &str) -> Result<(), String> {
    if claim.is_empty()
        || claim.trim() != claim
        || claim.len() > MAX_CLAIM_BYTES
        || claim.chars().any(char::is_control)
    {
        return Err("citation claim must be explicit, trimmed, bounded text".into());
    }
    Ok(())
}

fn validate_gui_request_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_GUI_REQUEST_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err("citation request identity is invalid".into());
    }
    Ok(())
}

fn valid_private_token(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_GUI_TOKEN_BYTES && !value.chars().any(char::is_control)
}

fn zeroize_optional_token(token: &mut Option<String>) {
    if let Some(token) = token {
        token.zeroize();
    }
}

fn core_query(request: &CitationGuiRequest) -> Result<CitationQuery, String> {
    CitationQuery::new(request.provider.as_core(), &request.doi)
        .map_err(|_| "citation request no longer has a valid DOI".to_string())
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn bounded_state(value: &str) -> String {
    value.chars().take(MAX_STATUS_CHARS).collect()
}

fn source_name(source: LookupSource) -> &'static str {
    match source {
        LookupSource::Live => "live",
        LookupSource::Cache => "cache",
    }
}

fn detail_from_display(display: &CitationDisplay) -> Result<CitationGuiDetail, String> {
    if !is_lower_sha256(&display.binding_sha256) {
        return Err("citation display has a noncanonical binding".into());
    }
    Ok(CitationGuiDetail {
        claim: display.claim.clone(),
        provider: display.provider.wire_name().to_string(),
        provider_record_id: display.provider_record_id.clone(),
        canonical_doi: display.canonical_doi.clone(),
        title: display.title.clone(),
        authors: display.authors.clone(),
        year: display.year,
        venue: display.venue.clone(),
        source: source_name(display.source).to_string(),
        fetched_at_unix: display.fetched_at_unix,
        binding_sha256: display.binding_sha256.clone(),
    })
}

fn chip_from_display(display: &CitationDisplay) -> Result<CitationGuiChip, String> {
    if !is_lower_sha256(&display.binding_sha256) {
        return Err("citation display has a noncanonical binding".into());
    }
    Ok(CitationGuiChip {
        claim: display.claim.clone(),
        provider: display.provider.wire_name().to_string(),
        source: source_name(display.source).to_string(),
        provider_record_id: display.provider_record_id.clone(),
        binding_sha256: display.binding_sha256.clone(),
        available: true,
    })
}

// The CLI contract is intentionally mirrored rather than deserializing core
// structs directly: every consumed field is explicit and `deny_unknown_fields`
// prevents a changed CLI schema from being silently interpreted as authority.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CitationLookupReceipt {
    claim: String,
    providers: Vec<CitationProvider>,
    result: CitationResultWire,
    cache_read: CitationCacheReadStateWire,
    cache_write: CitationCacheWriteStateWire,
    attempts: Vec<CitationAttemptWire>,
    display: Option<CitationDisplayWire>,
}

impl CitationLookupReceipt {
    fn verify_for(&self, request: &CitationGuiRequest) -> Result<CitationGuiOutcome, String> {
        validate_explicit_claim(&request.claim)?;
        if self.claim != request.claim {
            return Err("citation child changed the frozen claim".into());
        }
        if self.providers.len() != 1
            || self.providers.first().copied() != Some(request.provider.as_core())
        {
            return Err("citation child selected providers outside the frozen request".into());
        }
        if self.attempts.len() != 1 {
            return Err(
                "citation GUI request must have exactly one bounded provider attempt".into(),
            );
        }
        let attempt = &self.attempts[0];
        if attempt.provider != request.provider.as_core()
            || attempt.doi != request.doi
            || attempt.cache_read != self.cache_read
            || attempt.cache_write != self.cache_write
            || attempt.result.to_core()? != self.result.to_core()?
        {
            return Err("citation child attempt differs from the final typed result".into());
        }
        if request.offline && self.cache_write != CitationCacheWriteStateWire::NotAttempted {
            return Err("offline citation lookup attempted a cache write".into());
        }
        match (&self.result, &self.display) {
            (CitationResultWire::Found { .. }, Some(_)) => {
                let (_, display) = self.into_verified_core(request)?;
                Ok(CitationGuiOutcome::Found {
                    chip: chip_from_display(&display)?,
                    detail: detail_from_display(&display)?,
                })
            }
            (CitationResultWire::Found { .. }, None) => {
                Err("citation child omitted the validated display projection".into())
            }
            (CitationResultWire::Unavailable { provider, state }, None) => {
                if *provider != request.provider.as_core() {
                    return Err("citation unavailable result names another provider".into());
                }
                Ok(CitationGuiOutcome::Unavailable {
                    provider: provider.wire_name().to_string(),
                    state: bounded_state(&state.label()),
                })
            }
            (CitationResultWire::Unavailable { .. }, Some(_)) => {
                Err("unavailable citation result must not carry a display chip".into())
            }
        }
    }

    fn into_verified_core(
        &self,
        request: &CitationGuiRequest,
    ) -> Result<(CitationLookupResult, CitationDisplay), String> {
        let query = core_query(request)?;
        let result = self.result.to_core()?;
        let expected_display = result
            .display_for_claim(&query, &request.claim)
            .ok_or_else(|| "citation result does not validate for the frozen claim".to_string())?;
        if !result.validate_for_claim(&query, &request.claim) {
            return Err("citation result binding is invalid".into());
        }
        let received_display = self
            .display
            .as_ref()
            .ok_or_else(|| "citation child omitted the validated display projection".to_string())?;
        if !received_display.matches(&expected_display) {
            return Err("citation display differs from the core binding projection".into());
        }
        Ok((result, expected_display))
    }
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CitationCacheReadStateWire {
    NotConfigured,
    Hit,
    Miss,
    ReadFailed,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CitationCacheWriteStateWire {
    NotAttempted,
    Stored,
    WriteFailed,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CitationAttemptWire {
    provider: CitationProvider,
    doi: String,
    result: CitationResultWire,
    cache_read: CitationCacheReadStateWire,
    cache_write: CitationCacheWriteStateWire,
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum CitationResultWire {
    Found {
        record: CitationRecordWire,
        binding: ClaimCitationBindingWire,
        source: LookupSource,
    },
    Unavailable {
        provider: CitationProvider,
        state: CitationLookupStateWire,
    },
}

impl CitationResultWire {
    fn to_core(&self) -> Result<CitationLookupResult, String> {
        match self {
            Self::Found {
                record,
                binding,
                source,
            } => Ok(CitationLookupResult::Found {
                record: Box::new(record.to_core()),
                binding: binding.to_core(),
                source: *source,
            }),
            Self::Unavailable { provider, state } => Ok(CitationLookupResult::Unavailable {
                provider: *provider,
                state: state.to_core(),
            }),
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum CitationLookupStateWire {
    OfflineCacheMiss,
    Timeout,
    RateLimited { retry_after_secs: Option<u64> },
    ProviderUnavailable,
    NotFound,
    PermissionDenied,
    InvalidQuery,
}

impl CitationLookupStateWire {
    fn to_core(&self) -> CitationLookupState {
        match self {
            Self::OfflineCacheMiss => CitationLookupState::OfflineCacheMiss,
            Self::Timeout => CitationLookupState::Timeout,
            Self::RateLimited { retry_after_secs } => CitationLookupState::RateLimited {
                retry_after_secs: *retry_after_secs,
            },
            Self::ProviderUnavailable => CitationLookupState::ProviderUnavailable,
            Self::NotFound => CitationLookupState::NotFound,
            Self::PermissionDenied => CitationLookupState::PermissionDenied,
            Self::InvalidQuery => CitationLookupState::InvalidQuery,
        }
    }

    fn label(&self) -> String {
        match self {
            Self::OfflineCacheMiss => "offline_cache_miss".into(),
            Self::Timeout => "timeout".into(),
            Self::RateLimited {
                retry_after_secs: Some(seconds),
            } => {
                format!("rate_limited ({seconds}s)")
            }
            Self::RateLimited {
                retry_after_secs: None,
            } => "rate_limited".into(),
            Self::ProviderUnavailable => "provider_unavailable".into(),
            Self::NotFound => "not_found".into(),
            Self::PermissionDenied => "permission_denied".into(),
            Self::InvalidQuery => "invalid_query".into(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CitationRecordWire {
    schema_version: u16,
    provider: CitationProvider,
    provider_record_id: String,
    canonical_doi: Option<String>,
    title: String,
    authors: Vec<String>,
    year: Option<u16>,
    venue: Option<String>,
    provider_permalink: String,
    fetched_at_unix: u64,
    provenance: RecordProvenanceWire,
}

impl CitationRecordWire {
    fn to_core(&self) -> CitationRecord {
        CitationRecord {
            schema_version: self.schema_version,
            provider: self.provider,
            provider_record_id: self.provider_record_id.clone(),
            canonical_doi: self.canonical_doi.clone(),
            title: self.title.clone(),
            authors: self.authors.clone(),
            year: self.year,
            venue: self.venue.clone(),
            provider_permalink: self.provider_permalink.clone(),
            fetched_at_unix: self.fetched_at_unix,
            provenance: self.provenance.to_core(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordProvenanceWire {
    provider: CitationProvider,
    request_key_sha256: String,
    source: RecordSource,
    fetched_at_unix: u64,
    response_version: Option<String>,
}

impl RecordProvenanceWire {
    fn to_core(&self) -> RecordProvenance {
        RecordProvenance {
            provider: self.provider,
            request_key_sha256: self.request_key_sha256.clone(),
            source: self.source,
            fetched_at_unix: self.fetched_at_unix,
            response_version: self.response_version.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimCitationBindingWire {
    schema_version: u16,
    claim_sha256: String,
    record_fingerprint_sha256: String,
    provider: CitationProvider,
    provider_record_id: String,
    binding_sha256: String,
}

impl ClaimCitationBindingWire {
    fn to_core(&self) -> ClaimCitationBinding {
        ClaimCitationBinding {
            schema_version: self.schema_version,
            claim_sha256: self.claim_sha256.clone(),
            record_fingerprint_sha256: self.record_fingerprint_sha256.clone(),
            provider: self.provider,
            provider_record_id: self.provider_record_id.clone(),
            binding_sha256: self.binding_sha256.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CitationDisplayWire {
    claim: String,
    provider: CitationProvider,
    provider_record_id: String,
    canonical_doi: Option<String>,
    title: String,
    authors: Vec<String>,
    year: Option<u16>,
    venue: Option<String>,
    record_fingerprint_sha256: String,
    provenance: RecordProvenanceWire,
    source: LookupSource,
    fetched_at_unix: u64,
    provider_permalink: String,
    binding_sha256: String,
}

impl CitationDisplayWire {
    fn matches(&self, expected: &CitationDisplay) -> bool {
        self.claim == expected.claim
            && self.provider == expected.provider
            && self.provider_record_id == expected.provider_record_id
            && self.canonical_doi == expected.canonical_doi
            && self.title == expected.title
            && self.authors == expected.authors
            && self.year == expected.year
            && self.venue == expected.venue
            && self.record_fingerprint_sha256 == expected.record_fingerprint_sha256
            && self.provenance.provider == expected.provenance.provider
            && self.provenance.request_key_sha256 == expected.provenance.request_key_sha256
            && self.provenance.source == expected.provenance.source
            && self.provenance.fetched_at_unix == expected.provenance.fetched_at_unix
            && self.provenance.response_version == expected.provenance.response_version
            && self.source == expected.source
            && self.fetched_at_unix == expected.fetched_at_unix
            && self.provider_permalink == expected.provider_permalink
            && self.binding_sha256 == expected.binding_sha256
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found_receipt(request: &CitationGuiRequest) -> String {
        let query = CitationQuery::new(request.provider.as_core(), &request.doi).unwrap();
        let authors = vec!["A. Author".to_string()];
        let record = CitationRecord::new(
            &query,
            &request.doi,
            Some(&request.doi),
            "Bounded citation title",
            &authors,
            Some(2026),
            Some("NEOTH Journal"),
            1,
            None,
        )
        .unwrap();
        let result = CitationLookupResult::from_live(&query, &request.claim, record).unwrap();
        let display = result.display_for_claim(&query, &request.claim).unwrap();
        serde_json::json!({
            "claim": request.claim.clone(),
            "providers": [request.provider.as_core()],
            "result": result.clone(),
            "cache_read": "miss",
            "cache_write": "stored",
            "attempts": [{
                "provider": request.provider.as_core(),
                "doi": request.doi.clone(),
                "result": result,
                "cache_read": "miss",
                "cache_write": "stored",
            }],
            "display": display,
        })
        .to_string()
    }

    #[test]
    fn explicit_request_rejects_model_style_or_untrimmed_claims() {
        assert!(
            CitationGuiRequest::new(" a claim ".into(), "10.1000/example".into(), 0, true).is_err()
        );
        assert!(
            CitationGuiRequest::new("a\nclaim".into(), "10.1000/example".into(), 0, true).is_err()
        );
        assert!(
            CitationGuiRequest::new("a claim".into(), "https://example.test/doi".into(), 0, true)
                .is_err()
        );
    }

    #[test]
    fn provider_indices_are_closed() {
        assert_eq!(
            CitationGuiProvider::from_index(0).unwrap().wire_name(),
            "crossref"
        );
        assert_eq!(
            CitationGuiProvider::from_index(2).unwrap().wire_name(),
            "semantic-scholar"
        );
        assert!(CitationGuiProvider::from_index(3).is_err());
    }

    #[test]
    fn citation_child_policy_is_bounded_and_cancellation_is_shared() {
        assert!(CITATION_CHILD_TIMEOUT > std::time::Duration::from_secs(0));
        assert!(CITATION_CHILD_STDOUT_CAP_BYTES > 0);
        assert!(CITATION_CHILD_STDERR_CAP_BYTES > 0);
        assert!(CITATION_CHILD_DRAIN_GRACE > std::time::Duration::from_secs(0));
        let cancellation = CitationGuiChildCancellation::new();
        let worker = cancellation.clone();
        assert!(!worker.is_cancelled());
        cancellation.cancel();
        assert!(worker.is_cancelled());
    }

    #[test]
    fn gui_preflight_requires_the_current_request_hash_and_nonterminal_cache_state() {
        let request = CitationGuiRequest::new("A claim".into(), "10.1000/example".into(), 0, false)
            .expect("valid GUI request");
        let request_id = "citation-request-123";
        let request_key = core_query(&request)
            .expect("current query")
            .request_key_sha256();
        let confirmation = format!(
            r#"{{"kind":"citation_gui_preflight","status":"confirmation_required","request_key_sha256":"{request_key}","cache_read":"miss","result":null,"expires_unix":1,"challenge_token":"challenge-token"}}"#
        );
        assert!(matches!(
            parse_gui_preflight(&confirmation, &request, request_id),
            Ok(CitationGuiPreflight::ConfirmationRequired { .. })
        ));

        let rebound = confirmation.replace(&request_key, &"0".repeat(64));
        assert!(parse_gui_preflight(&rebound, &request, request_id).is_err());
        let contradictory_hit =
            confirmation.replace("\"cache_read\":\"miss\"", "\"cache_read\":\"hit\"");
        assert!(parse_gui_preflight(&contradictory_hit, &request, request_id).is_err());
    }

    #[test]
    fn gui_decision_receipts_reject_unknown_or_inconsistent_proofs() {
        assert!(matches!(
            parse_gui_decision(
                r#"{"kind":"citation_gui_decision","status":"approved","proof_token":"proof-token"}"#
            ),
            Ok(CitationGuiDecision::Approved { .. })
        ));
        assert!(
            parse_gui_decision(
                r#"{"kind":"citation_gui_decision","status":"denied","proof_token":"proof-token"}"#
            )
            .is_err()
        );
        assert!(
            parse_gui_decision(
                r#"{"kind":"citation_gui_decision","status":"approved","proof_token":null}"#
            )
            .is_err()
        );
        assert!(parse_gui_decision(
            r#"{"kind":"citation_gui_decision","status":"denied","proof_token":null,"extra":true}"#
        )
        .is_err());
    }

    #[test]
    fn gui_command_builders_bind_only_request_data_and_validate_ids() {
        let request = CitationGuiRequest::new("A claim".into(), "10.1000/example".into(), 0, false)
            .expect("valid GUI request");
        let request_id = "citation-request-123";
        let preflight = request
            .preflight_command_args(request_id)
            .expect("valid preflight args");
        let decision = request
            .decision_command_args(request_id, true)
            .expect("valid decision args");
        let ready = request
            .approved_lookup_command_args(request_id, false)
            .expect("valid ready args");
        let confirmed = request
            .approved_lookup_command_args(request_id, true)
            .expect("valid confirmed args");
        assert!(!preflight.iter().any(|arg| *arg == "challenge-token"));
        assert!(!decision.iter().any(|arg| *arg == "challenge-token"));
        assert!(!ready.iter().any(|arg| *arg == "proof-token"));
        assert!(!ready.iter().any(|arg| *arg == "--gui-approval-stdin"));
        assert!(confirmed.iter().any(|arg| *arg == "--gui-approval-stdin"));
        assert!(
            request
                .preflight_command_args("request id with spaces")
                .is_err()
        );
        assert!(
            request
                .decision_command_args(&"x".repeat(129), true)
                .is_err()
        );
    }

    #[test]
    fn stale_or_historical_detail_never_survives() {
        let mut store = CitationGuiBindingStore::default();
        let request =
            CitationGuiRequest::new("A claim".into(), "10.1000/example".into(), 0, true).unwrap();
        let revision = store.begin_lookup(request);
        assert!(store.detail_for_click(revision, &"a".repeat(64)).is_err());
        store.set_historical(true);
        assert!(store.detail_for_click(revision, &"a".repeat(64)).is_err());
    }

    #[test]
    fn typed_unavailable_cannot_carry_a_chip() {
        let request =
            CitationGuiRequest::new("A claim".into(), "10.1000/example".into(), 0, true).unwrap();
        let receipt = r#"{"claim":"A claim","providers":["crossref"],"result":{"status":"unavailable","provider":"crossref","state":{"kind":"offline_cache_miss"}},"cache_read":"miss","cache_write":"not_attempted","attempts":[{"provider":"crossref","doi":"10.1000/example","result":{"status":"unavailable","provider":"crossref","state":{"kind":"offline_cache_miss"}},"cache_read":"miss","cache_write":"not_attempted"}],"display":null}"#;
        let parsed: CitationLookupReceipt = serde_json::from_str(receipt).unwrap();
        assert!(matches!(
            parsed.verify_for(&request),
            Ok(CitationGuiOutcome::Unavailable { .. })
        ));
    }

    #[test]
    fn current_core_bound_result_opens_only_its_own_in_app_detail() {
        let request =
            CitationGuiRequest::new("A claim".into(), "10.1000/example".into(), 0, false).unwrap();
        let mut store = CitationGuiBindingStore::default();
        let revision = store.begin_lookup(request.clone());
        let json = found_receipt(&request);
        let outcome = store.apply_child_json(revision, request, &json).unwrap();
        let CitationGuiOutcome::Found { chip, detail } = outcome else {
            panic!("expected a validated citation chip");
        };
        assert_eq!(detail.binding_sha256, chip.binding_sha256);
        assert_eq!(
            store
                .detail_for_click(revision, &chip.binding_sha256)
                .unwrap(),
            detail
        );
    }

    #[test]
    fn forged_display_binding_and_replayed_child_result_are_rejected() {
        let request =
            CitationGuiRequest::new("A claim".into(), "10.1000/example".into(), 0, false).unwrap();
        let mut forged: serde_json::Value = serde_json::from_str(&found_receipt(&request)).unwrap();
        forged["display"]["binding_sha256"] = serde_json::Value::String("0".repeat(64));
        let mut store = CitationGuiBindingStore::default();
        let revision = store.begin_lookup(request.clone());
        assert!(
            store
                .apply_child_json(revision, request.clone(), &forged.to_string())
                .is_err()
        );

        let fresh = found_receipt(&request);
        assert!(
            store
                .apply_child_json(revision, request.clone(), &fresh)
                .is_ok()
        );
        assert!(store.apply_child_json(revision, request, &fresh).is_err());
    }
}
