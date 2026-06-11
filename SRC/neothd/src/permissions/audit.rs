//! KF-06 (Session 24) — `neoth permissions audit`.
//!
//! Operator-facing diagnostic: every permission decision the
//! daemon made in a time window + (when present) the downstream
//! effect that decision produced. Pure-read scan over WAL frames
//! in the permission band (`0xA0..=0xAF` PERMISSION_GRANTED /
//! _DENIED) + the adjacent consent decisions (`0x65
//! CONSENT_DECISION`).
//!
//! ## What the report surfaces
//!
//! - One [`AuditEntry`] per permission/consent frame in the window
//! - Summary counts by decision (granted / denied / consent
//!   tri-state)
//! - Top-N most-denied actions so the operator sees which gates
//!   bite hardest
//!
//! ## Downstream-effect correlation
//!
//! For a v0.4 first pass, "downstream effect" means: scan the
//! next frame AFTER each permission decision in the same WAL
//! stream — if it's a provider call / channel send / tool
//! invocation, that's a plausible downstream. Strict causal
//! correlation (the same `event_id` thread) lands when the
//! Coding Workflow's `parent_task_id` model generalises to the
//! permission surface (v0.9).
//!
//! ## Scope
//!
//! Pure-read. No mutations. No WAL writes. Operator can run it
//! against a backup-tarball segment file without spinning up the
//! daemon (matches the recovery / drift / diff pattern from the
//! rest of v0.4).

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::wal::events::{
    EVENT_TYPE_CONSENT_DECISION, EVENT_TYPE_PERMISSION_DENIED, EVENT_TYPE_PERMISSION_GRANTED,
};
use crate::wal::segment_header::SEGMENT_HEADER_LEN;

/// One row in the audit report. Carries the decision verdict + a
/// best-effort downstream-effect description.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AuditEntry {
    pub event_id: u64,
    pub ts_ns: u64,
    pub decision: AuditDecision,
    /// Parsed `action` field from the payload (e.g.
    /// `"paid_provider_call"`, `"shell_exec"`). Empty when the
    /// payload didn't carry one or didn't parse.
    pub action: String,
    /// Operator-visible reason string from the payload. Empty
    /// when none was recorded.
    pub reason: String,
    /// Downstream-effect description (next-frame heuristic). Empty
    /// when the frame was the last in the segment or the next
    /// frame is not a recognised effect type.
    pub downstream: Option<String>,
    /// SL-01a-b: the authenticated subject the decision was made for
    /// (peer pub-key-hex / plugin id / channel sender). `None` for frames
    /// written before lease wiring or with no lease context.
    pub subject: Option<String>,
    /// SL-01a-b: the capability lease that upgraded a `Confirm` to `Allow`,
    /// if any. `None` means the decision was reached without a lease. This
    /// is the pointer the operator joins against `0xA5 LEASE_GRANTED` to
    /// prove the grant chain.
    pub lease_id: Option<String>,
}

/// Three-way decision discriminator. Pinned `serde(rename_all =
/// "snake_case")` for stable wire form.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    /// `EVENT_TYPE_PERMISSION_GRANTED` (0xA0).
    Granted,
    /// `EVENT_TYPE_PERMISSION_DENIED` (0xA1).
    Denied,
    /// `EVENT_TYPE_CONSENT_DECISION` (0x65) — `allow_once` or
    /// `allow_always` value in the payload.
    ConsentAllow,
    /// `EVENT_TYPE_CONSENT_DECISION` (0x65) — `deny` value in the
    /// payload.
    ConsentDeny,
}

impl AuditDecision {
    /// Stable wire form. Drift-guard pinned.
    pub fn as_str(self) -> &'static str {
        match self {
            AuditDecision::Granted => "granted",
            AuditDecision::Denied => "denied",
            AuditDecision::ConsentAllow => "consent_allow",
            AuditDecision::ConsentDeny => "consent_deny",
        }
    }
}

/// Aggregate report. Entries are ordered chronologically (oldest
/// first) so the operator's terminal scroll matches WAL time.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AuditReport {
    pub entries: Vec<AuditEntry>,
    pub by_decision: HashMap<AuditDecision, i64>,
    /// Most-denied actions (sorted desc by deny count). Limited
    /// by `top_denied_cap` arg to [`audit_segment`].
    pub top_denied_actions: Vec<(String, i64)>,
}

/// Walk one WAL segment + extract the permission audit trail
/// within `[from_ns, to_ns]`. `top_denied_cap` caps the
/// most-denied summary list.
///
/// The function tolerates a missing segment file (returns
/// `Ok(empty)`) so the operator's first `neoth permissions
/// audit` against a fresh install doesn't hard-fail.
pub fn audit_segment(
    segment: &Path,
    from_ns: i64,
    to_ns: i64,
    top_denied_cap: usize,
) -> Result<AuditReport> {
    let bytes = match std::fs::read(segment) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(empty_report()),
        Err(e) => return Err(e).with_context(|| format!("read {}", segment.display())),
    };
    if bytes.len() < SEGMENT_HEADER_LEN {
        return Ok(empty_report());
    }

    // Walk frames, collect raw (header, payload) for permission-band
    // + consent frames in the window. Also collect EVERY frame's
    // (event_id, event_type) so the downstream-effect heuristic can
    // look up the next frame after a permission decision.
    let mut raw_decisions: Vec<(u64, u64, u8, Vec<u8>)> = Vec::new(); // (event_id, ts_ns, event_type, payload)
    let mut next_after: HashMap<u64, (u8, u64)> = HashMap::new(); // event_id → (event_type, ts_ns) of the NEXT frame
    let mut prev_event_id: Option<u64> = None;
    // GOLD-ARCH-03: for_each_frame so permission/consent frames inside a
    // v2/zstd-compressed segment are audited, not silently skipped. Frame order
    // is preserved, so the prev→next "downstream effect" wiring is unchanged.
    // GR-033: the scan Result is PROPAGATED (not `let _ =`-discarded). It Errs
    // only on an unreconstructable — tamper-suspect — compressed blob, so a
    // security audit MUST fail loud on a corrupt segment rather than silently
    // report a clean trail (the old fail-open).
    crate::wal::scan::for_each_frame(&bytes, |_, dec| {
        let event_id = dec.header.event_id.0;
        let event_type = dec.header.event_type;
        let ts_ns = dec.header.hlc.physical_ns();

        // Wire the previous frame's "next-after" lookup.
        if let Some(prev) = prev_event_id.take() {
            next_after.insert(prev, (event_type, ts_ns));
        }
        prev_event_id = Some(event_id);

        // Collect permission/consent frames in the window.
        let in_window = (ts_ns as i64) >= from_ns && (ts_ns as i64) <= to_ns;
        let is_audit_event = matches!(
            event_type,
            t if t == EVENT_TYPE_PERMISSION_GRANTED
              || t == EVENT_TYPE_PERMISSION_DENIED
              || t == EVENT_TYPE_CONSENT_DECISION,
        );
        if in_window && is_audit_event {
            raw_decisions.push((event_id, ts_ns, event_type, dec.payload.to_vec()));
        }
        Ok(())
    })
    .with_context(|| {
        format!(
            "permission audit: WAL segment {} is tamper-suspect / unreconstructable — \
             refusing to report a clean audit over a corrupt segment",
            segment.display()
        )
    })?;

    // Build entries + summary counts.
    let mut entries: Vec<AuditEntry> = Vec::with_capacity(raw_decisions.len());
    let mut by_decision: HashMap<AuditDecision, i64> = HashMap::new();
    let mut denied_counter: HashMap<String, i64> = HashMap::new();
    for (event_id, ts_ns, event_type, payload) in raw_decisions {
        let parsed = parse_payload(&payload);
        let decision = classify_decision(event_type, &parsed);
        let action = parsed.action.clone();
        let reason = parsed.reason.clone();
        let subject = parsed.subject.clone();
        let lease_id = parsed.lease_id.clone();
        let downstream = next_after
            .get(&event_id)
            .map(|(et, _)| describe_downstream(*et));
        *by_decision.entry(decision).or_insert(0) += 1;
        if matches!(decision, AuditDecision::Denied | AuditDecision::ConsentDeny)
            && !action.is_empty()
        {
            *denied_counter.entry(action.clone()).or_insert(0) += 1;
        }
        entries.push(AuditEntry {
            event_id,
            ts_ns,
            decision,
            action,
            reason,
            downstream,
            subject,
            lease_id,
        });
    }

    // Sort entries chronologically by ts_ns ASC. The frames already
    // arrive in segment order, but a future torn-tail-then-resume
    // could surface out-of-order frames; sort defensively.
    entries.sort_by_key(|e| e.ts_ns);

    // Top-denied actions, sorted desc by count then alphabetically
    // for stable output.
    let mut top_denied: Vec<(String, i64)> = denied_counter.into_iter().collect();
    top_denied.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    top_denied.truncate(top_denied_cap);

    Ok(AuditReport {
        entries,
        by_decision,
        top_denied_actions: top_denied,
    })
}

fn empty_report() -> AuditReport {
    AuditReport {
        entries: Vec::new(),
        by_decision: HashMap::new(),
        top_denied_actions: Vec::new(),
    }
}

/// Minimal payload shape we extract from each permission/consent
/// frame. Fields are best-effort — missing or non-JSON payloads
/// yield empty strings.
#[derive(Default, Debug)]
struct ParsedPayload {
    action: String,
    reason: String,
    decision_label: String,
    subject: Option<String>,
    lease_id: Option<String>,
}

fn parse_payload(bytes: &[u8]) -> ParsedPayload {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return ParsedPayload::default();
    };
    let pick = |key: &str| {
        v.get(key)
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string()
    };
    // Optional fields stay `None` when absent OR JSON-null (the gate writes
    // `null` for these on a non-lease decision).
    let pick_opt = |key: &str| v.get(key).and_then(|x| x.as_str()).map(str::to_string);
    ParsedPayload {
        action: pick("action"),
        reason: pick("reason"),
        decision_label: pick("decision"),
        subject: pick_opt("subject"),
        lease_id: pick_opt("lease_id"),
    }
}

/// Classify the frame into one of the four audit verdicts.
/// Permission frames map directly; consent frames inspect the
/// payload's `decision` field to split allow_once / allow_always
/// (= Allow) from deny (= ConsentDeny). Unknown consent labels
/// default to Allow (charitable: an old client sending a
/// non-canonical string shouldn't get auto-flagged as deny).
fn classify_decision(event_type: u8, parsed: &ParsedPayload) -> AuditDecision {
    match event_type {
        t if t == EVENT_TYPE_PERMISSION_GRANTED => AuditDecision::Granted,
        t if t == EVENT_TYPE_PERMISSION_DENIED => AuditDecision::Denied,
        t if t == EVENT_TYPE_CONSENT_DECISION => {
            if parsed.decision_label.eq_ignore_ascii_case("deny") {
                AuditDecision::ConsentDeny
            } else {
                AuditDecision::ConsentAllow
            }
        }
        _ => AuditDecision::Granted, // unreachable in practice
    }
}

/// Map a follow-up `event_type` to an operator-visible downstream
/// description. Conservative: only frames the operator typically
/// associates with permission-gated effects (provider calls,
/// channel egress, tool invocations, kanban transitions).
fn describe_downstream(next_event_type: u8) -> String {
    use crate::wal::events::*;
    let label = match next_event_type {
        t if t == EVENT_TYPE_PROVIDER_REQUEST => "provider_request",
        t if t == EVENT_TYPE_PROVIDER_RESPONSE => "provider_response",
        t if t == EVENT_TYPE_CHANNEL_EGRESS => "channel_egress",
        t if t == EVENT_TYPE_MCP_TOOL_CALLED => "mcp_tool_called",
        t if t == EVENT_TYPE_PLUGIN_HOSTCALL => "plugin_hostcall",
        t if t == EVENT_TYPE_KANBAN_STATUS_CHANGED => "kanban_status_changed",
        _ => "",
    };
    label.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::builder::HeaderBuilder;
    use crate::wal::events::*;
    use crate::wal::frame::encode_frame;
    use crate::wal::segment_header::SegmentHeader;
    use tempfile::tempdir;

    fn write_segment(path: &Path, frames: &[(u8, &[u8])]) {
        let mut out = Vec::new();
        out.extend_from_slice(&SegmentHeader::new(0, 1, 0, 0, [0u8; 16]).to_le_bytes());
        for (event_type, payload) in frames {
            let header = HeaderBuilder::new(*event_type, payload).build();
            out.extend_from_slice(&encode_frame(&header, payload));
        }
        std::fs::write(path, out).unwrap();
    }

    fn pl(action: &str, reason: &str, decision: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "action": action,
            "reason": reason,
            "decision": decision,
        }))
        .unwrap()
    }

    // ── classifier + helpers ──────────────────────────────────────────

    #[test]
    fn decision_as_str_pinned_for_audit() {
        assert_eq!(AuditDecision::Granted.as_str(), "granted");
        assert_eq!(AuditDecision::Denied.as_str(), "denied");
        assert_eq!(AuditDecision::ConsentAllow.as_str(), "consent_allow");
        assert_eq!(AuditDecision::ConsentDeny.as_str(), "consent_deny");
    }

    #[test]
    fn audit_segment_fails_loud_on_a_tamper_suspect_compressed_segment() {
        // GR-033: a security audit must NOT silently report a clean trail over an
        // unreconstructable (tamper-suspect) compressed segment. A v2 header that
        // FLAGS compression but whose body is not valid zstd makes for_each_frame
        // (via logical_segment_bytes) Err — audit_segment must PROPAGATE it, not
        // swallow it via `let _ =`. FAILS pre-fix (Ok empty report), passes post.
        use crate::wal::segment_header::{SEGMENT_FLAG_COMPRESSED, SegmentHeaderV2};
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let mut bytes = SegmentHeaderV2::new(0, 1, 0, 0, [0u8; 16], SEGMENT_FLAG_COMPRESSED)
            .to_le_bytes()
            .to_vec();
        // A body that is NOT valid zstd → decompress fails → tamper-suspect.
        bytes.extend_from_slice(&[0xFFu8; 64]);
        std::fs::write(&seg, &bytes).unwrap();
        let r = audit_segment(&seg, 0, i64::MAX, 10);
        assert!(
            r.is_err(),
            "a tamper-suspect compressed segment must fail the audit, not report clean"
        );
    }

    #[test]
    fn classify_decision_pins_each_event_type() {
        let empty = ParsedPayload::default();
        let mut allow_once = ParsedPayload::default();
        allow_once.decision_label = "allow_once".into();
        let mut allow_always = ParsedPayload::default();
        allow_always.decision_label = "allow_always".into();
        let mut deny = ParsedPayload::default();
        deny.decision_label = "DENY".into();

        assert_eq!(
            classify_decision(EVENT_TYPE_PERMISSION_GRANTED, &empty),
            AuditDecision::Granted,
        );
        assert_eq!(
            classify_decision(EVENT_TYPE_PERMISSION_DENIED, &empty),
            AuditDecision::Denied,
        );
        assert_eq!(
            classify_decision(EVENT_TYPE_CONSENT_DECISION, &allow_once),
            AuditDecision::ConsentAllow,
        );
        assert_eq!(
            classify_decision(EVENT_TYPE_CONSENT_DECISION, &allow_always),
            AuditDecision::ConsentAllow,
        );
        assert_eq!(
            classify_decision(EVENT_TYPE_CONSENT_DECISION, &deny),
            AuditDecision::ConsentDeny,
        );
    }

    #[test]
    fn unknown_consent_label_charitably_defaults_to_allow() {
        // Pre-rule: an old client / future-format payload that
        // omits `decision` or sends a non-canonical string is
        // classified as ConsentAllow (charitable). Pin this so a
        // future strict-validation refactor doesn't quietly flip
        // historic audit reads.
        let mut weird = ParsedPayload::default();
        weird.decision_label = "maybe".into();
        assert_eq!(
            classify_decision(EVENT_TYPE_CONSENT_DECISION, &weird),
            AuditDecision::ConsentAllow,
        );
    }

    #[test]
    fn describe_downstream_recognises_canonical_effect_types() {
        assert!(!describe_downstream(EVENT_TYPE_PROVIDER_REQUEST).is_empty());
        assert!(!describe_downstream(EVENT_TYPE_CHANNEL_EGRESS).is_empty());
        assert!(!describe_downstream(EVENT_TYPE_MCP_TOOL_CALLED).is_empty());
        assert!(!describe_downstream(EVENT_TYPE_PLUGIN_HOSTCALL).is_empty());
        // Unknown event types yield empty string.
        assert!(describe_downstream(0x01).is_empty());
        assert!(describe_downstream(0xFF).is_empty());
    }

    // ── audit_segment integration ─────────────────────────────────────

    #[test]
    fn audit_returns_empty_for_missing_segment() {
        let dir = tempdir().unwrap();
        let absent = dir.path().join("never-existed.wal");
        let r = audit_segment(&absent, 0, i64::MAX, 10).unwrap();
        assert!(r.entries.is_empty());
        assert!(r.by_decision.is_empty());
    }

    #[test]
    fn audit_returns_empty_for_tiny_file() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        std::fs::write(&seg, b"").unwrap();
        let r = audit_segment(&seg, 0, i64::MAX, 10).unwrap();
        assert!(r.entries.is_empty());
    }

    #[test]
    fn audit_surfaces_subject_and_lease_id_when_present() {
        // SL-01a-b: a lease-upgraded GRANTED frame carries subject + lease_id;
        // the audit reader must surface them (the grant-chain proof) and leave
        // them None on a plain frame that has neither.
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let with_lease = serde_json::to_vec(&serde_json::json!({
            "action": "ChannelSend",
            "reason": serde_json::Value::Null,
            "decision": "allow",
            "subject": "peerA",
            "lease_id": "0193f8a0-dead-7abc-9999-000000000001",
        }))
        .unwrap();
        write_segment(
            &seg,
            &[
                (EVENT_TYPE_PERMISSION_GRANTED, &with_lease),
                (EVENT_TYPE_PERMISSION_GRANTED, &pl("read", "", "")),
            ],
        );
        let r = audit_segment(&seg, 0, i64::MAX, 10).unwrap();
        assert_eq!(r.entries.len(), 2);
        let leased = &r.entries[0];
        assert_eq!(leased.subject.as_deref(), Some("peerA"));
        assert_eq!(
            leased.lease_id.as_deref(),
            Some("0193f8a0-dead-7abc-9999-000000000001")
        );
        let plain = &r.entries[1];
        assert!(plain.subject.is_none(), "no subject ⇒ None");
        assert!(plain.lease_id.is_none(), "no lease ⇒ None");
    }

    #[test]
    fn audit_surfaces_each_permission_frame_with_decision() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        write_segment(
            &seg,
            &[
                (
                    EVENT_TYPE_PERMISSION_GRANTED,
                    &pl("paid_provider_call", "ok", ""),
                ),
                (
                    EVENT_TYPE_PERMISSION_DENIED,
                    &pl("shell_exec", "blocked", ""),
                ),
                (
                    EVENT_TYPE_CONSENT_DECISION,
                    &pl("openai_api", "", "allow_always"),
                ),
                (EVENT_TYPE_CONSENT_DECISION, &pl("gemini_api", "", "deny")),
                (EVENT_TYPE_RAW_TEXT, b"unrelated"),
            ],
        );
        let r = audit_segment(&seg, 0, i64::MAX, 10).unwrap();
        // 4 audit frames; RAW_TEXT excluded.
        assert_eq!(r.entries.len(), 4);
        assert_eq!(
            r.by_decision
                .get(&AuditDecision::Granted)
                .copied()
                .unwrap_or(0),
            1
        );
        assert_eq!(
            r.by_decision
                .get(&AuditDecision::Denied)
                .copied()
                .unwrap_or(0),
            1
        );
        assert_eq!(
            r.by_decision
                .get(&AuditDecision::ConsentAllow)
                .copied()
                .unwrap_or(0),
            1
        );
        assert_eq!(
            r.by_decision
                .get(&AuditDecision::ConsentDeny)
                .copied()
                .unwrap_or(0),
            1
        );
    }

    #[test]
    fn audit_window_filter_excludes_out_of_window_frames() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        // Seed 3 frames with real wall-clock ts. Window cuts AFTER
        // them to leave 0 in range, then expand to include all.
        write_segment(
            &seg,
            &[
                (EVENT_TYPE_PERMISSION_GRANTED, &pl("a", "", "")),
                (EVENT_TYPE_PERMISSION_DENIED, &pl("b", "", "")),
                (EVENT_TYPE_PERMISSION_GRANTED, &pl("c", "", "")),
            ],
        );

        // Future-only window — zero hits.
        let r_future = audit_segment(&seg, i64::MAX - 1_000, i64::MAX, 10).unwrap();
        assert!(r_future.entries.is_empty());

        // Wide-open window — all 3 hits.
        let r_open = audit_segment(&seg, 0, i64::MAX, 10).unwrap();
        assert_eq!(r_open.entries.len(), 3);
    }

    #[test]
    fn audit_downstream_recognises_next_frame_when_permission_grants() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        write_segment(
            &seg,
            &[
                (
                    EVENT_TYPE_PERMISSION_GRANTED,
                    &pl("paid_provider_call", "ok", ""),
                ),
                (EVENT_TYPE_PROVIDER_REQUEST, b"{\"provider\":\"openai\"}"),
            ],
        );
        let r = audit_segment(&seg, 0, i64::MAX, 10).unwrap();
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].downstream.as_deref(), Some("provider_request"));
    }

    #[test]
    fn audit_downstream_is_none_when_permission_is_last_frame() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        write_segment(
            &seg,
            &[(
                EVENT_TYPE_PERMISSION_DENIED,
                &pl("shell_exec", "blocked", ""),
            )],
        );
        let r = audit_segment(&seg, 0, i64::MAX, 10).unwrap();
        assert_eq!(r.entries.len(), 1);
        assert!(r.entries[0].downstream.is_none());
    }

    #[test]
    fn audit_top_denied_actions_sorted_desc_with_cap() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        // shell_exec denied 3x, provider_call denied 1x, paid_io denied 2x.
        write_segment(
            &seg,
            &[
                (EVENT_TYPE_PERMISSION_DENIED, &pl("shell_exec", "", "")),
                (EVENT_TYPE_PERMISSION_DENIED, &pl("shell_exec", "", "")),
                (EVENT_TYPE_PERMISSION_DENIED, &pl("shell_exec", "", "")),
                (EVENT_TYPE_PERMISSION_DENIED, &pl("provider_call", "", "")),
                (EVENT_TYPE_PERMISSION_DENIED, &pl("paid_io", "", "")),
                (EVENT_TYPE_PERMISSION_DENIED, &pl("paid_io", "", "")),
                (EVENT_TYPE_CONSENT_DECISION, &pl("openai_api", "", "deny")),
            ],
        );
        let r = audit_segment(&seg, 0, i64::MAX, 2).unwrap();
        // Top-2 cap. shell_exec (3) + paid_io (2) win; openai_api (1) and provider_call (1) tied for 3rd, dropped.
        assert_eq!(r.top_denied_actions.len(), 2);
        assert_eq!(r.top_denied_actions[0], ("shell_exec".to_string(), 3));
        assert_eq!(r.top_denied_actions[1], ("paid_io".to_string(), 2));
    }

    #[test]
    fn audit_tolerates_non_json_payload_gracefully() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        write_segment(
            &seg,
            &[
                (EVENT_TYPE_PERMISSION_GRANTED, b"not json"),
                (EVENT_TYPE_PERMISSION_DENIED, b"{\"action\":}"), // malformed
            ],
        );
        // No panic — entries appear with empty action/reason.
        let r = audit_segment(&seg, 0, i64::MAX, 10).unwrap();
        assert_eq!(r.entries.len(), 2);
        assert!(r.entries[0].action.is_empty());
        assert!(r.entries[1].action.is_empty());
    }

    #[test]
    fn audit_entries_sorted_chronologically_by_ts_asc() {
        // Drift guard: even if a future torn-tail recovery path
        // surfaces frames out of order, the entries vec MUST come
        // back oldest-first so the operator's terminal scroll
        // matches WAL time.
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        write_segment(
            &seg,
            &[
                (EVENT_TYPE_PERMISSION_GRANTED, &pl("a", "", "")),
                (EVENT_TYPE_PERMISSION_GRANTED, &pl("b", "", "")),
                (EVENT_TYPE_PERMISSION_GRANTED, &pl("c", "", "")),
            ],
        );
        let r = audit_segment(&seg, 0, i64::MAX, 10).unwrap();
        let ts: Vec<u64> = r.entries.iter().map(|e| e.ts_ns).collect();
        for w in ts.windows(2) {
            assert!(w[0] <= w[1], "entries must sort ts ASC, got {ts:?}");
        }
    }
}
