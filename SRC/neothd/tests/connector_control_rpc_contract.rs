//! Source contracts for the private Connector-Control RPC vertical slice.
//!
//! The behaviour tests remain by the implementation so they can exercise
//! crate-private authority. These checks guard the public source shape against
//! accidental audit-RPC coupling, client-subject minting, TCP fallback, or
//! content-bearing response/WAL drift.

const RPC: &str = include_str!("../src/connectors/control_plane/rpc/mod.rs");
const CONTROL: &str = include_str!("../src/connectors/control_plane.rs");
const RELOAD: &str = include_str!("../src/config/reload.rs");
const SERVE: &str = include_str!("../src/cli/serve.rs");
const SERVE_TASKS: &str = include_str!("../src/cli/serve_tasks.rs");

fn compact_ascii_whitespace(source: &str) -> String {
    source
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect()
}

#[test]
fn connector_control_rpc_uses_its_own_domains_and_no_tcp_or_audit_routes() {
    for required in [
        "connector_control_rpc_token",
        "connector_control_rpc.endpoint.v1.json",
        "neoth-connector-control-rpc-v1-endpoint-nonce",
        "neoth-connector-control-rpc-v1-unix-socket",
        "same_effective_uid",
        "SO_PEERCRED",
        "getpeereid",
        "target_os = \"macos\"",
        "random_runtime_nonce",
        "runtime_nonce: String",
        "endpoint_for_home_with_runtime_nonce",
        "connector_control_rpc.prebind.v1.json",
        "write_prebind",
        "read_prior_prebind_endpoint",
        "remove_prebind_checked",
        "RUNTIME_ROOT_PREFIX: &str = \".n-\"",
        "SOCKET_BASENAME: &str = \"s\"",
        "MAX_UNIX_SOCKET_PATH_BYTES: usize = 100",
    ] {
        assert!(
            RPC.contains(required),
            "missing private CC RPC boundary: {required}"
        );
    }
    for forbidden in [
        "crate::daemon::audit_rpc",
        "audit_rpc_token",
        "audit_rpc.endpoint",
        "TcpListener",
        "TcpStream",
        "\"/tmp/ncc-{}\"",
        "AuthenticatedControlSessionIssuer",
        "pub fn daemon_authenticated_session",
    ] {
        assert!(
            !RPC.contains(forbidden),
            "CC RPC must not expose/couple {forbidden}"
        );
    }
    assert!(CONTROL.contains("fn daemon_authenticated_session"));
    assert!(!CONTROL.contains("pub(crate) fn daemon_authenticated_session"));
    assert!(CONTROL.contains("test_context_import_runtime_fixture"));
    assert!(CONTROL.contains(
        "#[cfg(test)]\npub(crate) fn test_context_import_runtime_fixture"
    ));
    assert!(CONTROL.contains("AuthenticatedControlSession::test_authenticated"));
}

#[test]
fn rpc_routes_are_bounded_authenticated_and_keep_import_artifacts_opaque() {
    for required in [
        "MAX_REQUEST_BYTES: usize = 8 * 1024",
        "MAX_BODY_BYTES: usize = 4096",
        "MAX_RESPONSE_BYTES: usize = 4096",
        "MAX_CONCURRENT_CONNECTIONS: usize = 16",
        "PLAN_TTL: Duration = Duration::from_secs(5 * 60)",
        "MAX_PENDING_PLANS: usize = 64",
        "constant_time_token_eq",
        "\"/cc/health\"",
        "\"/cc/accounts/status\"",
        "\"/cc/local-import/plan\"",
        "\"/cc/local-import/apply\"",
        "confirmation nonce does not match plan",
        "ContextEvidenceReceipt",
        "append_context_evidence_receipt_once_blocking",
        "receipt_handle: &[u8; 32]",
        "header_end.checked_add(content_length)? > MAX_REQUEST_BYTES",
        "connector-control response deadline exceeded",
        "http_status_line(status)",
        "connector_id.as_str()",
        "JoinSet",
        "deadline_exceeded_before_admission",
        "while let Some(joined) = connections.join_next().await",
        "remove_boot_artifacts(home, None)",
        "ContextImportApplyKey",
        "decode_lower_hex_32",
        "reserve_apply_outcome",
        "query_apply_outcome",
        "release_apply_outcome",
        "confirm_import_with_outcome",
        "reclaim_uncommitted_apply_outcomes",
    ] {
        assert!(
            RPC.contains(required),
            "missing CC RPC safety/route contract: {required}"
        );
    }
    for forbidden in [
        "source_text",
        "selected_relative_path\":",
        "receipt_handle\":",
        ".writer.append(",
        "TerminalPlanOutcome",
        "outcomes: BTreeMap",
    ] {
        assert!(
            !RPC.contains(forbidden),
            "CC RPC response/WAL must not expose {forbidden}"
        );
    }
    assert!(
        compact_ascii_whitespace(RPC).contains("registry.pending.remove(&request.plan_id)"),
        "consuming a plan must remain an exact remove rather than a lookup or clone"
    );
}

#[test]
fn durable_discovery_precedes_listener_admission() {
    let start = RPC
        .find("pub(crate) async fn bind_and_serve(")
        .expect("Unix bind_and_serve must exist");
    let end = start
        + RPC[start..]
            .find("/// Windows and other non-Unix targets")
            .expect("Unix bind_and_serve must end before the unavailable stub");
    let bind = &RPC[start..end];
    let publish = bind
        .find("write_sidecar(home, &endpoint, &endpoint_nonce)")
        .expect("sidecar publication must exist");
    let spawn = bind
        .find("tokio::spawn(")
        .expect("listener spawn must exist");
    assert!(
        publish < spawn,
        "the accept loop must not exist before authenticated discovery is durable"
    );
}

#[test]
fn durable_apply_is_reserved_before_read_and_recovered_before_consumption() {
    let build = RPC
        .find("fn build_pending_plan(")
        .expect("bounded plan builder must exist");
    let apply = RPC
        .find("fn apply_import(")
        .expect("apply route must exist");
    let reserve = RPC[build..apply]
        .find("runtime.reserve_apply_outcome(apply_key)")
        .expect("outer operation must be durably reserved");
    let read = RPC[build..apply]
        .find("runtime.plan_import(Path::new(&request.relative_path))")
        .expect("capability-bound source read must exist");
    assert!(
        reserve < read,
        "durable capacity must be reserved before source read"
    );

    let apply_body = &RPC[apply..];
    let query = apply_body
        .find("recovery.query_apply_outcome(&apply_key)")
        .expect("restart-stable durable query must exist");
    let remove = apply_body
        .find("registry.pending.remove(&request.plan_id)")
        .expect("one-shot plan removal must exist");
    let commit = apply_body
        .find("confirm_import_with_outcome")
        .expect("atomic outcome/evidence commit must exist");
    assert!(query < remove && remove < commit);
    assert!(apply_body.contains("replay_receipts(&mut sink).is_err()"));
    assert!(apply_body.contains("plan_outcome_response(audit_pending)"));
}

#[test]
fn whitespace_stable_plan_consumption_contract_rejects_a_lookup() {
    let expected = "registry.pending.remove(&request.plan_id)";
    assert!(
        compact_ascii_whitespace("registry\n  . pending\n  . remove(&request.plan_id)")
            .contains(expected)
    );
    assert!(!compact_ascii_whitespace("registry.pending.get(&request.plan_id)").contains(expected));
}

#[test]
fn lifecycle_is_pid_bound_fatal_and_reload_cannot_split_authority() {
    assert!(SERVE.contains("audit_endpoint_nonce"));
    assert!(SERVE.contains("spawn_connector_control_rpc"));
    assert!(SERVE.contains("replay_connector_control_receipts_at_startup"));
    assert!(
        SERVE
            .contains("recover pending connector-control Context Evidence before endpoint startup")
    );
    assert!(SERVE.contains("connector_control_rpc_required"));
    assert!(SERVE.contains("connector_control_rpc_guard.take()"));
    assert!(SERVE_TASKS.contains("join_connector_control_rpc(connector_control_rpc_task)"));
    assert!(RELOAD.contains("ConnectorControlTransitionRequired"));
    assert!(RELOAD.contains("context_connectors_transition_required"));
    assert!(RELOAD.contains("old.context_connectors != new.context_connectors"));
}

#[test]
fn windows_is_explicitly_unavailable_without_a_weaker_fallback() {
    assert!(
        RPC.contains("Windows and other non-Unix targets deliberately expose no connector-control")
    );
    assert!(RPC.contains("no TCP fallback exists"));
    assert!(RPC.contains("#[cfg(not(unix))]\npub(crate) async fn bind_and_serve"));
    assert!(SERVE.contains("private connector-control RPC unavailable on this platform"));
}

#[test]
fn owned_effects_are_drained_not_aborted_after_discovery_withdrawal() {
    for required in [
        "self.shutdown.stop()",
        "remove_sidecar_checked(&self.home)",
        "remove_prebind_checked(&self.home)",
        "every blocking SQLite/WAL call remains joined",
        "spawn_blocking(move || process_route",
        "The connection task owns this JoinHandle",
        "shutdown.admit_blocking",
        "Linearize shutdown against a handler's final pre-effect admission",
        "withdraw_after_listener_failure",
        "cleanup_prior_boot_artifacts",
        "read_prior_sidecar_endpoint",
        "remove_endpoint_socket_and_empty_ancestors",
        "remove_exact_private_socket_and_empty_ancestors",
        "drop(listener)",
    ] {
        assert!(
            RPC.contains(required),
            "missing owned-effect shutdown rule: {required}"
        );
    }
    assert!(
        !RPC.contains("listener_abort.abort()"),
        "CC guard must signal and drain rather than abort owned effects"
    );
    let guard_cleanup = RPC
        .find("if remove_endpoint_socket_and_empty_ancestors(&self.home, &endpoint).is_err()")
        .expect("guard must check exact endpoint cleanup");
    let guard_sidecar_removal = RPC
        .find("remove_sidecar_checked(&self.home)")
        .expect("guard must remove sidecar only through checked cleanup");
    assert!(
        guard_cleanup < guard_sidecar_removal,
        "guard must retain discovery and the pre-bind journal until exact cleanup succeeds"
    );
}

#[test]
fn restart_replay_is_plan_independent_and_uses_the_authenticated_once_sink() {
    for required in [
        "replay_pending_context_evidence_at_startup",
        "ContextEvidenceReplayRuntime::new",
        "append_context_evidence_receipt_once_blocking",
        "load_existing_master_key_at",
        "LocalImport account binding",
    ] {
        assert!(
            RPC.contains(required),
            "missing restart-safe replay rule: {required}"
        );
    }
    let replay_ownership = compact_ascii_whitespace(RPC).replace("///", "");
    assert!(
        replay_ownership.contains("ownsnoroot,plan,path,orimportedcontent"),
        "restart replay must remain independent of imported content and its root, plan, and path"
    );
}

#[test]
fn rpc_module_carries_executable_boundary_regressions_beyond_source_shape() {
    for required in [
        "parser_rejects_a_request_whose_header_plus_body_exceeds_the_total_cap",
        "shutdown_signal_is_sticky_and_refuses_later_worker_admission",
        "stale_token_cleanup_is_scoped_to_the_cc_token_name",
        "canonical_clean_shutdown_and_two_crash_restarts_remove_exact_prior_endpoint",
        "prior_cleanup_preserves_every_hostile_or_unbound_artifact",
        "bind_before_sidecar_crash_cleanup_is_bounded_and_exact",
        "prebind_crash_before_directory_creation_is_recoverable",
        "prebind_cleanup_recovers_each_partial_directory_creation_stage",
        "prebind_crash_after_bind_before_socket_chmod_is_recoverable",
        "hostile_global_tmp_junk_is_ignored_without_a_bound_prebind_journal",
        "runtime_root_is_unpredictable_and_precreated_victim_name_fails_closed",
        "endpoint_path_is_short_enough_to_bind_and_cleanup",
        "required_connector_control_rejects_legacy_incompatible_operator_id_before_artifacts",
        "http_status_lines_are_valid_and_have_fixed_reason_phrases",
        "response_uses_a_valid_http_status_line_with_reason_phrase",
        "current_max_connector_roster_status_is_canonical_and_below_response_cap",
        "concurrent_stop_and_admit_has_one_linearized_winner",
        "accept_failure_withdraws_discovery_before_preaccepted_work_can_admit_again",
        "#[tokio::test]",
        "#[cfg(unix)]",
    ] {
        assert!(
            RPC.contains(required),
            "missing CC RPC behavioral regression: {required}"
        );
    }
}
