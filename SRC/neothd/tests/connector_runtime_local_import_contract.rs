//! GOLD-CC-RUNTIME-P0 source contracts. Functional tests live with the
//! crate-private runtime because no production session issuer/RPC exists yet.

use syn::{BinOp, Expr, ExprMethodCall, Member, Stmt, UnOp};

const RUNTIME: &str = include_str!("../src/connectors/runtime_local_import.rs");
const LOCAL_IMPORT: &str = include_str!("../src/connectors/local_import.rs");
const STORE: &str = include_str!("../src/context_graph/mod.rs");

fn is_self_field(expression: &Expr, expected: &str) -> bool {
    let Expr::Field(field) = expression else {
        return false;
    };
    matches!(
        (&*field.base, &field.member),
        (Expr::Path(base), Member::Named(member))
            if base.qself.is_none() && base.path.is_ident("self") && member == expected
    )
}

fn is_shared_reference_to_self_field(expression: &Expr, expected: &str) -> bool {
    matches!(
        expression,
        Expr::Reference(reference)
            if reference.mutability.is_none() && is_self_field(&reference.expr, expected)
    )
}

fn is_shared_reference_to_ident(expression: &Expr, expected: &str) -> bool {
    matches!(
        expression,
        Expr::Reference(reference)
            if reference.mutability.is_none()
                && matches!(
                    &*reference.expr,
                    Expr::Path(path) if path.qself.is_none() && path.path.is_ident(expected)
                )
    )
}

fn negated_method_call(expression: &Expr) -> Option<&ExprMethodCall> {
    let Expr::Unary(unary) = expression else {
        return None;
    };
    if !matches!(unary.op, UnOp::Not(_)) {
        return None;
    }
    match &*unary.expr {
        Expr::MethodCall(call) => Some(call),
        _ => None,
    }
}

fn is_negated_runtime_lease_match(expression: &Expr) -> bool {
    let Some(call) = negated_method_call(expression) else {
        return false;
    };
    let mut arguments = call.args.iter();
    call.method == "matches_operation_lease"
        && is_self_field(&call.receiver, "runtime_binding")
        && arguments
            .next()
            .is_some_and(|argument| is_shared_reference_to_ident(argument, "lease"))
        && arguments.next().is_none()
}

fn is_negated_capability_binding_match(expression: &Expr) -> bool {
    let Some(call) = negated_method_call(expression) else {
        return false;
    };
    let mut arguments = call.args.iter();
    call.method == "binding_matches"
        && is_self_field(&call.receiver, "capability")
        && arguments.next().is_some_and(|argument| {
            is_shared_reference_to_self_field(argument, "runtime_binding")
        })
        && arguments
            .next()
            .is_some_and(|argument| is_shared_reference_to_ident(argument, "lease"))
        && arguments.next().is_none()
}

fn is_exact_rejecting_binding_guard(statement: &Stmt) -> bool {
    let Stmt::Expr(Expr::If(guard), None) = statement else {
        return false;
    };
    let Expr::Binary(condition) = &*guard.cond else {
        return false;
    };
    guard.attrs.is_empty()
        && matches!(condition.op, BinOp::Or(_))
        && is_negated_runtime_lease_match(&condition.left)
        && is_negated_capability_binding_match(&condition.right)
        && guard.else_branch.is_none()
        && matches!(
            guard.then_branch.stmts.as_slice(),
            [Stmt::Macro(statement)] if statement.attrs.is_empty()
                && statement.mac.path.is_ident("bail")
                && statement.semi_token.is_some()
        )
}

fn is_lease_ensure_live_statement(statement: &Stmt) -> bool {
    let Stmt::Expr(Expr::Try(try_expression), Some(_)) = statement else {
        return false;
    };
    let Expr::MethodCall(map_error) = &*try_expression.expr else {
        return false;
    };
    let Expr::MethodCall(ensure_live) = &*map_error.receiver else {
        return false;
    };
    map_error.method == "map_err"
        && ensure_live.method == "ensure_live"
        && ensure_live.args.is_empty()
        && matches!(
            &*ensure_live.receiver,
            Expr::Path(path) if path.qself.is_none() && path.path.is_ident("lease")
        )
}

fn is_ok_lease_tail(statement: &Stmt) -> bool {
    let Stmt::Expr(Expr::Call(call), None) = statement else {
        return false;
    };
    let Expr::Path(function) = &*call.func else {
        return false;
    };
    let mut arguments = call.args.iter();
    function.qself.is_none()
        && function.path.is_ident("Ok")
        && arguments.next().is_some_and(|argument| {
            matches!(
                argument,
                Expr::Path(path) if path.qself.is_none() && path.path.is_ident("lease")
            )
        })
        && arguments.next().is_none()
}

#[test]
fn runtime_is_private_plan_bound_and_effectively_one_shot() {
    let compact_runtime = RUNTIME
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    assert!(RUNTIME.contains("pub(crate) struct RuntimeLocalImport"));
    assert!(!RUNTIME.contains("pub struct RuntimeLocalImport"));
    assert!(RUNTIME.contains("MAX_RETAINED_PLANS"));
    assert!(RUNTIME.contains("plan_ttl"));
    assert!(compact_runtime.contains("plans.remove(&plan_id)"));
    assert!(RUNTIME.contains("plan_id != confirm_plan_id"));
    assert!(RUNTIME.contains("source changed after planning"));
    assert!(RUNTIME.contains("purge_expired"));
    assert!(
        RUNTIME.contains("LocalImportPlanId(<redacted>)")
            || LOCAL_IMPORT.contains("LocalImportPlanId(<redacted>)")
    );
    assert!(RUNTIME.contains("runtime_binding: ContextImportRuntimeBinding"));
    assert!(!RUNTIME.contains("lease: ContextImportOperationLease"));
    assert!(RUNTIME.contains("acquire_context_import_operation_lease"));
    assert!(RUNTIME.contains("matches_operation_lease(&lease)"));
    assert!(
        RUNTIME
            .contains("LocalImportPolicy::default_bounded(self.runtime_binding.policy_revision())")
    );
    let runtime = syn::parse_file(RUNTIME).expect("runtime source must remain valid Rust syntax");
    let acquire_methods = runtime
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(implementation) => Some(&implementation.items),
            _ => None,
        })
        .flatten()
        .filter_map(|item| match item {
            syn::ImplItem::Fn(method) if method.sig.ident == "acquire_live_operation_lease" => {
                Some(method)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [acquire_method] = acquire_methods.as_slice() else {
        panic!("runtime must retain exactly one live-operation lease acquisition method");
    };
    assert_eq!(
        acquire_method.block.stmts.len(),
        4,
        "lease acquisition must remain a straight-line mint, guard, liveness-check, return path"
    );
    let binding_guards = acquire_method
        .block
        .stmts
        .iter()
        .enumerate()
        .filter_map(|(index, statement)| {
            is_exact_rejecting_binding_guard(statement).then_some(index)
        })
        .collect::<Vec<_>>();
    assert_eq!(binding_guards, [1]);
    let ensure_live = acquire_method
        .block
        .stmts
        .iter()
        .position(is_lease_ensure_live_statement)
        .expect("lease liveness check must remain on the accepted path");
    let ok_lease = acquire_method
        .block
        .stmts
        .iter()
        .position(is_ok_lease_tail)
        .expect("accepted path must return the exact checked lease");
    assert_eq!(ensure_live, 2);
    assert_eq!(ok_lease, 3);
    assert!(LOCAL_IMPORT.contains("runtime_binding: Option<ContextImportCapabilityBinding>"));
    assert!(LOCAL_IMPORT.contains("runtime_binding: Some(runtime_binding)"));
}

#[test]
fn runtime_has_no_public_or_legacy_effect_surface() {
    for forbidden in [
        "pub fn",
        "pub struct",
        "pub async",
        "GroundTruth",
        "ObjectKind::Memory",
        "ObjectKind::Note",
        "Provider",
        "Mcp",
        "obsidian",
        "std::fs::read",
        "tokio::",
        "dispatch",
        "channel",
        "credential",
    ] {
        assert!(
            !RUNTIME.contains(forbidden),
            "runtime must not expose {forbidden}"
        );
    }
    assert!(LOCAL_IMPORT.contains("read_bound_source"));
    assert!(LOCAL_IMPORT.contains("PlatformUnsupported"));
}

#[test]
fn store_bridge_is_exactly_untrusted_connector_evidence_and_outbox_backed() {
    assert!(STORE.contains("pub(crate) fn commit_local_import_evidence"));
    assert!(STORE.contains("ObjectKind::Evidence"));
    assert!(STORE.contains("ProvenanceKind::Connector"));
    assert!(STORE.contains("untrusted_external:local_import"));
    assert!(STORE.contains("AuditReceipt::ContextEvidenceStored"));
    // The operation gate, not a pre-transaction probe, is the final
    // revocation-safe boundary around the SQLite transaction and WAL ACK.
    assert!(STORE.contains("with_context_import_commit_permit"));
    assert!(STORE.contains("commit_batch_with_limits_and_context_evidence_receipt"));
    assert!(STORE.contains("permits_context_evidence_receipt"));
    assert!(STORE.contains("pub(crate) fn reserve_local_import_audit"));
    assert!(STORE.contains("pub(crate) fn acknowledge_local_import_audit"));
    assert!(RUNTIME.contains("ContextEvidenceReceipt::new"));
    assert!(RUNTIME.contains("reserve_local_import_audit"));
    assert!(RUNTIME.contains("acknowledge_local_import_audit"));
    assert!(RUNTIME.contains("append_context_evidence_receipt_once"));
    assert!(STORE.contains("authority_revisions"));
    let reserve = RUNTIME.find("reserve_local_import_audit").unwrap();
    let deliver = RUNTIME.find("adapter.deliver(&entry)").unwrap();
    let acknowledge = RUNTIME.find("acknowledge_local_import_audit").unwrap();
    assert!(reserve < deliver && deliver < acknowledge);
}
