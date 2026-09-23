# W424 — Outbound task-delegation Group841 repair

## Result

Group841 run `35871794576` reported six outbound-related fixture failures plus
the v6-to-v7 migration fixture. They share one production SQL defect in
`MembershipStore::task_delegate_outbound_candidates`, not a fixture-only timing
or assertion problem.

The query joins `task_delegate_outbound_assignments o` with
`transport_bindings b`; both expose `transport_identity`. Its original ordering
clause used the unqualified name:

```sql
ORDER BY priority ASC, transport_identity ASC
```

SQLite rejects the prepared query as `ambiguous column name: transport_identity`.
Consequently every caller fails before it can select an outbound candidate:

- exact-scope candidate and ordering fixtures;
- prepared/result lifecycle fixtures that query candidates;
- live-stream dispatch/teardown/race fixtures;
- the audit-RPC accepted-route fixture, which correctly returned `422` from the
  dispatch error rather than the expected `200` typed receipt;
- the migration fixture, whose intended empty-candidate assertion instead
  failed during query preparation.

The hosted failure text identifies this exact clause and offset in each case;
for example the migration failure begins at lifecycle-log lines 36749-36763 and
the audit-RPC failure at 37406-37409.

## Repair

`SRC/neothd/src/cluster/membership.rs` now qualifies both sort keys with the
operator-assignment table alias:

```sql
ORDER BY o.priority ASC, o.transport_identity ASC
```

This preserves the documented selection semantics: priority first, then the
same authenticated assignment key selected by `SELECT o.transport_identity`.
It does not change membership eligibility joins, authorization predicates,
persisted data, fallback behavior, retry semantics, or any fixture assertion.

## Current evidence and remaining validation

- Source and hosted log inspection establish the root cause and direct fix.
- `git diff --check` for the owned source and this report is clean.
- No local Cargo, compiler, parser, formatter, test, runtime, browser, model,
  or network operation ran under the BSOD hold.
- The hosted Group841 rerun must re-execute the seven failed selectors. The
  current source also gives live outbound fixtures fresh attestations where
  required; that separate fixture-time correction is preserved and was not
  relaxed by this SQL repair.

W219 completed the independent static review with PASS; hosted rerun remains pending.
