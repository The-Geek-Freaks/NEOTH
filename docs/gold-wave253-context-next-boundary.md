# W253: Local Import plan preview

## Selected batch: content-free Local Import plan summary

The completed user-visible batch is a useful dry-run response for the existing
`neoth context import plan <root> <relative_path>` flow. The daemon performs
the same bounded, no-follow read and retains the same one-shot plan, then
returns its planned record count and parser/policy generation before the
operator chooses `apply`.

The batch returns a content-free `preview` beside those existing opaque
values:

```json
{
  "plan_id": "<opaque>",
  "confirmation_nonce": "<opaque>",
  "preview": {
    "record_count": 3,
    "policy_revision": 7,
    "parser_revision": 1
  }
}
```

`preview` is derived from the exact retained `LocalImportPlan`; it must not
contain a root, relative path, file name, source-object ID, version fingerprint,
source span, text, bytes, content hash, account/subject, or a reusable
authority. It creates no additional filesystem read, database mutation, WAL
frame, cursor, background task, or apply reservation beyond the current plan
path. `apply` stays bound solely to the existing opaque plan and confirmation
nonce and still re-reads the selected file before committing.

## Implemented ownership

1. `SRC/neothd/src/connectors/runtime_local_import.rs` owns
   `LocalImportPlanPreview` and `plan_import_with_preview`. It derives the
   allowlisted values from the exact `LocalImportPlan` immediately before that
   plan is retained. The established `plan_import` API keeps returning only
   the opaque ID for existing runtime callers.
2. `SRC/neothd/src/connectors/control_plane/rpc/mod.rs` retains the preview in
   `PendingPlan` and serializes it only in the existing
   `POST /cc/local-import/plan` success response.
3. `SRC/neothd/src/cli/context.rs` has no command or request change. Its
   existing Windows and Unix live-daemon roundtrips assert the exact preview
   and the complete response-key allowlist.

`plan_preview_is_exact_content_free_and_has_no_store_or_wal_effect` proves a
multi-record selected file returns the exact count/current revisions and emits
no receipt. The existing Windows and Unix live-daemon roundtrips assert the
exact preview schema and that the `data` object exposes only
`plan_id`, `confirmation_nonce`, and `preview`. Existing changed-source,
one-shot-plan, and apply-replay tests remain the regression fence for the
unchanged commit boundary.

## Deliberately deferred work

Selective erase is still absent from the Local Import RPC/CLI. It is not this
batch: current `apply` returns no stable, operator-safe erase selector, and the
generic ContextStore tombstone primitive has no Local Import-specific
authenticated RPC, receipt, replay, or anti-reimport contract. That requires a
separate complete evidence-lifecycle batch.

Obsidian also remains a source-only planning substrate. Its deterministic vault
planner has no durable CC-03 authority owner or Context Evidence apply path;
wiring it into `context` would be a larger vertical, not a plan-summary patch.

## Evidence boundary

W247 pause/resume and W249's Unix client are source-complete/reviewed but need
their active Hosted acceptance. W252's AppArmor work is platform evidence, not
a missing Local Import product feature. No local compiler, formatter, parser,
test, runtime, Git mutation, or Hosted dispatch was run during the BSOD hold.
