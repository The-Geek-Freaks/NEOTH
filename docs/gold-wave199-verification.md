# W199 — Cron session-start Skill registry

W199 gives each operator-authored Cron job one metadata-only Skill registry
before its first provider dispatch. The runner constructs a fresh
`ReloadController` from the already-loaded Cron config and that job's exact
`home/freedom.yaml`, then loads `home/skills` through the controller and pins
the accepted config epoch with `authority_bound_snapshot_for_epoch`.

The admitted snapshot uses the established pinned-hash and evaluation filters.
`SkillRouteResolver::session_registry_context(&[])` renders the complete
enabled, visible Cron inventory as one typed Block D envelope. Cron does not
select a skill and never injects a Skill body, tool allowlist, route, model, or
other execution authority. The existing Cron prompt remains the user prompt;
the briefing/profile system text remains the explicit system layer.

The rendered envelope is assembled once in `cron_enriched_request` before the
provider deadline starts. The initial call receives `req.clone()` and the
briefing quality retry uses `..req`, retaining byte-identical system context
while intentionally replacing only the retry prompt. Registry load, epoch,
authority, or exact-size rendering failures propagate before any provider
dispatch.
Because request preparation occurs after the existing `JOB_FIRED` audit, a
registry refusal completes that run through `finish_job_fired_failure` as
`failure_kind: "cron_skill_registry_failed"`; the terminal `JOB_FAILED`
links to the fired event. Failure to write this terminal frame still propagates.

Focused regression identities in `SRC/neothd/src/cron/runner.rs`:

- `cron_registry_filters_disabled_pinned_and_eval_skills`
- `cron_registry_first_request_has_one_typed_metadata_envelope`
- `cron_registry_retry_retains_byte_identical_system_context`
- `cron_registry_later_job_uses_its_changed_config_generation`
- `cron_registry_load_failure_stops_before_provider_dispatch`

The resolver's pre-existing exact-inventory limits remain the oversized-input
gate; W199 propagates that error before provider dispatch. Per the BSOD hold,
no local formatter, compiler, parser, test, product runtime, GUI, or audio
operation was run. Hosted validation is required before accepting W199.
