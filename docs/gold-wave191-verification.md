# W191 standalone loop Skill registry verification

`neoth loop run` now loads one authority-bound Skill snapshot from the same
accepted `freedom.yaml` generation used for its provider/MCP/WAL session. It
filters that snapshot through the existing pinned-hash and eval-suppression
gates, derives `NEOTH_ACTIVE_FILES` once, and renders one typed untrusted Skill
registry envelope through `SkillRouteResolver::session_registry_context`.

The standalone loop passes that envelope to the shared enriched-request
composer with the local-interactive operator authority. The resulting request
is created once before `loop_engine::run_loop`; the engine's existing request
cloning therefore preserves the accepted envelope for every round and provider
retry/fallback path. A later standalone invocation obtains a fresh snapshot;
an in-flight invocation never rereads the registry. Cluster executor remains
unchanged because it is an isolated foreign-peer task surface.

Pinned-hash mismatches remain excluded and produce the existing
`SKILL_INJECT_SKIPPED` WAL reason. Eval sessions exclude every registry entry
and retain no behavioural Skill layer. No dependency schema was added because
the current `SkillManifest` does not represent dependencies.

The production-used `standalone_loop_enriched_request` seam has focused fixture
coverage. `w191_loop_request_excludes_pin_rejected_and_eval_suppressed_registry_entries`
uses its actual registry loader and proves both exclusions are absent from the
rendered request. `w191_later_standalone_loop_rebuilds_its_registry_from_fresh_config`
proves a later invocation does not retain the earlier rejected view.
`w191_loop_retains_one_registry_envelope_byte_identically_across_rounds` uses
the real loop engine with a recording provider over two rounds, while
`w191_loop_fallback_recovery_keeps_the_same_registry_envelope` sends the same
request through a quota-error primary and real fallback recovery leaf. Both
prove the complete accepted system/envelope bytes are retained; the two-round
test additionally proves the iterative prompt itself changes.
`w191_actual_standalone_request_retains_loaded_registry_through_two_rounds`
closes the entry-point boundary by handing the real helper-produced request to
the real loop engine and recording both provider calls.

No local Cargo, formatter, parser, fixture, product, GUI, audio, or test
command ran during the BSOD hold. Reviewed source may be published while Hosted
formatting, compilation and targeted regression execution remain pending;
runtime acceptance still requires those gates. Road-plan, manifest, and count
changes are outside this batch.

Grouped Hosted run `35717294010` compiled and passed all first ten W190
identities. It stopped at W191's first helper because `first_registry_skill_id`
searched the JSON-escaped envelope instead of decoded inner registry JSON. The
narrow helper repair decodes both layers; its exact rerun remains pending.
