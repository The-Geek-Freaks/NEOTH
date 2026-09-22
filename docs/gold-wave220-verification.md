# W220 — Persisted background registry snapshot isolation

The existing detached CLI worker stores the originating request rather than
reloading its Skill registry. This batch adds behavioral coverage of the
actual metadata, signing, persistence and pre-dispatch boundaries without
changing production policy or pretending the whole detached CLI process ran.

## Verified source coverage; Hosted execution pending

`cli::bg_session::tests::queued_background_request_keeps_real_registry_metadata_a_after_skill_b_publication`
creates an installed Skill with authenticated install incarnation and active
authority, then acquires a ReloadController-bound SkillRegistry snapshot A.
The resolver renders the complete session registry metadata. The production
enricher must place this exact envelope in required Block D; its renderer
builds the queued request. Skill instruction bodies are explicitly absent.

The fixture signs BgWorkerSpec, durably writes it through the private production
writer, then replaces the installed package with metadata B and publishes its
new authority. The accepted configuration remains A. The reloaded live registry
must now contain B and exclude A. The production bounded private reader loads
the original job, verifies its approval and passes the unchanged live-config
gate. The loaded system must exactly equal the original rendered A envelope.
Canary binding then retains that envelope and excludes B.

`cli::bg_session::tests::accepted_config_b_refuses_the_queued_background_worker_before_dispatch`
separately accepts a real config B with the ReloadController and proves the
same production live-config gate rejects the signed A job. Changed policy is
not treated as permission to continue an old queued request. This directly
covers the gate called before Canary binding and again before provider dispatch.
It does not spawn a detached process, exercise the complete CLI `/background`
branch, or prove provider delivery. Direct CLI prompt/fallback coverage remains
an independent work item.

Independent static review passed. No compiler, formatter, parser, test, fixture
or product runtime was executed locally. The new source path and two exact
native test identities enter the canonical inventory and Hosted Grouped274.
Inventory is 532 sources / 816 universal native / 94 universal GUI names,
22 Linux/22 macOS GUI extras, and 26 custom macOS GUI cases.

The ongoing full CI `35782661515` is intentionally retained on `74334d4b`:
it validates W219 and the aggregate Skill rollback. W220 requires its own
source-bound Hosted result; later code must not be credited to that older run.
Road remains 1015 checked / 307 open / 2 partial. No box is closed by adding tests.

Published144135d937340f6f02f6c666afb91d2ae9b07349. Exact Hosted formatter
receipt35783144307 imported after source/SHA256 and Git pre/postimage checks.
No formatter ran locally; Grouped274 must exercise the new tests.
