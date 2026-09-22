# W201: Hosted fixture compilation and formatting repair

Grouped60 `35728169263` and Core/CLI `35728172230` on `b7c9de56` reported
the same four test compilation errors. The Cron metadata fixture attempted to
call two private trusted-bundled constructors from outside the skills module.
A cfg(test)-only SkillSnapshot factory now wraps synthetic raw fixtures inside
that module; production constructors retain their original visibility. The
Cron WAL fixture retains a cloned segment path for its later record assertions.
The n8n pin fixture reads the actual Arc<Vec> snapshot and selects an enabled
Skill, preserving a meaningful pinned-mismatch check.

Preflight `35728147190` supplied 27 exact formatting hunks across Cron, n8n,
the Skill loader and prerequisites. Original published and resulting blobs were
checked before the compiler repairs were applied. Full custody is retained in
`work/gold-20260906/wave200-hosted-lint/FORMAT-B7C9-RECEIPT.json`.

Windows Python/OfficeCLI prerequisite subprocesses use the existing
CREATE_NO_WINDOW pattern, retaining null streams, fixed arguments, deadlines
and kill-on-drop. This prevents visible console allocation during daemon
registry admission; Graphify keeps its existing contained process launcher.

The sixty selected fixture identities are unchanged. No fixture was removed
or ignored. Independent static review passed. Fresh Hosted compilation, formatting and
execution remain required; no local executable validation ran.

Separately, full-CI `35726117022` on `0d18bb17` passed all nineteen audio
fixtures on Linux, Windows and macOS, including the W195 fallible-resampler
source. Downloaded names, actual pass records, source hashes, catalog and lockfile
were verified on all three platforms. This is exact audio-fixture evidence;
physical microphone/device, live-provider and release qualification remain open.

## Hosted recovery follow-up

On published `737b9835`, Preflight `35729768850` and Code Quality
`35729767980` passed. The core test-target check in `35729831467` passed;
its CLI build and Grouped60 `35729827037` remain pending. These are separate
checks: no complete behavior or release claim follows from compilation.

The observed warning in the b7c9 core log identifies
`load_trusted_bundled_with_policy` as unused in production. Its four current
callers are test fixtures. Applying `#[cfg(test)]` removes the production-only
warning while retaining all test behavior. This one-line correction still
needs Hosted production compilation/lint verification; no local executable ran.
