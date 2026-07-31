# NEOTH v1.0 GOLD handoff for Claude Opus 5

**Created:** 2026-07-31
**Repository:** `C:\Users\Shadow-PC\CascadeProjects\AGENTER`
**Remote:** `https://github.com/The-Geek-Freaks/NEOTH.git`
**Branch:** `main`
**Provider checkpoint commit:** `94006a53315345d7e11452df09acf82fd2b11ec1`
(`fix(providers): bound OpenAI response envelopes`).
**Handoff commit:** this file is committed immediately after that checkpoint and
both commits are pushed together. Start from the newest exact `origin/main`.

This is an execution handoff, not a request for another high-level audit.
Continue delivering bounded, wired, reviewed checkpoints until every v1.0 Gold
contract is closed and the exact release head passes the final platform gates.

## 1. Mission and non-negotiable completion standard

The authoritative backlog is `PLAN/ROAD_TO_1_0_GOLD.md`. Everything in that
document is v1.0 scope. Do not silently defer work to 1.1, delete findings,
convert unfinished work to prose-only completion, or mark a task complete
because a helper/module/test exists.

A task is complete only when all applicable parts are true:

1. The implementation exists and handles failure paths explicitly.
2. Every intended production caller is wired; searches prove no stale bypass or
   duplicate legacy path remains.
3. Config, safe/default behavior, migrations, wizard/onboarding, doctor/probe,
   CLI, GUI, channels, and release packaging are updated where the feature
   crosses those surfaces.
4. CLI/GUI/channel behavior is genuinely parity-safe, not merely documented.
5. Tests cover the real boundary and a production-shaped path, including
   negative/adversarial cases.
6. Public docs and operator guidance tell the truth about what ships.
7. An independent code review and, for trust boundaries, a security review have
   no unresolved blocking finding.
8. The checkpoint is committed, pushed, and `HEAD == origin/main` is verified.

NEOTH's v1.0 product target remains: zero-friction install and first run,
complete release artifacts, GUI included where the target supports it, easy
CLI/GUI switching, useful Buddy behavior, provider/channel parity, clean
migration, no hidden manual prerequisite, and no advertised feature that is
partial or unwired.

## 2. Start every resumed session safely

Run these checks before editing:

```powershell
Set-Location C:\Users\Shadow-PC\CascadeProjects\AGENTER
git status --short
git fetch origin --prune
git rev-parse HEAD
git rev-parse origin/main
git log -5 --oneline
git merge-base --is-ancestor 94006a53315345d7e11452df09acf82fd2b11ec1 origin/main
```

Do not pull/rebase over a dirty tree blindly. Another agent or the operator may
have legitimate work present. Inspect provenance and integrate around it.
Never use `git reset --hard`, `git clean`, broad checkout/revert, or `git add -A`.
Do not begin the Ollama slice unless the ancestry check above succeeds and
`HEAD == origin/main`. If the heads differ, stop the commit path, inspect the
foreign commits and dirty-file provenance, then integrate explicitly without
discarding either side.

At this handoff the following local items are explicitly unrelated to the
provider-bounds checkpoint and must not be staged, deleted, reformatted, or
claimed:

- modified `.gitignore`;
- untracked `.kilo/`;
- untracked `SRC/_autoupdate.py`;
- untracked helper batches shown by `git status` under `SRC/_*.bat`;
- untracked `SRC/neothd/unused/`.

The repository may have changed after this handoff. Re-read current status and
history; never assume the list above is exhaustive or still current.

## 3. Required loop and engineering behavior

For every checkpoint:

1. Read `PLAN/ROAD_TO_1_0_GOLD.md`, `PLAN/PROGRESS_v1_0.md`, the relevant SPEC,
   and current code/history before deciding scope.
2. Perform a deep trace:
   config/default -> constructor -> runtime caller -> policy/audit gate ->
   output/error -> CLI/GUI/channel/doctor/wizard -> docs/release.
3. Search all callers and sibling adapters. A function with zero production
   callers is not shipped. A new guarded path with an old bypass still present
   is not shipped.
4. Use parallel read-only agents for independent inventory, adoption research,
   adversarial review, or test-gap analysis. Give write ownership to only one
   agent per file. Do not let agents overwrite each other in the shared tree.
5. Implement the smallest complete root-cause fix. Reuse native/shared helpers;
   avoid speculative abstractions and new dependencies.
6. Add exact boundary tests, one-byte-over tests, malformed-input tests,
   secret/raw-payload non-echo assertions, and production-shaped wiring tests
   where applicable.
7. Run proportional verification while building. Do not run the entire
   workspace/platform matrix after every small edit.
8. Run an independent code reviewer after code changes. Run a security reviewer
   for provider, credential, transport, permission, audit, updater, channel, or
   release trust-boundary changes. Fix all valid blockers and re-review.
9. Update roadmap/progress/docs honestly. Keep the parent task open until all
   listed adapters/surfaces are adopted.
10. Stage exact owned paths, inspect the cached diff, commit one coherent
    checkpoint, push, fetch, and verify exact remote equality.

Do not hallucinate completion from a green compile. Do not suppress errors,
swallow malformed provider frames, log raw untrusted bodies, or replace typed
outcomes with generic strings. Do not claim a test ran unless its actual result
was observed.

## 4. Build/test strategy that avoids wasted hours

Use three verification tiers:

### Inner loop

- `cargo fmt --all` after Rust edits.
- Focused unit/module tests only.
- Reuse the newest already-linked
  `SRC\target\debug\deps\neothd-*.exe` for neighboring test filters when source
  has not changed since the link.
- Run `cargo check -p neoth --lib` when a compile boundary changes.

### Checkpoint gate

- Focused changed-scope tests.
- Relevant neighboring security/termination/recovery tests.
- `cargo clippy -p neoth --lib --tests --no-deps -- -D warnings`.
- `git diff --check`.
- Roadmap and lost-feature gates.
- Independent review.

### Release-candidate gate

Only after the roadmap is actually closed: exact-head workspace CI, security,
CodeQL, all feature combinations required by release, clean-machine installer
tests, and the Windows/macOS/Linux artifact matrix. Do not repeatedly run that
full matrix while later roadmap work will rewrite the same code.

On this Windows machine use the repository's MSVC environment helper. The
tracked/local wrappers currently used successfully are:

```powershell
cmd /c SRC\_check.bat
cmd /c SRC\_clippy.bat
$env:NEOTH_TEST_THREADS='1'; cmd /c SRC\_test.bat <filter>
```

The OpenAI adapter tests share a process-global circuit breaker keyed by adapter
identity. Several tests deliberately fail to prove fail-closed behavior. Keep
the focused suite serial and do not arrange five deliberate failures
consecutively without an intervening success, or later tests will correctly
observe the opened breaker and produce misleading cascades. Diagnose the first
failure, never count the cascade as 17 independent bugs.

## 5. Checkpoint just landed: OpenAI-compatible response bounds

The pushed checkpoint is the first part of open task `GOLD-R4-15k1`. It covers
the shared Chat-Completions family:

- OpenAI;
- OpenRouter;
- DeepSeek;
- Moonshot/Kimi;
- Qwen Chat compatible mode;
- reviewed custom OpenAI-compatible endpoints.

Implemented contracts:

- successful JSON is incrementally read into a hard 8 MiB byte envelope before
  deserialization;
- individual SSE lines/residuals and the joined data payload of a complete SSE
  event are hard-capped at 1 MiB before append;
- multiple standard SSE `data:` fields are joined with `\n` and decoded once at
  the blank event separator or EOF;
- UTF-8 is validated only after bounded byte assembly, so split code points are
  valid and invalid UTF-8 fails closed;
- retained refusal metadata is capped at 1 MiB for streaming fragments,
  non-stream `message.refusal`, and concatenated `content[].refusal`;
- successful-body, malformed-frame, over-limit, and truncated-transport errors
  expose only bounded, domain-separated digest evidence;
- SSE read errors drop the raw `reqwest::Error` source chain;
- existing typed quota, `Retry-After`, OpenRouter observation, finish/refusal,
  and visible completion behavior remains intact.

Relevant files:

- `SRC/neothd/src/providers/response_bounds.rs`;
- `SRC/neothd/src/providers/openai_api.rs`;
- `SRC/neothd/src/providers/mod.rs`;
- `SRC/neothd/src/security/redact.rs`;
- `PLAN/ROAD_TO_1_0_GOLD.md`;
- `PLAN/PROGRESS_v1_0.md`;
- `PLAN/SPEC_refusal_recovery.md`;
- `docs/providers.md`;
- `docs/security/threat-model.md`.

Observed local verification against exact provider checkpoint
`94006a53315345d7e11452df09acf82fd2b11ec1` (this is not a claim that remote
exact-head CI has already completed):

- OpenAI-compatible adapter tests: **53/53**;
- shared response-bounds tests: **3/3**;
- redaction tests: **53/53**;
- quota tests: **22/22**;
- termination tests: **4/4**;
- refusal-recovery tests: **26/26**;
- abliterated-fallback tests: **11/11**;
- turn-journal tests: **13/13**;
- affected total: **185/185**;
- Cargo check: pass;
- Clippy `-D warnings`: pass;
- roadmap release-gate tests: **11/11**;
- lost-feature integrity tests: **19/19**;
- independent code review: approve;
- independent security review: approve.

Roadmap state remains intentionally open:

```text
total=1222
complete=988
open/raw blockers=234
pre-tag blockers=233
```

Do not mark `GOLD-R4-15k1` complete yet.

## 6. Native Ollama response envelopes — LANDED 2026-07-31

Status: implemented, tested and pushed on top of `076bda02`. All nine required
fixtures below exist and pass, including the raw HTTP/1.1 chunked fixture.
`GOLD-R4-15k1` stays open; the next owned target is the Anthropic Messages
transport, then Gemini, Cohere, Azure, Bedrock, Copilot-token refresh, Claude
CLI, Tmux and RecursiveMAS. The original specification is kept verbatim below
as the contract the next adapters must match.

Implementation target:

`SRC/neothd/src/providers/ollama_api.rs`

Adopt the shared `response_bounds` primitives without changing public Ollama
semantics:

1. Cap non-2xx complete and stream handshake bodies at 64 KiB and surface only
   status plus digest evidence.
2. Replace unbounded successful `response.json().await` with shared bounded
   decoding using the 8 MiB success cap and an Ollama-specific evidence domain.
3. Replace streaming `String` accumulation with raw-byte NDJSON framing.
4. Cap each NDJSON line/EOF residual at 1 MiB before append.
5. Validate UTF-8 only after a complete bounded line exists.
6. Parse newline-delimited and newline-less final frames through the same helper.
7. Change today's malformed-NDJSON behavior from raw warning + skip to a
   digest-only fail-closed error. It must never skip malformed input and then
   synthesize a false successful done frame.
8. Preserve real delta text, `done_reason`, input/output token counts,
   `ProviderTermination`, model identity, remote-consent behavior, and the
   existing synthetic EOF terminator only when no malformed frame occurred.

Required Ollama tests:

- oversized valid/near-valid 2xx body, secret sentinel not echoed;
- malformed 2xx JSON, digest only;
- oversized 500 body for complete and stream handshake, digest only;
- newline-free NDJSON line over 1 MiB;
- malformed newline-delimited line fails closed;
- malformed EOF residual fails closed and emits no synthetic success;
- invalid UTF-8 line, digest only;
- UTF-8 code point split across transport chunks using a local HTTP/1.1 chunked
  fixture that splits the four-byte code point between two transfer chunks;
  assert the exact reconstructed delta and final done metadata;
- all existing progressive/done/token/redirect/consent tests remain green.

After landing Ollama, update docs to say “OpenAI-compatible + native Ollama
adopted”, but leave `GOLD-R4-15k1` open.

## 7. Remaining `GOLD-R4-15k1` inventory after Ollama

Trace and adopt every real response surface:

- ~~Anthropic Messages JSON and error bodies~~ — **done 2026-07-31**;
- ~~Gemini JSON and error bodies~~ — **done 2026-07-31**;
- ~~Cohere JSON and error bodies~~ — **done 2026-07-31**;
- ~~Azure OpenAI JSON and error bodies~~ — **done 2026-07-31** (classifies
  under the cap, `Raw body:` echo removed);
- ~~AWS Bedrock JSON and error bodies~~ — **done 2026-07-31** (same);
- ~~Copilot token-refresh JSON/error body~~ — **done 2026-07-31** (Copilot chat
  already delegates to the OpenAI transport);
- Claude CLI non-stream stdout/stderr, `stream-json` records, and cumulatively
  retained visible/refusal text — **open**; inventory: unbounded
  `read_to_end` into `stdout_bytes`/`stderr_bytes`, unbounded
  `BufReader::lines()` per record, unbounded cumulative `visible_text`, and
  raw stderr embedded in two `anyhow::bail!` messages;
- Tmux captured stdout/stderr — **open**; `capture_pane` is bounded by line
  count only, and tmux stderr lands raw in an error; PTY `read_until` is
  time-bounded but byte-unbounded;
- feature-gated RecursiveMAS line input — **open**; unbounded `read_line` from
  the sidecar, then `serde_json::from_str` on it.

Decorators were traced and confirmed to delegate rather than re-parse:
`fallback.rs`, `compactor.rs`, `abliterated.rs` and `token_cap.rs` all forward
to the leaf adapter and never touch response bytes. `meter.rs`,
`singleflight.rs`, `circuit_breaker*.rs`, `effort_override.rs` and
`model_roles.rs` are not Provider decorators at all.

The no-bypass search now has a permanent home:
`SRC/neothd/tests/provider_response_bounds_source_gate.rs` pins every adopted
transport and keeps a `PENDING` ratchet of the rest. Closing this box means
that list is empty and the gate's own guard test is deleted.

Local Qwen/Ouro inference is in-process and does not need a remote HTTP response
envelope. Decorators must be proven to delegate through a bounded leaf rather
than receiving redundant parsing. Close `GOLD-R4-15k1` only after a final
no-bypass search proves every listed external byte stream is bounded.

## 8. Adoption and wiring audit rules

When implementing any later roadmap adoption:

- Deep-read the source project and record exact feature/algorithm/data-flow
  findings; do not infer from its README.
- Check the source license before copying anything. Reimplement behavior when
  code reuse is incompatible.
- Search NEOTH first for partial, duplicate, legacy, or “built but zero caller”
  implementations.
- Define the production entrypoint and the exact operator-visible surface before
  writing a helper.
- Wire configuration defaults, validation, serialization, example config,
  onboarding, CLI, GUI, doctor/probe, audit/WAL, migration, and release artifacts
  as applicable.
- Test the consumer, not only the helper.
- Search again after implementation for old bypasses and stale docs.
- Keep feature availability honest when a platform or build feature cannot ship
  on a target.

Graphify may accelerate architecture tracing, but treat `INFERRED` edges as
hypotheses and exclude generated files, uploads, backups, screenshots, old
reports, and `target/` before making a decision.

## 9. Git landing protocol

Before every commit:

```powershell
git diff --check
git status --short
git diff --stat
git fetch origin --prune
git rev-parse HEAD
git rev-parse origin/main
```

If `HEAD != origin/main` before staging or committing, do not commit or push.
Inspect the divergence and integrate the remote work first. Immediately after a
local commit and before push, require the old `origin/main` to be an ancestor of
`HEAD`, inspect `git rev-list --left-right --count origin/main...HEAD`, and
expect exactly the checkpoint commits you just created on the local-ahead side.

Stage only the explicitly owned files:

```powershell
git add -- <exact paths>
git diff --cached --check
git diff --cached --stat
git status --short
```

Inspect the cached file list and prove none of `.gitignore`, `.kilo/`,
`SRC/_*.bat`, `SRC/_autoupdate.py`, or `SRC/neothd/unused/` entered the index
unless the operator later assigns those exact files.

Then:

```powershell
git commit -m "<coherent checkpoint subject>"
git push origin main
git fetch origin --prune
git rev-parse HEAD
git rev-parse origin/main
git status --short
```

Report separately:

- what is implemented and wired;
- exact tests/gates that passed;
- the pushed commit hash;
- remaining roadmap blockers;
- unrelated dirty/untracked files left untouched.

Do not stop after writing a plan. Land the next verified checkpoint, push it,
then start the next loop.
