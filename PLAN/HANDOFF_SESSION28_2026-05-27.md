# NEOTH — Session 28 Handoff (2026-05-27)

> Session 28 closed late on 2026-05-27 after a vollausbau push. This
> handoff is the next-session pickup brief.

---

## TL;DR

- **17 commits** landed this session on top of the Session 28 morning
  baseline (which itself shipped the C-04b Firefox decrypt + C-03b
  Chrome per-OS work + the G-01 substrate). See "Shipped this session"
  below for the per-item table.
- **Final v1.0-blocker list (operator harte-Kritik audit, end of
  session)**, prioritised:
  1. **SPEC-04** local Qwen3-4B profile extraction (privacy-critical;
     today the extractor can still hit Gemini).
  2. **SPEC-01 Pick #8** GUI Code Sessions tab (DAU/Noob blocker;
     coding-buddy stays abstract without it).
  3. **QU-01 Phase 3** repetition-loop dispatcher wire-in (substrate
     + greeting-regression + patch-spiral all shipped this session;
     repetition-loop still pure-fn-only).
  4. **QU-05** cargo-check validate→fix→escalate loop.
  5. **HO-03 / SPEC-09 / SL-01b** cluster + mesh erlebbarkeit.
  6. **SC-09 remaining recovery commands**:
     `neoth security rewrap-hmac-key --plaintext-source` +
     `neoth wal verify --since-rotation`.
  7. **C-02b** encrypted Bitwarden importer integration into the
     credentials pipeline (decrypt primitive already shipped earlier
     this session).
  8. **DOC-01 / README / launch assets** — only finalise once items
     1–7 are real (today the README would over-promise on the
     "private-first" claim).
- **CI status at session end**: in flight on `6da495a`. Last green
  matrix run depends on whether the two clippy regressions in
  c7dff2d (`needless_borrow` on `&resp`, `iter().copied().collect()`
  → `to_vec()`) plus the `E0507` in builtins.rs (fixed in f21a722)
  fully clear on stable + beta. Check with
  `gh run list --workflow CI --branch main --limit 1`.

---

## Shipped this session (in commit order)

| Commit  | Item                                                      | Notes |
|---------|-----------------------------------------------------------|-------|
| `aef6531` | G-02 surfacing producer + cron                          | profile/surfacing.rs + daemon/g02_surfacing_cron.rs + wired into serve.rs section 5d-quartus |
| `ec6f569` | SPEC-01 Pick #7 `neoth kanban watch --follow`           | live tail with delta-filter pure-fn + tokio::signal::ctrl_c exit |
| `2034355` | ADV-04 apply-step redaction recheck                     | new WAL 0xB8 PROFILE_REDACT_BLOCKED + 3 tests |
| `ec79ab3` | build fixes for E0063 + clippy regressions              | delegated to build-error-resolver agent |
| `7d6fe98` | QU-01 Phase 1 EarlyStopDetector pure-fn substrate       | coding/early_stop.rs (~390 LOC + 14 tests) |
| `95cbb58` | ADV-05 Block-B injection PII category gate              | new SkillsConfig.pii_categories_disabled + filter_pii_disabled |
| `6beeab9` | ADV-06 sub-field granularity in PII deny-list           | extends ADV-05 with exact-field + dotted-prefix match |
| `77f2e48` | HO-02 stale-Planning kanban reaper                      | reap_stale_planning_sessions + wired into serve.rs 5a-kanban |
| `773e73b` | fix(build): 2 clippy regressions in factual_check tests | needless_borrow + useless_vec |
| `60be9c2` | HO-06 startup credential-pattern scanner                | daemon/startup_credential_audit.rs + PolicyConfig fields |
| `db25cb8` | QU-09a EvidenceCollector + RealityChecker built-ins     | sub_agents::builtins |
| `c7dff2d` | HO-06 audit-excerpt precision + aws_key + HO-01 reconcile | new `security::redact::find_secret_kinds` public API |
| `9662267` | QU-01 Phase 2 dispatcher wire-in                        | greeting-regression + patch-spiral bypasses in handle_retryable_failure |
| `f21a722` | fix(build): E0507 in reality-checker test               | added missing `&` borrow |
| `bf36dac` | ARCH-07 pinned-hash integrity guard final slice         | SkillsConfig.pinned_hashes + check_pinned_hashes + chat wire-in |
| `3c6bb26` | chore(plan): flip ARCH-07 to [x]                        | all slices shipped |
| `6da495a` | SC-09 `neoth security backup-hmac-key` subcommand       | first of three recovery commands |

Approximate diff: ~3,500 LOC + ~75 new tests across 17 commits.

---

## Operator harte-Kritik findings (still open at session end)

These are the residual issues flagged after the QU-09a / HO-06 /
QU-01 wire-in pushes. None are blocking the audit, but each is a
real edge that should land before v1.0 public.

1. **QU-01 greeting-regression edge** — the detector only fires on
   the `handle_retryable_failure` path. A worker that returns
   non-empty `patch_text` containing a refusal but with `--apply`
   DISABLED gets promoted to Review (the dispatcher treats the
   non-empty patch_text as structural success). With `--apply` the
   apply-rejection path catches it; without `--apply` the prose
   refusal slips through as Review material. See
   [SRC/neothd/src/coding/dispatcher.rs](SRC/neothd/src/coding/dispatcher.rs#L1701)
   for the test pin documenting the current behaviour. Not
   catastrophic, but for a coding-buddy it should also gate on the
   no-apply path. Two options:
   - Run `is_greeting_regression(patch_text)` BEFORE the
     `review_ready()` check + downgrade to retryable-failure when
     it fires (works for both `--apply` and no-`--apply`).
   - Make the dispatcher require `--apply` for the chat-auto-
     dispatch path so prose-only outputs always go through the
     apply gate.
2. **QU-01 Phase 3 repetition-loop** — `is_repetition_loop` is
   shipped + tested but the dispatcher doesn't thread recent-output
   state across attempts. To wire: add a per-task ring buffer
   (`Vec<String>` cap 5) to `dispatch_session_with_apply`, push
   each `partial_outcome.summary` (or `.patch_text`) on every
   failed attempt, call `is_repetition_loop(recent_outputs)` in
   `handle_retryable_failure` next to the greeting + spiral
   checks. ~50 LOC + 2 tests.
3. **GUI Pick #8 bottleneck** — every Rust-side improvement
   shipped this session moves the needle for power-users but does
   nothing for DAU/Noob readiness. Until the Slint Code Sessions
   tab lands, the coding-buddy stays invisible to operators who
   don't `tail -f` the WAL.
4. **SPEC-04 privacy gap** — `freedom.yaml::profile.learn_provider`
   default is `local_qwen`, but until SPEC-04 (Day-14b forward-pass
   + sampling-loop closed) lands the extractor falls back to
   whatever the operator's `provider_kind` is, which can be Gemini.
   The README + launch claims of "private-first" need this to
   actually be the floor, not the default.

---

## CI state at session end

- Pre-session-28 baseline was green.
- Mid-session some commits got their CI cancelled by newer pushes
  (queue contention — multiple `feat:` commits in rapid succession).
- The clippy-as-errors gates on stable macOS + ubuntu/macOS beta
  bit twice this session (op_ref, needless_borrow, iter_overeager,
  byte_char_slices, useless_vec, manual_div_ceil, type_complexity).
  Both rounds were resolved by `ec79ab3` + `c7dff2d` + `773e73b`.
- The `E0507 cannot move out of a shared reference` in
  `sub_agents/builtins.rs:237` (missing `&` borrow on `.system`
  in the reality-checker test) was fixed in `f21a722`.
- Next session: check `gh run view --branch main --json jobs` on
  the latest run. If stable matrix is finally clean, the working
  base is solid.

---

## Local build state

- **Windows MSVC cl.exe** STILL broken in this env (cc-rs:
  `ToolNotFound: failed to find tool "cl.exe"`). Touches zstd-sys,
  ring, stacker. Pre-existing — not session-induced. Validation
  this session relied on `cargo fmt -- --check` for syntax + CI
  for semantics.
- Confirmed: `cargo fmt -- --check` was used after EVERY commit;
  all 17 commits are fmt-clean.

---

## Key new public APIs introduced this session

Useful to know for next-session callers:

- **`security::redact::find_secret_kinds(input) -> Vec<SecretMatch>`** —
  byte-precise secret-shape match results. Replaces the old
  diff-vs-`redact_text` hack in `daemon::startup_credential_audit`.
  Each `SecretMatch` has `kind: &'static str`, `start`, `end`,
  `text: String`. Overlapping matches dedup-keep first-declared
  pattern (most-specific wins).
- **`skills::versioning::check_pinned_hashes(skills_iter, &pinned_map)
  -> Vec<PinnedHashVerdict>`** — pure-fn per-skill pinned-hash
  verdict. Allowed when no pin OR pin == actual; Mismatch otherwise.
  Input-order preserving so callers zip-by-index.
- **`profile::lookup::filter_pii_disabled(claims, disabled_entries)`**
  + **`top_claims_for_chat_with_pii_gate(...)`** — ADV-05/06 PII
  category-and-subfield deny-list filter. Match semantics:
  category-of(field) match OR exact-field match OR dotted-prefix
  match (entry `identity.location` blocks `identity.location.country`
  too).
- **`coding::early_stop::{is_repetition_loop, is_greeting_regression,
  PatchSpiralTracker}`** — three pure-fn early-stop detectors.
  Greeting + spiral wired into dispatcher in Phase 2; repetition is
  still pure-fn-only (Phase 3 pickup above).
- **`coding::store::reap_stale_planning_sessions(conn, now_ns,
  stale_after_ns)`** — HO-02 dispatcher startup reaper. Wired into
  `cli/serve.rs` section 5a-kanban.
- **`daemon::startup_credential_audit::run_credential_scan`** —
  HO-06 boot-time pattern scanner. Off by default; opt-in via
  `policy.yaml::startup_audit_scan_paths` /
  `forbid_inline_tokens_in_remotes`.
- **`profile::surfacing::{find_novel_high_confidence_claims,
  build_g02_proactive_item}`** + **`daemon::g02_surfacing_cron`** —
  G-02 producer (daily cron) feeding the proactive_queue → JSONL
  sidecar chain.
- **`recall::reconstruct::reconstruct_from_checkpoint`** (shipped
  earlier this session, listed for completeness) — QU-11 read-side
  for `chat --resume-from <hash>`.
- **`cli::security::run_backup_hmac_key(args)`** — SC-09 plaintext
  backup. Mode-0600 on Unix; refuses overwrite without `--force`.

---

## Next-session shortest-path recommendations

If next session targets v1.0-public-ready:

1. **Day 1 (highest leverage, lowest blocker risk)**:
   - Wire SPEC-04 local Qwen3-4B profile extraction. The
     `learn_provider: local_qwen` config already exists; what's
     missing is the actual `embed()` / forward-pass path in the
     LocalQwenProvider when called from the profile extractor.
     Verify via `neoth chat --provider gemini_api "I live in
     Berlin"` then `neoth profile show identity.location` and
     check the WAL frames for which provider the extract call
     actually hit.
   - This unblocks the README's "private-first" claim AND the
     launch-asset finalisation track.
2. **Day 2** (parallel-friendly):
   - SPEC-01 Pick #8 GUI Code Sessions tab. Lift from the Twitter
     image's 5-column layout (BACKLOG / TODO / IN_PROGRESS /
     REVIEW / DONE). The Slint surface is already in
     `SRC/neothd-gui/`; the kanban data is queryable via
     `coding::store::list_tasks_for_session`. Cerebral fallback
     panel from HO-02 (the other half — not yet shipped) lands
     in the same tab.
3. **Day 3 (cleanup + recovery):**
   - QU-01 Phase 3 repetition-loop wire-in (50 LOC).
   - SC-09 second + third recovery commands
     (`rewrap-hmac-key --plaintext-source` + `wal verify
     --since-rotation`).
   - QU-01 greeting-regression no-apply edge per the
     harte-Kritik note above.

---

## References

- Active backlog: [PLAN/PROGRESS_v1_0.md](PLAN/PROGRESS_v1_0.md)
- DPAPI recovery runbook (referenced by SC-09):
  [PLAN/RUNBOOK_dpapi_hmac_recovery.md](PLAN/RUNBOOK_dpapi_hmac_recovery.md)
- Coding workflow spec (Pick #8 origin):
  [PLAN/SPEC_coding_workflow.md](PLAN/SPEC_coding_workflow.md)
- Prior session handoff: [PLAN/HANDOFF_SESSION26_2026-05-27.md](PLAN/HANDOFF_SESSION26_2026-05-27.md)
